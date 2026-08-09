// The ElfParser analyses that need a real disassembler behind them.
//
// Everything here used to be declared and never implemented -- the binary could
// not link. Rather than hand-rolling the control-flow and pointer analysis they
// need, each one is expressed in terms of what rizin already recovers from the
// image: functions, cross-references, imports and classes.

#include "memory.h"
#include "rizin_bridge.h"

#include <elf.h>

#include <algorithm>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <vector>

namespace {

// One session per module, shared with every other caller -- see
// rzb::shared_image().
rzb::Image *session(const std::vector<uint8_t> &data, uint64_t base) {
  return rzb::shared_image(data, base);
}

} // namespace

std::vector<ElfParser::ImportCall>
ElfParser::find_import_calls(const std::vector<uint8_t> &data,
                             uint64_t base_addr) {
  std::vector<ImportCall> out;
  // Same base as every other query on this image: a different one would key a
  // second session and pay for a whole extra analysis pass of the same module.
  rzb::Image *img = session(data, base_addr);
  if (!img)
    return out;
  for (const auto &c : img->import_call_sites())
    out.push_back({c.site, c.symbol});
  return out;
}

std::vector<ElfParser::PltEntry>
ElfParser::get_plt_entries(const std::vector<uint8_t> &data) {
  std::vector<PltEntry> out;
  rzb::Image *img = session(data, 0);
  if (!img)
    return out;
  for (const auto &imp : img->imports()) {
    PltEntry e;
    // `offset` is what a call site branches to. The previous implementation put
    // the GOT slot here, so matching BL targets against it never hit.
    e.offset = imp.stub_vaddr ? imp.stub_vaddr : imp.got_vaddr;
    e.got_offset = imp.got_vaddr;
    e.symbol_name = imp.symbol;
    e.symbol_index = 0; // rizin resolves the name directly; the index is unused
    out.push_back(std::move(e));
  }
  return out;
}

std::vector<ElfParser::PointerTable>
ElfParser::find_function_tables(const std::vector<uint8_t> &data,
                                uint64_t base_addr, bool *truncated) {
  std::vector<PointerTable> out;
  if (truncated)
    *truncated = false;
  rzb::Image *img = session(data, base_addr);
  if (!img)
    return out;
  for (const auto &r : img->function_tables(4, truncated))
    out.push_back({r.vaddr, r.count, r.targets});
  return out;
}

std::vector<ElfParser::RttiClass>
ElfParser::scan_rtti_tables(const std::vector<uint8_t> &data,
                            uint64_t base_addr) {
  std::vector<RttiClass> out;
  rzb::Image *img = session(data, base_addr);
  if (!img)
    return out;
  for (const auto &c : img->rtti_classes()) {
    RttiClass rc;
    rc.typeinfo_vaddr = c.typeinfo_vaddr;
    rc.vtable_vaddr = c.vtable_vaddr;
    rc.name = c.name;
    rc.vfuncs = c.vfuncs;
    out.push_back(std::move(rc));
  }
  return out;
}

std::vector<ElfParser::StructLayout>
ElfParser::recover_struct_layouts(const std::vector<uint8_t> &data,
                                  uint64_t base_addr) {
  std::vector<StructLayout> out;
  rzb::Image *img = session(data, base_addr);
  if (!img)
    return out;

  for (const auto &cls : img->rtti_classes()) {
    if (img->budget_exhausted())
      break;
    if (cls.vfuncs.empty())
      continue;

    // Merge what every virtual method of the class touches through x0. A field
    // is usually read in one method and written in another, so the union across
    // methods is a much better picture of the layout than any single one.
    std::map<uint64_t, FieldAccess> merged;
    for (uint64_t fn : cls.vfuncs) {
      if (img->budget_exhausted())
        break;
      for (const auto &fa : img->field_accesses(fn)) {
        FieldAccess &slot = merged[fa.offset];
        slot.offset = fa.offset;
        slot.width = std::max(slot.width, fa.width);
        slot.written = slot.written || fa.written;
        slot.hits += fa.hits;
      }
    }
    if (merged.empty())
      continue;

    StructLayout sl;
    sl.name = cls.name;
    sl.vtable_vaddr = cls.vtable_vaddr;
    sl.min_size = 0;
    for (const auto &kv : merged) {
      sl.fields.push_back(kv.second);
      sl.min_size = std::max(sl.min_size, kv.first + kv.second.width);
    }
    out.push_back(std::move(sl));
  }
  return out;
}

std::vector<uint8_t>
ElfParser::find_encryption_key(const std::vector<uint8_t> &data,
                               uint64_t base_addr) {
  std::vector<uint8_t> key;
  // The session has to be opened at the module's load address, not at zero:
  // DT_INIT_ARRAY in a memory dump has already been relocated, so its entries
  // are absolute runtime addresses. Reading them out of an image mapped at zero
  // lands outside the mapping and returns nothing at all.
  rzb::Image *img = session(data, base_addr);
  if (!img)
    return key;

  // Constructors are where a packer builds its key before anything else runs.
  //
  // They are executed under rizin's IL virtual machine rather than scanned for
  // MOVZ/MOVK chains. Pattern matching only ever sees a constant that was
  // written by immediates; emulation also catches one that was rotated,
  // xored together, loaded from a literal pool or assembled in a loop, which is
  // what anything trying to hide a key actually does.
  // What counts as key material.
  //
  // A constructor leaves plenty of live registers that are not keys: pointers
  // into the module's own image, small counters, and sign-extended negative
  // displacements. Reporting those filled the section with 32 bytes of noise
  // before the real value was ever reached.
  //
  // The span to exclude is the address space the module occupies, not its file
  // size: a 16 KB-aligned library reaches vaddr 0x22000 out of 0x15c10 bytes of
  // file, and measuring against the file let every pointer above that through.
  uint64_t va_end = 0;
  Elf64ProgramHeaders program_headers;
  if (!parse_elf64_program_headers(data, &program_headers))
    return key;
  bool have_load = false;
  for (const auto &ph : program_headers.entries) {
    if (ph.p_type != PT_LOAD ||
        ph.p_vaddr > std::numeric_limits<uint64_t>::max() - ph.p_memsz)
      continue;
    have_load = true;
    va_end = std::max<uint64_t>(va_end, ph.p_vaddr + ph.p_memsz);
  }
  if (!have_load)
    return key;
  // Rounded to the largest page size Android maps with. Addresses just past the
  // last p_memsz are still inside the module's final page -- .bss and the tail
  // of the GOT live there -- and they are pointers, not keys.
  if (va_end <= std::numeric_limits<uint64_t>::max() - 0x3FFF)
    va_end = (va_end + 0x3FFF) & ~uint64_t(0x3FFF);
  auto plausible = [&](uint64_t v) {
    if (v <= 0xFFFF || v == UINT64_MAX)
      return false;
    if (v < va_end) // address inside this module
      return false;
    if (base_addr &&
        base_addr <= std::numeric_limits<uint64_t>::max() - va_end &&
        v >= base_addr && v < base_addr + va_end) // live address
      return false;
    if ((v >> 32) == 0xFFFFFFFFu) // sign-extended small negative
      return false;
    return true;
  };

  // A plausible register constant is only a candidate. Promote it to an exact
  // encryption key if the same bytes independently seed a fully validated AES
  // expanded schedule in this runtime image. This prevents unrelated pointer,
  // counter, or constructor constants from being concatenated and reported as
  // cryptographic fact.
  const auto aes = detect_aes_keys(data);
  auto exact_schedule_match = [&](const std::vector<uint64_t> &values)
      -> const AESKeyInfo * {
    for (size_t start = 0; start < values.size(); start++) {
      for (const auto &schedule : aes) {
        if (schedule.key_size == 0 || schedule.confidence != 1.0 ||
            schedule.key_size % sizeof(uint64_t) != 0)
          continue;
        const size_t words = schedule.key_size / sizeof(uint64_t);
        if (words > values.size() - start)
          continue;
        bool equal = true;
        for (size_t word = 0; word < words && equal; word++)
          for (size_t byte = 0; byte < sizeof(uint64_t); byte++)
            if (static_cast<uint8_t>(values[start + word] >> (byte * 8)) !=
                schedule.key[word * sizeof(uint64_t) + byte]) {
              equal = false;
              break;
            }
        if (equal)
          return &schedule;
      }
    }
    return nullptr;
  };

  for (uint64_t fn : get_init_array(data)) {
    if (img->budget_exhausted())
      break;
    // The entries were relocated by the loader before the image was lifted, so
    // they are live addresses, while rizin holds the module at zero. Emulating
    // at the unadjusted address ran off the end of the image and returned
    // nothing, which is why this section never appeared for a real dump.
    if (base_addr && fn >= base_addr)
      fn -= base_addr;

    std::vector<uint64_t> emulated;
    for (const auto &rv : img->emulate(fn))
      if (plausible(rv.value))
        emulated.push_back(rv.value);

    // The IL virtual machine stops at the first instruction rizin's AArch64
    // lifter does not implement, and a constructor reaches one well before it
    // returns -- in practice after nine or fifteen steps, which is not far
    // enough to finish two MOVZ/MOVK chains. Reading the immediates back out of
    // the instruction stream picks up what the run did not reach. Emulation
    // stays first: it also catches a value that was rotated, xored or built in
    // a loop, which no immediate scan can see.
    std::vector<uint64_t> materialised;
    for (uint64_t c : img->materialised_constants(fn))
      if (plausible(c))
        materialised.push_back(c);

    const AESKeyInfo *matched = exact_schedule_match(materialised);
    if (!matched)
      matched = exact_schedule_match(emulated);
    if (matched)
      return std::vector<uint8_t>(matched->key,
                                  matched->key + matched->key_size);
  }
  return key;
}

// Which code sites form the address of each string.
//
// The queries go through rizin's cross-reference database, which is exact: it
// decodes every instruction rather than matching a fixed ADRP/ADD shape, and it
// knows which function each site belongs to.
//
// Two things had to line up before this worked. rizin leaves data references
// switched off by default (analysis.datarefs / analysis.strings /
// analysis.refstr), and only the `aaa` pass populates them at all -- both are
// handled in Image::open. And rizin's own string table comes back empty in an
// embedded RzCore, so the strings are taken from hayabusa's scanner. Their file
// offsets must still be translated through the ELF PT_LOAD map before querying
// Rizin; returned reference sites remain virtual addresses.
std::map<uint64_t, std::vector<uint64_t>>
ElfParser::build_string_xref_map(const std::vector<uint8_t> &data,
                                 uint64_t base_addr, size_t max_strings,
                                 size_t max_xrefs, size_t max_string_bytes,
                                 bool *truncated) {
  (void)base_addr; // map keys are file offsets; sites are ELF virtual addresses
  std::map<uint64_t, std::vector<uint64_t>> out;
  if (truncated)
    *truncated = false;
  rzb::Image *img = session(data, 0);
  if (!img)
    return out;
  StringScanLimits limits;
  limits.max_results = max_strings;
  limits.max_retained_bytes = max_string_bytes;
  StringScanStatus string_status;
  auto strings = get_strings(data, 4, limits, &string_status);
  if (string_status.truncated && truncated)
    *truncated = true;
  size_t examined_remaining = std::max(max_strings, max_xrefs);
  for (size_t index = 0; index < strings.size(); index++) {
    if (img->budget_exhausted()) {
      if (truncated)
        *truncated = true;
      break;
    }
    const auto &s = strings[index];
    if (max_xrefs == 0 || examined_remaining == 0) {
      if (truncated)
        *truncated = true;
      break;
    }
    bool local_truncated = false;
    auto sites = img->xrefs_to(img->offset_to_vaddr(s.offset), max_xrefs,
                               &examined_remaining, &local_truncated);
    if (local_truncated && truncated)
      *truncated = true;
    if (!sites.empty())
      out[s.offset] = std::move(sites);
    const size_t used = out.count(s.offset) ? out[s.offset].size() : 0;
    max_xrefs -= std::min(max_xrefs, used);
  }
  return out;
}

std::string ElfParser::generate_signature(const std::vector<uint8_t> &data,
                                          uint64_t offset, size_t length) {
  rzb::Image *img = session(data, 0);
  if (!img)
    return "";
  std::vector<uint8_t> bytes;
  std::vector<bool> mask;
  if (!img->signature(img->offset_to_vaddr(offset), length, &bytes, &mask))
    return "";

  std::ostringstream sig;
  for (size_t i = 0; i < bytes.size(); i++) {
    if (mask[i])
      sig << "?? ";
    else
      sig << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i]
          << " ";
  }
  return sig.str();
}

std::vector<ElfParser::RecoveredName>
ElfParser::recover_names(const std::vector<uint8_t> &data, uint64_t base_addr) {
  std::vector<RecoveredName> out;
  rzb::Image *img = session(data, base_addr);
  if (!img)
    return out;

  // Names already carried by the symbol table are reported elsewhere; what is
  // wanted here is what analysis recovered on top of it. rizin names a function
  // from whichever source it found -- symbol, import stub, or a registration
  // structure a plugin understood -- so anything that is not one of its
  // generated `fcn.*` / `sub.*` placeholders is a real recovered binding.
  // rizin holds the image at its live load address, but every other producer
  // feeding the function map -- symbol st_value, the unwind table, branch
  // targets -- works module-relative. Returning absolute addresses here put the
  // recovered names past the end of that space, where they were sorted out of
  // the map and printed with the base added a second time.
  auto to_relative = [&](uint64_t addr) {
    return (base_addr && addr >= base_addr) ? addr - base_addr : addr;
  };

  std::set<uint64_t> seen;
  for (uint64_t addr : img->functions()) {
    if (img->budget_exhausted())
      break;
    if (!seen.insert(addr).second)
      continue;
    std::string name = img->name_at(addr);
    if (name.empty())
      continue;
    if (name.rfind("fcn.", 0) == 0 || name.rfind("sub.", 0) == 0 ||
        name.rfind("loc.", 0) == 0)
      continue;

    RecoveredName rn;
    rn.func_vaddr = to_relative(addr);
    rn.name = name;
    rn.source = "rizin analysis";
    out.push_back(std::move(rn));
  }

  // Anything reachable through a class vtable gets attributed to its class,
  // which is the binding a reader actually wants out of a stripped image.
  for (const auto &cls : img->rtti_classes()) {
    if (img->budget_exhausted())
      break;
    for (size_t i = 0; i < cls.vfuncs.size(); i++) {
      if (!cls.vfuncs[i] || !seen.insert(cls.vfuncs[i]).second)
        continue;
      RecoveredName rn;
      rn.func_vaddr = to_relative(cls.vfuncs[i]);
      rn.name = cls.name + "::vfunc_" + std::to_string(i);
      rn.source = "vtable";
      out.push_back(std::move(rn));
    }
  }

  std::sort(out.begin(), out.end(),
            [](const RecoveredName &a, const RecoveredName &b) {
              return a.func_vaddr < b.func_vaddr;
            });
  return out;
}
