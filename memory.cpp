#include "memory.h"
#include "tracer.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstring>
#include <cxxabi.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <set>
#include <unordered_map>
#include <signal.h>
#include <sstream>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif

#ifndef R_AARCH64_NONE
#define R_AARCH64_NONE 0
#endif

#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif

#ifndef R_AARCH64_ABS64
#define R_AARCH64_ABS64 257
#endif

#ifndef R_AARCH64_ABS32
#define R_AARCH64_ABS32 258
#endif

#ifndef R_AARCH64_ABS16
#define R_AARCH64_ABS16 259
#endif

#ifndef R_AARCH64_PREL64
#define R_AARCH64_PREL64 260
#endif

#ifndef R_AARCH64_PREL32
#define R_AARCH64_PREL32 261
#endif

#ifndef R_AARCH64_PREL16
#define R_AARCH64_PREL16 262
#endif

#ifndef R_AARCH64_GLOB_DAT
#define R_AARCH64_GLOB_DAT 1025
#endif

#ifndef R_AARCH64_TLS_DTPMOD64
#define R_AARCH64_TLS_DTPMOD64 1028
#endif

#ifndef R_AARCH64_TLS_DTPREL64
#define R_AARCH64_TLS_DTPREL64 1029
#endif

#ifndef R_AARCH64_TLS_TPREL64
#define R_AARCH64_TLS_TPREL64 1030
#endif

#ifndef R_AARCH64_TLSDESC
#define R_AARCH64_TLSDESC 1031
#endif

#ifndef R_AARCH64_IRELATIVE
#define R_AARCH64_IRELATIVE 1032
#endif

#ifndef DT_RELR
#define DT_RELR 36
#endif

#ifndef DT_RELRSZ
#define DT_RELRSZ 35
#endif

#ifndef DT_RELRENT
#define DT_RELRENT 37
#endif

#ifndef DT_ANDROID_RELR
#define DT_ANDROID_RELR 0x6fffe000
#endif

#ifndef DT_ANDROID_RELRSZ
#define DT_ANDROID_RELRSZ 0x6fffe001
#endif

#ifndef DT_ANDROID_RELRENT
#define DT_ANDROID_RELRENT 0x6fffe003
#endif

#ifndef SHT_RELR
#define SHT_RELR 19
#endif
#ifndef SHT_ANDROID_RELR
#define SHT_ANDROID_RELR 0x6fffff00
#endif
#ifndef SHT_GNU_verdef
#define SHT_GNU_verdef 0x6ffffffd
#endif
#ifndef SHT_GNU_verneed
#define SHT_GNU_verneed 0x6ffffffe
#endif
#ifndef SHT_GNU_versym
#define SHT_GNU_versym 0x6fffffff
#endif

#ifndef PT_GNU_RELRO
#define PT_GNU_RELRO 0x6474E552
#endif

static bool byte_range_fits(size_t size, uint64_t offset, uint64_t length) {
  return offset <= size &&
         length <= size - static_cast<size_t>(offset);
}

static bool checked_add_u64(uint64_t lhs, uint64_t rhs, uint64_t *out) {
  if (!out || lhs > std::numeric_limits<uint64_t>::max() - rhs)
    return false;
  *out = lhs + rhs;
  return true;
}

static bool checked_mul_u64(uint64_t lhs, uint64_t rhs, uint64_t *out) {
  if (!out || (rhs != 0 && lhs > std::numeric_limits<uint64_t>::max() / rhs))
    return false;
  *out = lhs * rhs;
  return true;
}

// Bidirectional vaddr <-> file-offset map, built once from PT_LOAD.
//
// The old helper re-parsed the program headers on every single lookup and only
// went one way. Both directions are needed: strings are found at file offsets
// but referenced by virtual address, and the two are NOT interchangeable --
// plenty of Android libraries map a segment at p_vaddr != p_offset, and
// assuming they match silently produced zero cross-references for them.
class AddrMap {
public:
  explicit AddrMap(const std::vector<uint8_t> &data) {
    limit_ = data.size();
    Elf64ProgramHeaders program_headers;
    if (!parse_elf64_program_headers(data, &program_headers))
      return;
    for (const auto &ph : program_headers.entries) {
      if (ph.p_type == PT_LOAD)
        segs_.push_back(
            {ph.p_vaddr, ph.p_offset, ph.p_memsz, ph.p_filesz});
    }
    for (const auto &s : segs_) {
      if (s.vaddr != s.off) {
        identity_ = false;
        break;
      }
    }
  }

  bool valid() const { return !segs_.empty(); }
  bool identity() const { return identity_; }

  bool to_offset(uint64_t vaddr, uint64_t *out) const {
    uint64_t available = 0;
    return mapped_available(vaddr, out, &available);
  }

  // Resolve a mapped byte and report how many file-backed bytes remain in the
  // same PT_LOAD. Hash tables are variable-length; bounding their walks by the
  // containing segment prevents a corrupt chain from consuming unrelated
  // bytes later in the image.
  bool mapped_available(uint64_t vaddr, uint64_t *out,
                        uint64_t *available) const {
    if (!out || !available)
      return false;
    for (const auto &s : segs_) {
      if (vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz) {
        const uint64_t delta = vaddr - s.vaddr;
        if (delta > std::numeric_limits<uint64_t>::max() - s.off)
          return false;
        const uint64_t o = s.off + delta;
        if (o >= limit_)
          return false;
        *out = o;
        *available = std::min<uint64_t>(s.filesz - delta, limit_ - o);
        return true;
      }
    }
    return false;
  }

  bool to_vaddr(uint64_t off, uint64_t *out) const {
    for (const auto &s : segs_) {
      if (off >= s.off && off - s.off < s.filesz) {
        *out = s.vaddr + (off - s.off);
        return true;
      }
    }
    return false;
  }

private:
  struct Seg {
    uint64_t vaddr, off, memsz, filesz;
  };
  std::vector<Seg> segs_;
  uint64_t limit_ = 0;
  bool identity_ = true;
};

static bool vaddr_to_offset(const std::vector<uint8_t> &data, uint64_t vaddr,
                            size_t &offset_out) {
  AddrMap map(data);
  uint64_t off = 0;
  if (!map.to_offset(vaddr, &off))
    return false;
  offset_out = static_cast<size_t>(off);
  return true;
}

std::vector<MapEntry> Memory::read_maps(int pid) {
  std::vector<MapEntry> entries;
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line)) {
    unsigned long start = 0, end = 0, offset = 0;
    char perms[5] = {0};
    char name[512] = {0};
    // %511[^\n] keeps paths that contain spaces intact.
    int parsed = sscanf(line.c_str(), "%lx-%lx %4s %lx %*s %*d %511[^\n]",
                        &start, &end, perms, &offset, name);
    if (parsed < 4)
      continue;
    MapEntry e;
    e.start = start;
    e.end = end;
    e.offset = offset;
    e.perms = perms;
    e.name = name;
    size_t first = e.name.find_first_not_of(" \t");
    e.name = (first == std::string::npos) ? "" : e.name.substr(first);
    entries.push_back(std::move(e));
  }
  return entries;
}

std::vector<uint8_t> Memory::dump(int pid, uint64_t addr, size_t size) {
  std::vector<uint8_t> buf(size, 0);
  if (size == 0)
    return buf;
  int fd = open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
  if (fd < 0)
    return {};
  bool any_read = false;
  for (size_t off = 0; off < size; off += 4096) {
    size_t len = std::min((size_t)4096, size - off);
    ssize_t rd = pread(fd, buf.data() + off, len, addr + off);
    if (rd > 0)
      any_read = true;
    if (rd > 0 && static_cast<size_t>(rd) < len) {
      memset(buf.data() + off + rd, 0, len - static_cast<size_t>(rd));
    }
  }
  close(fd);
  if (!any_read)
    return {};
  return buf;
}


std::string Utils::format_size(size_t bytes) {
  const char *u[] = {"B", "KB", "MB", "GB"};
  int i = 0;
  double s = bytes;
  while (s >= 1024 && i < 3) {
    s /= 1024;
    i++;
  }
  std::ostringstream ss;
  ss << std::fixed << std::setprecision(i ? 2 : 0) << s << u[i];
  return ss.str();
}


// AArch64 only: a 32-bit image is rejected here rather than half-parsed
// further down. Every other parser in this file reads Elf64_* structs directly,
// so this is the single gate that keeps an ELFCLASS32 buffer from being
// reinterpreted through 64-bit headers. e_machine is deliberately not checked:
// packers routinely mangle it in the images we dump, and the class byte is the
// only field that actually governs struct layout.
bool ElfParser::is_elf(const std::vector<uint8_t> &data) {
  return data.size() > EI_VERSION && data[0] == 0x7f && data[1] == 'E' &&
         data[2] == 'L' && data[3] == 'F' &&
         data[EI_CLASS] == ELFCLASS64 && data[EI_DATA] == ELFDATA2LSB &&
         data[EI_VERSION] == EV_CURRENT;
}

bool ElfParser::is_file_backed_vaddr(const std::vector<uint8_t> &data,
                                     uint64_t vaddr) {
  size_t offset = 0;
  return vaddr_to_offset(data, vaddr, offset);
}

using SymbolEmit =
    std::function<void(const char *name, uint64_t offset, uint64_t size,
                       uint8_t type)>;

static size_t iterate_symbols(const std::vector<uint8_t> &data,
                              const SymbolEmit &emit);
static bool vaddr_to_offset(const std::vector<uint8_t> &data, uint64_t vaddr,
                            size_t &offset);
template <int Bits>
static size_t gnu_hash_symbol_count(const std::vector<uint8_t> &data,
                                    uint64_t off, uint64_t available,
                                    size_t max_symbols,
                                    size_t *out_table_size);

std::vector<ElfSymbol>
ElfParser::get_symbols(const std::vector<uint8_t> &data) {
  std::vector<ElfSymbol> symbols;
  if (data.size() < 16 || !is_elf(data))
    return symbols;

  iterate_symbols(data,
                  [&](const char *name, uint64_t offset, uint64_t size,
                      uint8_t type) {
                    if (!name || name[0] == '\0')
                      return;
                    ElfSymbol s;
                    s.name = name;
                    s.offset = offset;
                    s.size = size;
                    s.type = (type == STT_FUNC)    ? "FUNC"
                             : (type == STT_OBJECT) ? "VAR"
                                                    : "OTHER";
                    symbols.push_back(s);
                  });
  return symbols;
}

template <int Bits>
static size_t iterate_symbols_shdr(const std::vector<uint8_t> &data,
                                   const typename ElfTypes<Bits>::Ehdr *ehdr,
                                   const SymbolEmit &emit) {
  using E = ElfTypes<Bits>;
  using Shdr = typename E::Shdr;
  using Sym = typename E::Sym;

  if (ehdr->e_shoff == 0 || ehdr->e_shentsize == 0 || ehdr->e_shnum == 0)
    return 0;
  if (ehdr->e_shentsize != sizeof(Shdr))
    return 0;
  if (ehdr->e_shoff > data.size() ||
      ehdr->e_shnum >
          (data.size() - static_cast<size_t>(ehdr->e_shoff)) / sizeof(Shdr))
    return 0;

  // A section header table is not part of any PT_LOAD, so an image lifted out
  // of memory does not have one -- but e_shoff still holds the offset it had in
  // the file, and on a small module that offset lands inside the loaded bytes.
  // Reading whatever is there as section headers produced a symbol table of
  // pure noise, hundreds of entries long, which then displaced the real symbols
  // from the dynamic table because this path is tried first.
  //
  // Section 0 is defined to be all zeroes. That is the cheapest thing to check
  // and it is decisive: real data at that offset is not.
  {
    Shdr first{};
    memcpy(&first, data.data() + ehdr->e_shoff, sizeof(first));
    if (first.sh_type != SHT_NULL || first.sh_name != 0 ||
        first.sh_offset != 0 || first.sh_size != 0)
      return 0;
  }
  if (ehdr->e_shstrndx >= ehdr->e_shnum)
    return 0;

  size_t total = 0;
  for (size_t i = 0; i < ehdr->e_shnum; i++) {
    const size_t shdr_off = static_cast<size_t>(ehdr->e_shoff) +
                            i * sizeof(Shdr);
    Shdr shdr{};
    memcpy(&shdr, data.data() + shdr_off, sizeof(shdr));
    if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
      continue;
    if (shdr.sh_link >= ehdr->e_shnum ||
        (shdr.sh_entsize != 0 && shdr.sh_entsize != sizeof(Sym)) ||
        !byte_range_fits(data.size(), shdr.sh_offset, shdr.sh_size))
      continue;
    const size_t strtab_header_off =
        static_cast<size_t>(ehdr->e_shoff) +
        static_cast<size_t>(shdr.sh_link) * sizeof(Shdr);
    Shdr strtab_shdr{};
    memcpy(&strtab_shdr, data.data() + strtab_header_off,
           sizeof(strtab_shdr));
    if (strtab_shdr.sh_type != SHT_STRTAB ||
        !byte_range_fits(data.size(), strtab_shdr.sh_offset,
                         strtab_shdr.sh_size))
      continue;
    const char *strtab = reinterpret_cast<const char *>(
        data.data() + static_cast<size_t>(strtab_shdr.sh_offset));
    const size_t num_syms = static_cast<size_t>(shdr.sh_size / sizeof(Sym));
    for (size_t j = 0; j < num_syms; j++) {
      const size_t sym_off = static_cast<size_t>(shdr.sh_offset) +
                             j * sizeof(Sym);
      Sym sym{};
      memcpy(&sym, data.data() + sym_off, sizeof(sym));
      if (sym.st_name == 0 || sym.st_name >= strtab_shdr.sh_size)
        continue;
      const size_t remaining =
          static_cast<size_t>(strtab_shdr.sh_size - sym.st_name);
      const char *name = strtab + sym.st_name;
      if (!memchr(name, '\0', remaining))
        continue;
      emit(name, sym.st_value, sym.st_size, E::ST_TYPE(sym.st_info));
      total++;
    }
  }
  return total;
}

// Fallback for images whose section headers were stripped or corrupted:
// walk PT_DYNAMIC and size the symbol table from DT_HASH or DT_GNU_HASH.
template <int Bits>
static size_t iterate_symbols_dynamic(const std::vector<uint8_t> &data,
                                      const typename ElfTypes<Bits>::Ehdr *ehdr,
                                      const SymbolEmit &emit) {
  using E = ElfTypes<Bits>;
  using Dyn = typename E::Dyn;
  using Sym = typename E::Sym;
  using Addr = typename E::Addr;
  static_assert(Bits == 64, "only ELF64 program headers are supported");
  (void)ehdr;

  Elf64ProgramHeaders program_headers;
  if (!parse_elf64_program_headers(data, &program_headers))
    return 0;

  Addr dyn_addr = 0, dyn_sz = 0;
  bool have_dynamic = false;
  for (const auto &ph : program_headers.entries) {
    if (ph.p_type == PT_DYNAMIC) {
      dyn_addr = ph.p_offset;
      dyn_sz = ph.p_filesz;
      have_dynamic = true;
      break;
    }
  }
  if (!have_dynamic || dyn_sz < sizeof(Dyn) || dyn_addr > data.size() ||
      dyn_sz > data.size() - static_cast<size_t>(dyn_addr))
    return 0;

  Addr symtab = 0, strtab = 0, hash = 0, gnu_hash = 0;
  uint64_t strsz = 0, syment = 0;
  bool have_symtab = false, have_strtab = false, have_strsz = false;
  bool have_syment = false, have_hash = false, have_gnu_hash = false;
  bool terminated = false;
  for (size_t i = 0; i < dyn_sz / sizeof(Dyn); i++) {
    Dyn dyn{};
    memcpy(&dyn, data.data() + dyn_addr + i * sizeof(Dyn), sizeof(Dyn));
    if (dyn.d_tag == DT_NULL) {
      terminated = true;
      break;
    }
    switch (dyn.d_tag) {
    case DT_SYMTAB:
      symtab = dyn.d_un.d_ptr;
      have_symtab = true;
      break;
    case DT_STRTAB:
      strtab = dyn.d_un.d_ptr;
      have_strtab = true;
      break;
    case DT_STRSZ:
      strsz = dyn.d_un.d_val;
      have_strsz = true;
      break;
    case DT_SYMENT:
      syment = dyn.d_un.d_val;
      have_syment = true;
      break;
    case DT_HASH:
      hash = dyn.d_un.d_ptr;
      have_hash = true;
      break;
    case DT_GNU_HASH:
      gnu_hash = dyn.d_un.d_ptr;
      have_gnu_hash = true;
      break;
    }
  }

  if (!terminated || !have_symtab || !have_strtab || !have_strsz ||
      !have_syment || syment != sizeof(Sym) || strsz == 0 ||
      (!have_hash && !have_gnu_hash))
    return 0;

  AddrMap map(data);
  uint64_t symtab_off = 0, symtab_available = 0;
  uint64_t strtab_off = 0, strtab_available = 0;
  if (!map.valid() ||
      !map.mapped_available(symtab, &symtab_off, &symtab_available) ||
      !map.mapped_available(strtab, &strtab_off, &strtab_available) ||
      strsz > strtab_available ||
      !byte_range_fits(data.size(), strtab_off, strsz))
    return 0;

  uint64_t symbol_bytes = symtab_available;
  if (strtab_off > symtab_off)
    symbol_bytes = std::min(symbol_bytes, strtab_off - symtab_off);
  const size_t max_symbols =
      static_cast<size_t>(symbol_bytes / sizeof(Sym));
  if (max_symbols == 0)
    return 0;

  size_t count = 0;
  if (have_hash) {
    uint64_t hash_off = 0, hash_available = 0;
    if (map.mapped_available(hash, &hash_off, &hash_available) &&
        hash_available >= 8 && byte_range_fits(data.size(), hash_off, 8)) {
      const uint32_t nbucket = read_le32(data.data() + hash_off);
      const uint32_t nchain = read_le32(data.data() + hash_off + 4);
      uint64_t words = 0, bytes = 0;
      if (nbucket != 0 && nchain != 0 && nchain <= max_symbols &&
          checked_add_u64(nbucket, nchain, &words) &&
          checked_add_u64(words, 2, &words) &&
          checked_mul_u64(words, sizeof(uint32_t), &bytes) &&
          bytes <= hash_available && byte_range_fits(data.size(), hash_off, bytes))
        count = nchain;
    }
  }

  if (count == 0 && have_gnu_hash) {
    uint64_t gnu_hash_off = 0, gnu_hash_available = 0;
    if (map.mapped_available(gnu_hash, &gnu_hash_off, &gnu_hash_available))
      count = gnu_hash_symbol_count<Bits>(data, gnu_hash_off,
                                          gnu_hash_available, max_symbols,
                                          nullptr);
  }

  if (count == 0 || count > max_symbols ||
      !byte_range_fits(data.size(), symtab_off,
                       static_cast<uint64_t>(count) * sizeof(Sym)))
    return 0;
  const size_t string_bytes = static_cast<size_t>(strsz);

  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    const size_t sym_off = static_cast<size_t>(symtab_off) + i * sizeof(Sym);
    Sym sym{};
    memcpy(&sym, data.data() + sym_off, sizeof(sym));
    if (sym.st_name == 0 || sym.st_name >= string_bytes)
      continue;
    const char *name = reinterpret_cast<const char *>(
        data.data() + static_cast<size_t>(strtab_off) + sym.st_name);
    if (!memchr(name, '\0', string_bytes - sym.st_name))
      continue;
    emit(name, sym.st_value, sym.st_size, E::ST_TYPE(sym.st_info));
    total++;
  }
  return total;
}

template <int Bits>
static size_t iterate_symbols_impl(const std::vector<uint8_t> &data,
                                   const SymbolEmit &emit) {
  using Ehdr = typename ElfTypes<Bits>::Ehdr;
  if (data.size() < sizeof(Ehdr))
    return 0;
  Ehdr ehdr{};
  memcpy(&ehdr, data.data(), sizeof(ehdr));
  size_t count = iterate_symbols_shdr<Bits>(data, &ehdr, emit);
  return count > 0 ? count : iterate_symbols_dynamic<Bits>(data, &ehdr, emit);
}

size_t ElfParser::count_symbols(const std::vector<uint8_t> &data) {
  return iterate_symbols(data, [](const char *, uint64_t, uint64_t, uint8_t) {
  });
}

size_t ElfParser::write_symbols(std::ostream &out,
                                const std::vector<uint8_t> &data,
                                std::vector<ElfSymbol> *vtables) {
  auto emit = [&](const char *name, uint64_t offset, uint64_t size,
                  uint8_t type) {
    if (!name || name[0] == '\0')
      return;
    const char *type_str = "OTHER";
    if (type == STT_FUNC)
      type_str = "FUNC";
    else if (type == STT_OBJECT)
      type_str = "VAR";
    std::string demangled = demangle_symbol(name);
    out << "0x" << std::hex << std::setw(8) << std::setfill('0') << offset
        << std::dec << " " << type_str << " " << demangled << "\n";
    if (vtables && std::strncmp(name, "_ZTV", 4) == 0) {
      ElfSymbol v;
      v.name = name;
      v.offset = offset;
      v.size = size;
      v.type = "VTABLE";
      vtables->push_back(std::move(v));
    }
  };
  return iterate_symbols(data, emit);
}

std::vector<ElfString> ElfParser::get_strings(const std::vector<uint8_t> &data,
                                              size_t min_len) {
  return get_strings(data, min_len, StringScanLimits{}, nullptr);
}

std::vector<ElfString>
ElfParser::get_strings(const std::vector<uint8_t> &data, size_t min_len,
                       const StringScanLimits &limits,
                       StringScanStatus *status) {
  std::vector<ElfString> strings;
  StringScanStatus scan;
  const size_t effective_min = std::max<size_t>(min_len, 1);
  size_t start = 0;
  size_t run = 0;

  auto retain_run = [&](size_t run_start, size_t run_length) {
    if (run_length < effective_min)
      return;
    scan.total_matches++;
    if (strings.size() >= limits.max_results ||
        run_length > limits.max_string_bytes ||
        scan.retained_bytes > limits.max_retained_bytes ||
        run_length > limits.max_retained_bytes - scan.retained_bytes) {
      scan.truncated = true;
      return;
    }
    strings.push_back(
        {static_cast<uint64_t>(run_start),
         std::string(reinterpret_cast<const char *>(data.data() + run_start),
                     run_length)});
    scan.retained_bytes += run_length;
  };

  for (size_t i = 0; i < data.size(); ++i) {
    const uint8_t c = data[i];
    if (c >= 32 && c < 127) {
      if (run == 0)
        start = i;
      ++run;
    } else {
      retain_run(start, run);
      run = 0;
    }
  }
  retain_run(start, run);
  scan.retained_results = strings.size();
  if (status)
    *status = scan;
  return strings;
}

size_t ElfParser::write_strings(std::ostream &out,
                                const std::vector<uint8_t> &data,
                                size_t min_len) {
  size_t count = 0;
  size_t run = 0;
  size_t start = 0;
  for (size_t i = 0; i < data.size(); i++) {
    unsigned char c = data[i];
    if (c >= 32 && c < 127) {
      if (run == 0)
        start = i;
      run++;
    } else {
      if (run >= min_len) {
        out << "0x" << std::hex << std::setw(8) << std::setfill('0') << start
            << std::dec << " ";
        out.write(reinterpret_cast<const char *>(data.data() + start),
                  static_cast<std::streamsize>(run));
        out << "\n";
        count++;
      }
      run = 0;
    }
  }
  if (run >= min_len) {
    out << "0x" << std::hex << std::setw(8) << std::setfill('0') << start
        << std::dec << " ";
    out.write(reinterpret_cast<const char *>(data.data() + start),
              static_cast<std::streamsize>(run));
    out << "\n";
    count++;
  }
  return count;
}

static const char g_shstrtab[] =
    "\0.dynsym\0.dynstr\0.hash\0.gnu.hash\0.rel.dyn\0.rel.plt\0.rela.dyn\0."
    "rela.plt\0"
    ".plt\0.text\0.rodata\0.init_array\0.fini_array\0.dynamic\0.got\0.got."
    "plt\0.data\0.bss\0.shstrtab\0.relr.dyn\0.gnu.version\0"
    ".gnu.version_d\0.gnu.version_r\0";

static uint32_t shstr_off(const char *name) {
  if (!name)
    return 0;
  for (size_t off = 1; off < sizeof(g_shstrtab);) {
    const size_t remaining = sizeof(g_shstrtab) - off;
    const size_t len = strnlen(g_shstrtab + off, remaining);
    if (len == remaining)
      return 0;
    if (strcmp(g_shstrtab + off, name) == 0)
      return static_cast<uint32_t>(off);
    off += len + 1;
  }
  return 0;
}

struct DynParsed {
  uint64_t strtab = 0, strsz = 0, symtab = 0, syment = 0;
  uint64_t hash = 0, gnu_hash = 0;
  uint64_t rel = 0, relsz = 0, relent = 0;
  uint64_t jmprel = 0, pltrelsz = 0;
  uint64_t pltgot = 0;
  uint64_t init_arr = 0, init_sz = 0, fini_arr = 0, fini_sz = 0;
  uint64_t relr = 0, relrsz = 0, relrent = 0;
  bool android_relr = false;
  uint64_t versym = 0, verdef = 0, verdefnum = 0;
  uint64_t verneed = 0, verneednum = 0;
};

// GNU version records use the same layout in ELF32 and ELF64.  Bionic exposes
// Verneed but not Verdef from <elf.h>, so keep one local, layout-checked view
// instead of depending on a non-portable libc typedef.
struct GnuVerdef {
  uint16_t version, flags, index, count;
  uint32_t hash, aux, next;
};
struct GnuVerdaux {
  uint32_t name, next;
};
struct GnuVerneed {
  uint16_t version, count;
  uint32_t file, aux, next;
};
struct GnuVernaux {
  uint32_t hash;
  uint16_t flags, other;
  uint32_t name, next;
};
static_assert(sizeof(GnuVerdef) == 20);
static_assert(sizeof(GnuVerdaux) == 8);
static_assert(sizeof(GnuVerneed) == 16);
static_assert(sizeof(GnuVernaux) == 16);

// Reads the dynamic tags and normalises the pointer-valued ones in place.
//
// `norm` must map a virtual address to the virtual address it will have in the
// repaired image -- not to a file offset. The dynamic section is defined in
// terms of virtual addresses, and every reader treats it that way: rizin, the
// loader, and hayabusa's own get_init_array. Writing file offsets back into it
// left the repaired image describing DT_INIT_ARRAY as a location that resolved,
// through the segment table, to the middle of .text -- so the constructors that
// the key-recovery pass emulates were random instructions.
template <typename Dyn>
static bool parse_dynamic_tags(
    std::vector<uint8_t> &image, uint64_t dyn_off, size_t dyn_n,
    const std::function<uint64_t(uint64_t)> &norm, int rel_tag,
    int relsz_tag, int relent_tag, uint64_t default_syment,
    uint64_t default_relent, DynParsed *out) {
  if (!out || dyn_n > std::numeric_limits<uint64_t>::max() / sizeof(Dyn) ||
      !byte_range_fits(image.size(), dyn_off,
                       static_cast<uint64_t>(dyn_n) * sizeof(Dyn)))
    return false;

  DynParsed p;
  p.syment = default_syment;
  p.relent = default_relent;
  bool terminated = false;
  bool std_relr_addr = false, std_relr_size = false, std_relr_ent = false;
  bool android_relr_addr = false, android_relr_size = false;
  bool android_relr_ent = false;
  bool versym_seen = false, verdef_seen = false, verdefnum_seen = false;
  bool verneed_seen = false, verneednum_seen = false;
  for (size_t i = 0; i < dyn_n; i++) {
    const size_t entry_off = static_cast<size_t>(dyn_off) + i * sizeof(Dyn);
    Dyn dyn{};
    memcpy(&dyn, image.data() + entry_off, sizeof(dyn));
    if (dyn.d_tag == DT_NULL) {
      terminated = true;
      break;
    }
    switch (dyn.d_tag) {
    case DT_STRTAB:
      p.strtab = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.strtab);
      break;
    case DT_STRSZ:
      p.strsz = dyn.d_un.d_val;
      break;
    case DT_SYMTAB:
      p.symtab = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.symtab);
      break;
    case DT_SYMENT:
      p.syment = dyn.d_un.d_val;
      break;
    case DT_HASH:
      p.hash = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.hash);
      break;
    case DT_GNU_HASH:
      p.gnu_hash = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.gnu_hash);
      break;
    case DT_JMPREL:
      p.jmprel = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.jmprel);
      break;
    case DT_PLTRELSZ:
      p.pltrelsz = dyn.d_un.d_val;
      break;
    case DT_PLTGOT:
      p.pltgot = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.pltgot);
      break;
    case DT_INIT_ARRAY:
      p.init_arr = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.init_arr);
      break;
    case DT_INIT_ARRAYSZ:
      p.init_sz = dyn.d_un.d_val;
      break;
    case DT_FINI_ARRAY:
      p.fini_arr = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.fini_arr);
      break;
    case DT_FINI_ARRAYSZ:
      p.fini_sz = dyn.d_un.d_val;
      break;
    case DT_RELR:
      if (std_relr_addr || android_relr_addr)
        return false;
      std_relr_addr = true;
      p.relr = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.relr);
      break;
    case DT_RELRSZ:
      if (std_relr_size || android_relr_size)
        return false;
      std_relr_size = true;
      p.relrsz = dyn.d_un.d_val;
      break;
    case DT_RELRENT:
      if (std_relr_ent || android_relr_ent)
        return false;
      std_relr_ent = true;
      p.relrent = dyn.d_un.d_val;
      break;
    case DT_ANDROID_RELR:
      if (android_relr_addr || std_relr_addr)
        return false;
      android_relr_addr = true;
      p.android_relr = true;
      p.relr = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.relr);
      break;
    case DT_ANDROID_RELRSZ:
      if (android_relr_size || std_relr_size)
        return false;
      android_relr_size = true;
      p.android_relr = true;
      p.relrsz = dyn.d_un.d_val;
      break;
    case DT_ANDROID_RELRENT:
      if (android_relr_ent || std_relr_ent)
        return false;
      android_relr_ent = true;
      p.android_relr = true;
      p.relrent = dyn.d_un.d_val;
      break;
    case DT_VERSYM:
      if (versym_seen)
        return false;
      versym_seen = true;
      p.versym = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.versym);
      break;
    case DT_VERDEF:
      if (verdef_seen)
        return false;
      verdef_seen = true;
      p.verdef = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.verdef);
      break;
    case DT_VERDEFNUM:
      if (verdefnum_seen)
        return false;
      verdefnum_seen = true;
      p.verdefnum = dyn.d_un.d_val;
      break;
    case DT_VERNEED:
      if (verneed_seen)
        return false;
      verneed_seen = true;
      p.verneed = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.verneed);
      break;
    case DT_VERNEEDNUM:
      if (verneednum_seen)
        return false;
      verneednum_seen = true;
      p.verneednum = dyn.d_un.d_val;
      break;
    default:
      break;
    }
    if (dyn.d_tag == rel_tag) {
      p.rel = dyn.d_un.d_ptr;
      dyn.d_un.d_ptr = norm(p.rel);
    } else if (dyn.d_tag == relsz_tag) {
      p.relsz = dyn.d_un.d_val;
    } else if (dyn.d_tag == relent_tag) {
      p.relent = dyn.d_un.d_val;
    }
    memcpy(image.data() + entry_off, &dyn, sizeof(dyn));
  }
  const bool any_std_relr = std_relr_addr || std_relr_size || std_relr_ent;
  const bool any_android_relr =
      android_relr_addr || android_relr_size || android_relr_ent;
  if (!terminated ||
      (any_std_relr &&
       !(std_relr_addr && std_relr_size && std_relr_ent)) ||
      (any_android_relr &&
       !(android_relr_addr && android_relr_size && android_relr_ent)) ||
      ((any_std_relr || any_android_relr) &&
       (p.relr == 0 || p.relrsz == 0 || p.relrent == 0)) ||
      (versym_seen && p.versym == 0) ||
      (verdef_seen != verdefnum_seen) ||
      (verdef_seen && (p.verdef == 0 || p.verdefnum == 0)) ||
      (verneed_seen != verneednum_seen) ||
      (verneed_seen && (p.verneed == 0 || p.verneednum == 0)))
    return false;
  *out = p;
  return true;
}

// DT_GNU_HASH layout: {nbuckets, symoffset, bloom_size, bloom_shift},
// bloom[bloom_size] (Addr-sized), buckets[nbuckets] (u32), chain[] (u32).
// The symbol table has no explicit count, so recover it by finding the highest
// bucket start and walking its chain to the terminator (low bit set).
// Returns 0 when the table cannot be trusted.
template <int Bits>
static size_t gnu_hash_symbol_count(const std::vector<uint8_t> &data,
                                    uint64_t off, uint64_t available,
                                    size_t max_symbols,
                                    size_t *out_table_size) {
  constexpr size_t W = ElfTypes<Bits>::WORD_SIZE;
  if (out_table_size)
    *out_table_size = 0;
  if (max_symbols == 0 || available < 16 ||
      !byte_range_fits(data.size(), off, available))
    return 0;

  uint64_t table_end = 0;
  if (!checked_add_u64(off, available, &table_end))
    return 0;
  auto table_range_fits = [&](uint64_t offset, uint64_t length) {
    return offset >= off && offset <= table_end &&
           length <= table_end - offset &&
           byte_range_fits(data.size(), offset, length);
  };

  const uint32_t nbuckets = read_le32(data.data() + off);
  const uint32_t symoffset = read_le32(data.data() + off + 4);
  const uint32_t bloom_size = read_le32(data.data() + off + 8);

  // Guard against corrupted headers before using them as sizes or indices.
  if (nbuckets == 0 || nbuckets > (1u << 22) || bloom_size == 0 ||
      bloom_size > (1u << 22) || symoffset > max_symbols)
    return 0;

  uint64_t bloom_bytes = 0, buckets_off = 0, bucket_bytes = 0;
  if (!checked_mul_u64(bloom_size, W, &bloom_bytes) ||
      !checked_add_u64(off, 16, &buckets_off) ||
      !checked_add_u64(buckets_off, bloom_bytes, &buckets_off) ||
      !checked_mul_u64(nbuckets, sizeof(uint32_t), &bucket_bytes) ||
      !table_range_fits(buckets_off, bucket_bytes))
    return 0;

  uint32_t last_sym = 0;
  bool have_bucket = false;
  for (uint32_t i = 0; i < nbuckets; i++) {
    const uint32_t bucket =
        read_le32(data.data() + buckets_off + static_cast<uint64_t>(i) * 4);
    if (bucket == 0)
      continue;
    if (bucket < symoffset || bucket >= max_symbols)
      return 0;
    have_bucket = true;
    if (bucket > last_sym)
      last_sym = bucket;
  }

  if (!have_bucket) {
    // Every bucket empty: the table holds only the undefined-symbol prefix.
    if (out_table_size)
      *out_table_size =
          static_cast<size_t>(buckets_off + bucket_bytes - off);
    return symoffset;
  }

  const uint64_t chain_off = buckets_off + bucket_bytes;
  for (;;) {
    uint64_t chain_delta = 0, entry = 0;
    if (!checked_mul_u64(static_cast<uint64_t>(last_sym - symoffset), 4,
                         &chain_delta) ||
        !checked_add_u64(chain_off, chain_delta, &entry) ||
        !table_range_fits(entry, 4))
      return 0;
    const uint32_t value = read_le32(data.data() + entry);
    if (value & 1)
      break;
    if (last_sym == 0xFFFFFFFFu || ++last_sym >= max_symbols)
      return 0;
  }

  if (out_table_size) {
    uint64_t chain_bytes = 0, end = 0;
    if (!checked_mul_u64(static_cast<uint64_t>(last_sym) + 1 - symoffset, 4,
                         &chain_bytes) ||
        !checked_add_u64(chain_off, chain_bytes, &end) || end < off ||
        end > table_end || end > data.size())
      return 0;
    *out_table_size = static_cast<size_t>(end - off);
  }
  return static_cast<size_t>(last_sym) + 1;
}

// Instantiate the dynamic-symbol walker only after the GNU-hash helper's
// definition is visible. Keeping this wrapper above the helper left an
// unresolved gnu_hash_symbol_count<64> specialization at link time.
static size_t iterate_symbols(const std::vector<uint8_t> &data,
                              const SymbolEmit &emit) {
  if (!ElfParser::is_elf(data))
    return 0;
  return iterate_symbols_impl<64>(data, emit);
}

// When the inode that supplied a live mapping is still available, it is the
// only authoritative source for loader-mutated relocation targets and for
// non-PT_LOAD metadata such as the section table.  Rebuild from that complete
// baseline, copy every live PT_LOAD byte over it, then restore exactly the
// relocation targets that the loader was allowed to change.  Guessing an
// external GOT value from its ASLR-resolved address is intentionally forbidden.
static bool repair_elf_from_disk_baseline(
    const std::vector<uint8_t> &runtime, const std::vector<uint8_t> &disk,
    std::vector<uint8_t> *out) {
  if (!out)
    return false;
  out->clear();

  Elf64ProgramHeaders runtime_ph, disk_ph;
  if (!parse_elf64_program_headers(runtime, &runtime_ph) ||
      !parse_elf64_program_headers(disk, &disk_ph) ||
      runtime_ph.entries.size() != disk_ph.entries.size())
    return false;

  const Elf64_Ehdr &rh = runtime_ph.header;
  const Elf64_Ehdr &dh = disk_ph.header;
  if (memcmp(rh.e_ident, dh.e_ident, EI_NIDENT) != 0 ||
      rh.e_type != dh.e_type || rh.e_machine != EM_AARCH64 ||
      rh.e_machine != dh.e_machine || rh.e_version != dh.e_version ||
      rh.e_entry != dh.e_entry || rh.e_phoff != dh.e_phoff ||
      rh.e_flags != dh.e_flags || rh.e_ehsize != dh.e_ehsize ||
      rh.e_phentsize != dh.e_phentsize || rh.e_phnum != dh.e_phnum)
    return false;
  for (size_t i = 0; i < runtime_ph.entries.size(); ++i)
    if (memcmp(&runtime_ph.entries[i], &disk_ph.entries[i],
               sizeof(Elf64_Phdr)) != 0)
      return false;

  // Extended section numbering is deliberately not guessed here.  A normal
  // Android shared object has a bounded, ordinary ELF64 section table.
  if (dh.e_shentsize != sizeof(Elf64_Shdr) || dh.e_shnum == 0 ||
      dh.e_shnum > 4096 || dh.e_shstrndx == SHN_UNDEF ||
      dh.e_shstrndx >= dh.e_shnum || dh.e_shoff > disk.size() ||
      dh.e_shnum > (disk.size() - static_cast<size_t>(dh.e_shoff)) /
                       sizeof(Elf64_Shdr))
    return false;
  std::vector<Elf64_Shdr> sections(dh.e_shnum);
  for (size_t i = 0; i < sections.size(); ++i) {
    memcpy(&sections[i], disk.data() + static_cast<size_t>(dh.e_shoff) +
                              i * sizeof(Elf64_Shdr),
           sizeof(Elf64_Shdr));
    const Elf64_Shdr &sh = sections[i];
    if (sh.sh_type != SHT_NOBITS &&
        !byte_range_fits(disk.size(), sh.sh_offset, sh.sh_size))
      return false;
  }
  const Elf64_Shdr &shstr = sections[dh.e_shstrndx];
  if (shstr.sh_type != SHT_STRTAB || shstr.sh_size == 0 ||
      !byte_range_fits(disk.size(), shstr.sh_offset, shstr.sh_size))
    return false;

  const Elf64_Phdr *dynamic = nullptr;
  for (const auto &ph : disk_ph.entries) {
    if (ph.p_type != PT_DYNAMIC)
      continue;
    if (dynamic)
      return false;
    dynamic = &ph;
  }
  if (!dynamic || dynamic->p_filesz < sizeof(Elf64_Dyn) ||
      dynamic->p_filesz % sizeof(Elf64_Dyn) != 0 ||
      !byte_range_fits(runtime.size(), dynamic->p_offset,
                       dynamic->p_filesz) ||
      !byte_range_fits(disk.size(), dynamic->p_offset, dynamic->p_filesz) ||
      memcmp(runtime.data() + dynamic->p_offset,
             disk.data() + dynamic->p_offset, dynamic->p_filesz) != 0)
    return false;

  struct RelocTuple {
    uint64_t address = 0, size = 0, entry = 0;
    bool have_address = false, have_size = false, have_entry = false;
  };
  RelocTuple rela, relr, android_relr;
  uint64_t jmprel = 0, pltrelsz = 0, pltrel = 0;
  bool have_jmprel = false, have_pltrelsz = false, have_pltrel = false;
  uint64_t symtab = 0, syment = 0;
  bool have_symtab = false, have_syment = false;
  bool terminated = false, tags_valid = true;
  auto record = [&](uint64_t value, uint64_t *slot, bool *seen) {
    if (*seen) {
      tags_valid = false;
      return;
    }
    *slot = value;
    *seen = true;
  };
  const size_t dyn_count =
      static_cast<size_t>(dynamic->p_filesz / sizeof(Elf64_Dyn));
  for (size_t i = 0; i < dyn_count; ++i) {
    Elf64_Dyn dyn{};
    memcpy(&dyn, disk.data() + dynamic->p_offset +
                     i * sizeof(Elf64_Dyn),
           sizeof(dyn));
    if (dyn.d_tag == DT_NULL) {
      terminated = true;
      break;
    }
    switch (dyn.d_tag) {
    case DT_SYMTAB:
      record(dyn.d_un.d_ptr, &symtab, &have_symtab);
      break;
    case DT_SYMENT:
      record(dyn.d_un.d_val, &syment, &have_syment);
      break;
    case DT_RELA:
      record(dyn.d_un.d_ptr, &rela.address, &rela.have_address);
      break;
    case DT_RELASZ:
      record(dyn.d_un.d_val, &rela.size, &rela.have_size);
      break;
    case DT_RELAENT:
      record(dyn.d_un.d_val, &rela.entry, &rela.have_entry);
      break;
    case DT_JMPREL:
      record(dyn.d_un.d_ptr, &jmprel, &have_jmprel);
      break;
    case DT_PLTRELSZ:
      record(dyn.d_un.d_val, &pltrelsz, &have_pltrelsz);
      break;
    case DT_PLTREL:
      record(dyn.d_un.d_val, &pltrel, &have_pltrel);
      break;
    case DT_RELR:
      record(dyn.d_un.d_ptr, &relr.address, &relr.have_address);
      break;
    case DT_RELRSZ:
      record(dyn.d_un.d_val, &relr.size, &relr.have_size);
      break;
    case DT_RELRENT:
      record(dyn.d_un.d_val, &relr.entry, &relr.have_entry);
      break;
    case DT_ANDROID_RELR:
      record(dyn.d_un.d_ptr, &android_relr.address,
             &android_relr.have_address);
      break;
    case DT_ANDROID_RELRSZ:
      record(dyn.d_un.d_val, &android_relr.size,
             &android_relr.have_size);
      break;
    case DT_ANDROID_RELRENT:
      record(dyn.d_un.d_val, &android_relr.entry,
             &android_relr.have_entry);
      break;
    default:
      break;
    }
  }
  if (!terminated || !tags_valid)
    return false;
  if (have_symtab != have_syment ||
      (have_syment && syment != sizeof(Elf64_Sym)))
    return false;

  auto complete_tuple = [](const RelocTuple &tuple, uint64_t entry_size) {
    const bool any = tuple.have_address || tuple.have_size || tuple.have_entry;
    return !any || (tuple.have_address && tuple.have_size &&
                    tuple.have_entry && tuple.size != 0 &&
                    tuple.entry == entry_size &&
                    tuple.size % entry_size == 0);
  };
  if (!complete_tuple(rela, sizeof(Elf64_Rela)) ||
      !complete_tuple(relr, sizeof(Elf64_Addr)) ||
      !complete_tuple(android_relr, sizeof(Elf64_Addr)) ||
      ((relr.have_address || relr.have_size || relr.have_entry) &&
       (android_relr.have_address || android_relr.have_size ||
        android_relr.have_entry)))
    return false;
  const bool any_plt = have_jmprel || have_pltrelsz || have_pltrel;
  if (any_plt &&
      (!have_jmprel || !have_pltrelsz || !have_pltrel ||
       pltrelsz == 0 || pltrelsz % sizeof(Elf64_Rela) != 0 ||
       pltrel != DT_RELA))
    return false;

  auto mapped_range = [&](uint64_t vaddr, uint64_t length,
                          uint64_t *file_offset,
                          bool *file_backed) -> bool {
    if (!file_offset || !file_backed)
      return false;
    for (const auto &ph : disk_ph.entries) {
      if (ph.p_type != PT_LOAD || vaddr < ph.p_vaddr)
        continue;
      const uint64_t delta = vaddr - ph.p_vaddr;
      if (delta > ph.p_memsz || length > ph.p_memsz - delta)
        continue;
      *file_backed = delta <= ph.p_filesz && length <= ph.p_filesz - delta;
      if (!*file_backed) {
        *file_offset = 0;
        return true;
      }
      if (!checked_add_u64(ph.p_offset, delta, file_offset) ||
          !byte_range_fits(runtime.size(), *file_offset, length) ||
          !byte_range_fits(disk.size(), *file_offset, length))
        return false;
      return true;
    }
    return false;
  };

  auto table_offset = [&](uint64_t vaddr, uint64_t size,
                          uint64_t *offset) -> bool {
    bool file_backed = false;
    return mapped_range(vaddr, size, offset, &file_backed) && file_backed &&
           memcmp(runtime.data() + *offset, disk.data() + *offset, size) == 0;
  };

  uint64_t rela_off = 0, jmprel_off = 0, relr_off = 0;
  if ((rela.have_address &&
       !table_offset(rela.address, rela.size, &rela_off)) ||
      (any_plt && !table_offset(jmprel, pltrelsz, &jmprel_off)))
    return false;
  const RelocTuple *active_relr = nullptr;
  if (relr.have_address)
    active_relr = &relr;
  else if (android_relr.have_address)
    active_relr = &android_relr;
  if (active_relr &&
      !table_offset(active_relr->address, active_relr->size, &relr_off))
    return false;

  std::vector<uint8_t> fixed = disk;
  for (const auto &ph : runtime_ph.entries) {
    if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
      continue;
    if (!byte_range_fits(runtime.size(), ph.p_offset, ph.p_filesz) ||
        !byte_range_fits(fixed.size(), ph.p_offset, ph.p_filesz))
      return false;
    memcpy(fixed.data() + ph.p_offset, runtime.data() + ph.p_offset,
           ph.p_filesz);
  }

  auto restore_target = [&](uint64_t vaddr, uint64_t width) -> bool {
    uint64_t offset = 0;
    bool file_backed = false;
    if (!mapped_range(vaddr, width, &offset, &file_backed))
      return false;
    if (file_backed)
      memcpy(fixed.data() + offset, disk.data() + offset, width);
    return true;
  };
  auto read_dynamic_symbol = [&](uint32_t index, Elf64_Sym *symbol,
                                 bool *defined) -> bool {
    if (!symbol || !defined || !have_symtab || !have_syment)
      return false;
    uint64_t delta = 0, address = 0, offset = 0;
    bool file_backed = false;
    if (!checked_mul_u64(index, sizeof(Elf64_Sym), &delta) ||
        !checked_add_u64(symtab, delta, &address) ||
        !mapped_range(address, sizeof(Elf64_Sym), &offset, &file_backed) ||
        !file_backed)
      return false;
    memcpy(symbol, disk.data() + offset, sizeof(*symbol));
    *defined = symbol->st_shndx != SHN_UNDEF &&
               symbol->st_shndx != SHN_COMMON;
    return true;
  };
  auto write_target_u64 = [&](uint64_t vaddr, uint64_t value) -> bool {
    uint64_t offset = 0;
    bool file_backed = false;
    if (!mapped_range(vaddr, sizeof(value), &offset, &file_backed))
      return false;
    if (file_backed)
      memcpy(fixed.data() + offset, &value, sizeof(value));
    return true;
  };
  auto relocation_width = [](uint32_t type) -> uint64_t {
    switch (type) {
    case R_AARCH64_ABS16:
    case R_AARCH64_PREL16:
      return 2;
    case R_AARCH64_ABS32:
    case R_AARCH64_PREL32:
      return 4;
    case R_AARCH64_ABS64:
    case R_AARCH64_PREL64:
    case R_AARCH64_GLOB_DAT:
    case R_AARCH64_JUMP_SLOT:
    case R_AARCH64_RELATIVE:
    case R_AARCH64_TLS_DTPMOD64:
    case R_AARCH64_TLS_DTPREL64:
    case R_AARCH64_TLS_TPREL64:
    case R_AARCH64_IRELATIVE:
      return 8;
    case R_AARCH64_TLSDESC:
      return 16;
    default:
      return 0;
    }
  };
  auto restore_rela_table = [&](uint64_t offset, uint64_t size) -> bool {
    const size_t count = static_cast<size_t>(size / sizeof(Elf64_Rela));
    for (size_t i = 0; i < count; ++i) {
      Elf64_Rela relocation{};
      memcpy(&relocation,
             disk.data() + offset + i * sizeof(Elf64_Rela),
             sizeof(relocation));
      const uint32_t type = ELF64_R_TYPE(relocation.r_info);
      if (type == R_AARCH64_NONE)
        continue;
      if (type == R_AARCH64_ABS64) {
        const uint32_t symbol_index = ELF64_R_SYM(relocation.r_info);
        Elf64_Sym symbol{};
        bool defined = false;
        if (!read_dynamic_symbol(symbol_index, &symbol, &defined))
          return false;
        if (defined) {
          uint64_t resolved = symbol.st_value;
          if (relocation.r_addend >= 0) {
            if (!checked_add_u64(
                    resolved, static_cast<uint64_t>(relocation.r_addend),
                    &resolved))
              return false;
          } else {
            const uint64_t magnitude =
                static_cast<uint64_t>(-(relocation.r_addend + 1)) + 1;
            if (resolved < magnitude)
              return false;
            resolved -= magnitude;
          }
          if (!write_target_u64(relocation.r_offset, resolved))
            return false;
          continue;
        }
      }
      const uint64_t width = relocation_width(type);
      if (width == 0)
        return false;
      if (!restore_target(relocation.r_offset, width))
        return false;
    }
    return true;
  };
  if ((rela.have_address && !restore_rela_table(rela_off, rela.size)) ||
      (any_plt && !restore_rela_table(jmprel_off, pltrelsz)))
    return false;

  if (active_relr) {
    uint64_t cursor = 0;
    size_t restored = 0;
    const size_t count =
        static_cast<size_t>(active_relr->size / sizeof(Elf64_Addr));
    for (size_t i = 0; i < count; ++i) {
      const uint64_t entry = read_le64(disk.data() + relr_off + i * 8);
      if ((entry & 1u) == 0) {
        if ((entry & 7u) != 0 || (cursor != 0 && entry < cursor) ||
            !restore_target(entry, sizeof(Elf64_Addr)) ||
            !checked_add_u64(entry, sizeof(Elf64_Addr), &cursor))
          return false;
        ++restored;
      } else {
        if (cursor == 0)
          return false;
        for (unsigned bit = 1; bit < 64; ++bit) {
          if ((entry & (uint64_t{1} << bit)) == 0)
            continue;
          uint64_t delta = 0, target = 0;
          if (!checked_mul_u64(bit - 1, sizeof(Elf64_Addr), &delta) ||
              !checked_add_u64(cursor, delta, &target) ||
              !restore_target(target, sizeof(Elf64_Addr)))
            return false;
          if (++restored > 10000000)
            return false;
        }
        uint64_t advance = 0;
        if (!checked_mul_u64(63, sizeof(Elf64_Addr), &advance) ||
            !checked_add_u64(cursor, advance, &cursor))
          return false;
      }
    }
  }

  *out = std::move(fixed);
  return true;
}

// Rebuild a usable section-header table for a memory-dumped shared object.
// ELF metadata remains in its link-time address domain; only pointer *contents*
// that the loader relocated into this module's live address range are converted
// back to link-time virtual addresses. ARM (REL) and AArch64 (RELA) differ only
// in the traits pulled from ElfTypes<Bits>.
template <int Bits>
static std::vector<uint8_t> repair_elf(const std::vector<uint8_t> &data,
                                       uint64_t base_addr,
                                       const std::vector<uint8_t> *disk) {
  using E = ElfTypes<Bits>;
  using Ehdr = typename E::Ehdr;
  using Phdr = typename E::Phdr;
  using Shdr = typename E::Shdr;
  using Sym = typename E::Sym;
  using Dyn = typename E::Dyn;
  using Rel = typename E::RelType;
  using Addr = typename E::Addr;

  static_assert(Bits == 64, "only ELF64 repair is supported");
  static_assert(sizeof(Ehdr) == sizeof(Elf64_Ehdr));
  static_assert(sizeof(Phdr) == sizeof(Elf64_Phdr));
  constexpr uint64_t W = E::WORD_SIZE;

  if (disk) {
    std::vector<uint8_t> restored;
    if (repair_elf_from_disk_baseline(data, *disk, &restored))
      return restored;
    // A supplied baseline is either authoritative or rejected. Falling back
    // to heuristic GOT reconstruction would turn a validation failure into a
    // plausible-looking but incorrect ELF.
    return data;
  }

  Elf64ProgramHeaders program_headers;
  if (!parse_elf64_program_headers(data, &program_headers))
    return data;

  Ehdr ehdr{};
  memcpy(&ehdr, data.data(), sizeof(ehdr));
  if (ehdr.e_ident[EI_CLASS] != E::ELFCLASS)
    return data;

  std::vector<uint8_t> fixed = data;

  // Snapshot the original PT_LOAD table. Dynamic addresses, symbol values and
  // relocation metadata already use this link-time address space in a live
  // Android mapping and must not be rebased a second time.
  struct LoadSeg {
    uint64_t vaddr, offset, filesz, memsz;
  };
  std::vector<LoadSeg> loads;
  uint64_t dyn_vaddr = 0, dyn_off = 0, dyn_sz = 0;
  bool have_dynamic = false;

  for (const auto &raw_ph : program_headers.entries) {
    if (raw_ph.p_type == PT_LOAD) {
      // Keep these checks local to the mutable repair path as a defence in
      // depth measure: r() below relies on every subtraction being valid.
      if (raw_ph.p_filesz > raw_ph.p_memsz ||
          !byte_range_fits(data.size(), raw_ph.p_offset, raw_ph.p_filesz) ||
          raw_ph.p_vaddr >
              std::numeric_limits<uint64_t>::max() - raw_ph.p_memsz)
        return data;
      loads.push_back({raw_ph.p_vaddr, raw_ph.p_offset, raw_ph.p_filesz,
                       raw_ph.p_memsz});
    } else if (raw_ph.p_type == PT_DYNAMIC && !have_dynamic) {
      if (!byte_range_fits(data.size(), raw_ph.p_offset, raw_ph.p_filesz))
        return data;
      dyn_vaddr = raw_ph.p_vaddr;
      dyn_off = raw_ph.p_offset;
      dyn_sz = raw_ph.p_filesz;
      have_dynamic = true;
    }
  }
  if (loads.empty())
    return data;

  // Translate a virtual range only when all of it is backed by bytes in one
  // validated PT_LOAD. BSS-only addresses deliberately fail: there is no file
  // storage that can safely be rewritten for them.
  auto r = [&](uint64_t address, uint64_t length, uint64_t *out) -> bool {
    if (!out)
      return false;
    for (const auto &load : loads) {
      if (address < load.vaddr)
        continue;
      const uint64_t delta = address - load.vaddr;
      if (delta > load.filesz || length > load.filesz - delta)
        continue;
      uint64_t offset = 0;
      if (!checked_add_u64(load.offset, delta, &offset) ||
          !byte_range_fits(fixed.size(), offset, length))
        return false;
      *out = offset;
      return true;
    }
    return false;
  };

  auto mapped_available = [&](uint64_t address, uint64_t *out_offset,
                              uint64_t *out_available) -> bool {
    if (!out_offset || !out_available)
      return false;
    for (const auto &load : loads) {
      if (address < load.vaddr)
        continue;
      const uint64_t delta = address - load.vaddr;
      if (delta > load.filesz)
        continue;
      uint64_t offset = 0;
      if (!checked_add_u64(load.offset, delta, &offset) ||
          offset > fixed.size())
        return false;
      const uint64_t segment_available = load.filesz - delta;
      const uint64_t image_available = fixed.size() -
                                       static_cast<size_t>(offset);
      *out_offset = offset;
      *out_available = std::min(segment_available, image_available);
      return true;
    }
    return false;
  };

  auto normalize_runtime_pointer = [&](Addr value, Addr *out) -> bool {
    if (!out || base_addr == 0 || value == 0)
      return false;
    const uint64_t raw = static_cast<uint64_t>(value);
    if (raw == base_addr) {
      *out = 0;
      return true;
    }
    for (const auto &load : loads) {
      uint64_t runtime_start = 0, runtime_end = 0;
      if (!checked_add_u64(base_addr, load.vaddr, &runtime_start) ||
          !checked_add_u64(runtime_start, load.memsz, &runtime_end))
        continue;
      if (raw >= runtime_start && raw < runtime_end) {
        *out = static_cast<Addr>(raw - base_addr);
        return true;
      }
    }
    return false;
  };

  auto is_link_time_pointer = [&](Addr value) -> bool {
    const uint64_t raw = static_cast<uint64_t>(value);
    if (raw == 0)
      return true;
    for (const auto &load : loads) {
      uint64_t end = 0;
      if (!checked_add_u64(load.vaddr, load.memsz, &end))
        continue;
      if (raw >= load.vaddr && raw < end)
        return true;
    }
    return false;
  };

  if (have_dynamic) {
    uint64_t mapped_dyn_off = 0;
    if (!r(dyn_vaddr, dyn_sz, &mapped_dyn_off) || mapped_dyn_off != dyn_off)
      return data;
  }

  Shdr shdr[22] = {};

  // Section addresses and all dynamic pointers stay in the original link-time
  // virtual-address domain.
  auto va = [](uint64_t address) -> uint64_t { return address; };

  size_t nDynSyms = 0;

  if (have_dynamic && dyn_sz >= sizeof(Dyn) &&
      byte_range_fits(fixed.size(), dyn_off, dyn_sz)) {
    shdr[12].sh_name = shstr_off(".dynamic");
    shdr[12].sh_type = SHT_DYNAMIC;
    shdr[12].sh_flags = SHF_WRITE | SHF_ALLOC;
    shdr[12].sh_addr = va(dyn_vaddr);
    shdr[12].sh_offset = dyn_off;
    shdr[12].sh_size = dyn_sz;
    shdr[12].sh_link = 2;
    shdr[12].sh_addralign = W;
    shdr[12].sh_entsize = E::DYN_ENTSIZE;

    const size_t dyn_n = static_cast<size_t>(dyn_sz / sizeof(Dyn));
    DynParsed dp;
    if (!parse_dynamic_tags<Dyn>(fixed, dyn_off, dyn_n, va, E::DT_REL_TAG,
                                 E::DT_RELSZ_TAG, E::DT_RELENT_TAG,
                                 sizeof(Sym), sizeof(Rel), &dp))
      return data;

    const uint64_t strtab = dp.strtab, strsz = dp.strsz, symtab = dp.symtab;
    const uint64_t syment = dp.syment;
    const uint64_t hash = dp.hash, gnu_hash = dp.gnu_hash;
    const uint64_t reloc = dp.rel, relocsz = dp.relsz, relocent = dp.relent;
    const uint64_t jmprel = dp.jmprel, pltrelsz = dp.pltrelsz;
    const uint64_t pltgot = dp.pltgot;
    const uint64_t init_arr = dp.init_arr, init_sz = dp.init_sz;
    const uint64_t fini_arr = dp.fini_arr, fini_sz = dp.fini_sz;

    uint64_t sym_off = 0, sym_available = 0;
    size_t max_syms = 0;
    if (syment == sizeof(Sym) &&
        mapped_available(symtab, &sym_off, &sym_available)) {
      uint64_t sym_limit = sym_available;
      uint64_t str_off_for_limit = 0;
      if (r(strtab, 0, &str_off_for_limit) && str_off_for_limit > sym_off)
        sym_limit = std::min(sym_limit, str_off_for_limit - sym_off);
      max_syms = static_cast<size_t>(sym_limit / sizeof(Sym));
    }

    if (hash) {
      uint64_t h_off = 0;
      if (r(hash, 8, &h_off)) {
        const uint32_t nbucket = read_le32(fixed.data() + h_off);
        const uint32_t nchain = read_le32(fixed.data() + h_off + 4);
        uint64_t hash_words = 0, hash_size = 0;
        const bool valid_hash =
            nbucket != 0 && nchain != 0 && nchain <= max_syms &&
            checked_add_u64(nbucket, nchain, &hash_words) &&
            checked_add_u64(hash_words, 2, &hash_words) &&
            checked_mul_u64(hash_words, sizeof(uint32_t), &hash_size) &&
            r(hash, hash_size, &h_off);
        if (valid_hash) {
          nDynSyms = nchain;
          shdr[3].sh_name = shstr_off(".hash");
          shdr[3].sh_type = SHT_HASH;
          shdr[3].sh_flags = SHF_ALLOC;
          shdr[3].sh_addr = va(hash);
          shdr[3].sh_offset = h_off;
          shdr[3].sh_size = hash_size;
          shdr[3].sh_link = 1;
          shdr[3].sh_addralign = sizeof(uint32_t);
          shdr[3].sh_entsize = 4;
        }
      }
    }

    if (gnu_hash && max_syms != 0) {
      uint64_t gnu_hash_off = 0, gnu_hash_available = 0;
      if (mapped_available(gnu_hash, &gnu_hash_off, &gnu_hash_available)) {
        size_t gnu_hash_size = 0;
        const size_t gnu_symbols = gnu_hash_symbol_count<Bits>(
            fixed, gnu_hash_off, gnu_hash_available, max_syms,
            &gnu_hash_size);
        uint64_t checked_off = 0;
        if (gnu_symbols != 0 && gnu_hash_size != 0 &&
            r(gnu_hash, gnu_hash_size, &checked_off) &&
            checked_off == gnu_hash_off) {
          if (nDynSyms != 0 && nDynSyms != gnu_symbols)
            return data;
          nDynSyms = gnu_symbols;
          shdr[4].sh_name = shstr_off(".gnu.hash");
          shdr[4].sh_type = SHT_GNU_HASH;
          shdr[4].sh_flags = SHF_ALLOC;
          shdr[4].sh_addr = va(gnu_hash);
          shdr[4].sh_offset = gnu_hash_off;
          shdr[4].sh_size = gnu_hash_size;
          shdr[4].sh_link = 1;
          shdr[4].sh_addralign = W;
        }
      }
    }

    if (nDynSyms > max_syms)
      nDynSyms = 0;

    if (symtab && nDynSyms > 0) {
      uint64_t sym_bytes = 0;
      if (!checked_mul_u64(nDynSyms, sizeof(Sym), &sym_bytes) ||
          !r(symtab, sym_bytes, &sym_off)) {
        nDynSyms = 0;
      } else {
        shdr[1].sh_name = shstr_off(".dynsym");
        shdr[1].sh_type = SHT_DYNSYM;
        shdr[1].sh_flags = SHF_ALLOC;
        shdr[1].sh_addr = va(symtab);
        shdr[1].sh_offset = sym_off;
        shdr[1].sh_size = sym_bytes;
        shdr[1].sh_link = 2;
        shdr[1].sh_info = 1;
        shdr[1].sh_addralign = W;
        shdr[1].sh_entsize = sizeof(Sym);
      }
    }

    uint64_t str_off = 0;
    bool have_valid_strtab = false;
    if (strtab && strsz) {
      if (r(strtab, strsz, &str_off)) {
        have_valid_strtab = true;
        shdr[2].sh_name = shstr_off(".dynstr");
        shdr[2].sh_type = SHT_STRTAB;
        shdr[2].sh_flags = SHF_ALLOC;
        shdr[2].sh_addr = va(strtab);
        shdr[2].sh_offset = str_off;
        shdr[2].sh_size = strsz;
        shdr[2].sh_addralign = 1;
      }
    }

    // RELR encodes one direct target followed by zero or more 63-bit target
    // bitmaps.  The table itself remains in link-time form; only the pointer
    // contents at file-backed targets were changed by the loader.
    if (dp.relr || dp.relrsz || dp.relrent) {
      if (!dp.relr || !dp.relrsz || dp.relrent != W || dp.relrsz % W != 0)
        return data;
      uint64_t relr_off = 0;
      if (!r(dp.relr, dp.relrsz, &relr_off))
        return data;

      shdr[18].sh_name = shstr_off(".relr.dyn");
      shdr[18].sh_type = dp.android_relr ? SHT_ANDROID_RELR : SHT_RELR;
      shdr[18].sh_flags = SHF_ALLOC;
      shdr[18].sh_addr = va(dp.relr);
      shdr[18].sh_offset = relr_off;
      shdr[18].sh_size = dp.relrsz;
      shdr[18].sh_addralign = W;
      shdr[18].sh_entsize = W;

      uint64_t maximum_targets = 0;
      for (const auto &load : loads)
        if (!checked_add_u64(maximum_targets, load.memsz / W,
                             &maximum_targets))
          return data;
      uint64_t expanded_targets = 0;
      auto normalize_relr_target = [&](uint64_t target) -> bool {
        if ((target & (W - 1)) != 0)
          return false;
        uint64_t target_off = 0;
        if (r(target, W, &target_off)) {
          Addr value{}, normalized{};
          memcpy(&value, fixed.data() + target_off, sizeof(value));
          if (normalize_runtime_pointer(value, &normalized)) {
            memcpy(fixed.data() + target_off, &normalized,
                   sizeof(normalized));
            return true;
          }
          return is_link_time_pointer(value);
        }
        // A RELR may target BSS.  It is valid metadata but there are no bytes
        // for a reconstructed file to rewrite.
        for (const auto &load : loads) {
          if (target < load.vaddr)
            continue;
          const uint64_t delta = target - load.vaddr;
          if (delta <= load.memsz && W <= load.memsz - delta)
            return true;
        }
        return false;
      };
      auto consume_relr_target = [&](uint64_t target) -> bool {
        if (expanded_targets == maximum_targets)
          return false;
        ++expanded_targets;
        return normalize_relr_target(target);
      };

      uint64_t cursor = 0;
      bool have_cursor = false;
      const size_t count = static_cast<size_t>(dp.relrsz / W);
      for (size_t i = 0; i < count; ++i) {
        const uint64_t entry =
            read_le64(fixed.data() + relr_off + static_cast<uint64_t>(i) * W);
        if ((entry & 1u) == 0) {
          if ((entry & (W - 1)) != 0 ||
              (have_cursor && entry < cursor) ||
              !consume_relr_target(entry) ||
              !checked_add_u64(entry, W, &cursor))
            return data;
          have_cursor = true;
          continue;
        }
        if (!have_cursor)
          return data;
        for (unsigned bit = 1; bit < 64; ++bit) {
          if ((entry & (uint64_t{1} << bit)) == 0)
            continue;
          uint64_t delta = 0, target = 0;
          if (!checked_mul_u64(bit - 1, W, &delta) ||
              !checked_add_u64(cursor, delta, &target) ||
              !consume_relr_target(target))
            return data;
        }
        uint64_t advance = 0;
        if (!checked_mul_u64(63, W, &advance) ||
            !checked_add_u64(cursor, advance, &cursor))
          return data;
      }
    }

    uint64_t versym_off = 0, versym_size = 0;
    if (dp.versym) {
      if (nDynSyms == 0 ||
          !checked_mul_u64(nDynSyms, sizeof(uint16_t), &versym_size) ||
          !r(dp.versym, versym_size, &versym_off))
        return data;
      shdr[19].sh_name = shstr_off(".gnu.version");
      shdr[19].sh_type = SHT_GNU_versym;
      shdr[19].sh_flags = SHF_ALLOC;
      shdr[19].sh_addr = va(dp.versym);
      shdr[19].sh_offset = versym_off;
      shdr[19].sh_size = versym_size;
      shdr[19].sh_link = 1;
      shdr[19].sh_addralign = sizeof(uint16_t);
      shdr[19].sh_entsize = sizeof(uint16_t);
    }
    if ((dp.verdef || dp.verneed) && !dp.versym)
      return data;

    std::set<uint16_t> known_version_indexes;
    auto read_version_record = [&](uint64_t address, void *record,
                                   size_t size) -> bool {
      uint64_t offset = 0;
      if (!record || !r(address, size, &offset))
        return false;
      memcpy(record, fixed.data() + offset, size);
      return true;
    };
    auto valid_version_name = [&](uint32_t name) -> bool {
      if (!have_valid_strtab || name == 0 || name >= strsz)
        return false;
      const size_t offset = static_cast<size_t>(str_off + name);
      const size_t remaining = static_cast<size_t>(strsz - name);
      return fixed[offset] != 0 &&
             memchr(fixed.data() + offset, '\0', remaining) != nullptr;
    };
    auto remember_version_index = [&](uint16_t raw_index,
                                      bool dependency) -> bool {
      const uint16_t index = raw_index & 0x7fff;
      if (index == 0 || (dependency && index == 1))
        return false;
      return known_version_indexes.insert(index).second;
    };

    auto validate_verdef = [&](uint64_t address, uint64_t records,
                               uint64_t *span) -> bool {
      if (!span || records == 0 ||
          records > fixed.size() / sizeof(GnuVerdef))
        return false;
      uint64_t current = address;
      for (uint64_t i = 0; i < records; ++i) {
        GnuVerdef definition{};
        if (!read_version_record(current, &definition, sizeof(definition)) ||
            definition.version != VER_DEF_CURRENT || definition.count == 0 ||
            definition.aux < sizeof(definition) ||
            (definition.aux & 3u) != 0 ||
            !remember_version_index(definition.index, false))
          return false;
        uint64_t record_end = 0, auxiliary = 0;
        if (!checked_add_u64(current, sizeof(definition), &record_end) ||
            !checked_add_u64(current, definition.aux, &auxiliary) ||
            auxiliary < record_end)
          return false;
        for (uint16_t j = 0; j < definition.count; ++j) {
          GnuVerdaux aux{};
          if (!read_version_record(auxiliary, &aux, sizeof(aux)) ||
              !valid_version_name(aux.name))
            return false;
          uint64_t aux_end = 0;
          if (!checked_add_u64(auxiliary, sizeof(aux), &aux_end))
            return false;
          record_end = std::max(record_end, aux_end);
          const bool last = j + 1 == definition.count;
          if ((last && aux.next != 0) ||
              (!last && (aux.next < sizeof(aux) || (aux.next & 3u) != 0)))
            return false;
          if (!last) {
            uint64_t next = 0;
            if (!checked_add_u64(auxiliary, aux.next, &next) || next < aux_end)
              return false;
            auxiliary = next;
          }
        }
        const bool last = i + 1 == records;
        if ((last && definition.next != 0) ||
            (!last &&
             (definition.next < sizeof(definition) ||
              (definition.next & 3u) != 0)))
          return false;
        if (last) {
          if (record_end < address)
            return false;
          *span = record_end - address;
          return *span != 0;
        }
        uint64_t next = 0;
        if (!checked_add_u64(current, definition.next, &next) ||
            next < record_end)
          return false;
        current = next;
      }
      return false;
    };

    auto validate_verneed = [&](uint64_t address, uint64_t records,
                                uint64_t *span) -> bool {
      if (!span || records == 0 ||
          records > fixed.size() / sizeof(GnuVerneed))
        return false;
      uint64_t current = address;
      for (uint64_t i = 0; i < records; ++i) {
        GnuVerneed need{};
        if (!read_version_record(current, &need, sizeof(need)) ||
            need.version != VER_NEED_CURRENT || need.count == 0 ||
            !valid_version_name(need.file) || need.aux < sizeof(need) ||
            (need.aux & 3u) != 0)
          return false;
        uint64_t record_end = 0, auxiliary = 0;
        if (!checked_add_u64(current, sizeof(need), &record_end) ||
            !checked_add_u64(current, need.aux, &auxiliary) ||
            auxiliary < record_end)
          return false;
        for (uint16_t j = 0; j < need.count; ++j) {
          GnuVernaux aux{};
          if (!read_version_record(auxiliary, &aux, sizeof(aux)) ||
              !valid_version_name(aux.name) ||
              !remember_version_index(aux.other, true))
            return false;
          uint64_t aux_end = 0;
          if (!checked_add_u64(auxiliary, sizeof(aux), &aux_end))
            return false;
          record_end = std::max(record_end, aux_end);
          const bool last = j + 1 == need.count;
          if ((last && aux.next != 0) ||
              (!last && (aux.next < sizeof(aux) || (aux.next & 3u) != 0)))
            return false;
          if (!last) {
            uint64_t next = 0;
            if (!checked_add_u64(auxiliary, aux.next, &next) || next < aux_end)
              return false;
            auxiliary = next;
          }
        }
        const bool last = i + 1 == records;
        if ((last && need.next != 0) ||
            (!last &&
             (need.next < sizeof(need) || (need.next & 3u) != 0)))
          return false;
        if (last) {
          if (record_end < address)
            return false;
          *span = record_end - address;
          return *span != 0;
        }
        uint64_t next = 0;
        if (!checked_add_u64(current, need.next, &next) || next < record_end)
          return false;
        current = next;
      }
      return false;
    };

    if (dp.verdef) {
      uint64_t span = 0, offset = 0;
      if (dp.verdefnum > std::numeric_limits<uint32_t>::max() ||
          !validate_verdef(dp.verdef, dp.verdefnum, &span) ||
          !r(dp.verdef, span, &offset))
        return data;
      shdr[20].sh_name = shstr_off(".gnu.version_d");
      shdr[20].sh_type = SHT_GNU_verdef;
      shdr[20].sh_flags = SHF_ALLOC;
      shdr[20].sh_addr = va(dp.verdef);
      shdr[20].sh_offset = offset;
      shdr[20].sh_size = span;
      shdr[20].sh_link = 2;
      shdr[20].sh_info = static_cast<uint32_t>(dp.verdefnum);
      shdr[20].sh_addralign = 4;
    }
    if (dp.verneed) {
      uint64_t span = 0, offset = 0;
      if (dp.verneednum > std::numeric_limits<uint32_t>::max() ||
          !validate_verneed(dp.verneed, dp.verneednum, &span) ||
          !r(dp.verneed, span, &offset))
        return data;
      shdr[21].sh_name = shstr_off(".gnu.version_r");
      shdr[21].sh_type = SHT_GNU_verneed;
      shdr[21].sh_flags = SHF_ALLOC;
      shdr[21].sh_addr = va(dp.verneed);
      shdr[21].sh_offset = offset;
      shdr[21].sh_size = span;
      shdr[21].sh_link = 2;
      shdr[21].sh_info = static_cast<uint32_t>(dp.verneednum);
      shdr[21].sh_addralign = 4;
    }

    if (dp.versym) {
      for (size_t i = 0; i < nDynSyms; ++i) {
        uint16_t version = 0;
        memcpy(&version,
               fixed.data() + versym_off + i * sizeof(version),
               sizeof(version));
        const uint16_t index = version & 0x7fff;
        if (index > 1 && known_version_indexes.count(index) == 0)
          return data;
      }
    }

    if (reloc && relocsz && relocent == sizeof(Rel) &&
        relocsz % sizeof(Rel) == 0) {
      uint64_t reloc_off = 0;
      if (r(reloc, relocsz, &reloc_off)) {
        shdr[5].sh_name = shstr_off(E::REL_DYN_NAME);
        shdr[5].sh_type = E::SHT_REL_TYPE;
        shdr[5].sh_flags = SHF_ALLOC;
        shdr[5].sh_addr = va(reloc);
        shdr[5].sh_offset = reloc_off;
        shdr[5].sh_size = relocsz;
        shdr[5].sh_link = 1;
        shdr[5].sh_addralign = W;
        shdr[5].sh_entsize = sizeof(Rel);
        const size_t rel_n = static_cast<size_t>(relocsz / sizeof(Rel));
        for (size_t i = 0; i < rel_n; i++) {
          const size_t entry_off = static_cast<size_t>(reloc_off) +
                                   i * sizeof(Rel);
          Rel rel{};
          memcpy(&rel, fixed.data() + entry_off, sizeof(rel));
          const uint64_t target_vaddr = rel.r_offset;
          const uint64_t type = E::R_TYPE(rel.r_info);

          if (type == static_cast<uint64_t>(E::R_RELATIVE)) {
            uint64_t target_off = 0;
            if (r(target_vaddr, W, &target_off)) {
              Addr value{}, normalized{};
              memcpy(&value, fixed.data() + target_off, sizeof(value));
              if (normalize_runtime_pointer(value, &normalized))
                memcpy(fixed.data() + target_off, &normalized,
                       sizeof(normalized));
            }
          }
        }
      }
    }

    size_t plt_entries = 0;
    uint64_t jmprel_off = 0;
    if (jmprel && pltrelsz && pltrelsz % sizeof(Rel) == 0 &&
        r(jmprel, pltrelsz, &jmprel_off)) {
      shdr[6].sh_name = shstr_off(E::REL_PLT_NAME);
      shdr[6].sh_type = E::SHT_REL_TYPE;
      shdr[6].sh_flags = SHF_ALLOC;
      shdr[6].sh_addr = va(jmprel);
      shdr[6].sh_offset = jmprel_off;
      shdr[6].sh_size = pltrelsz;
      shdr[6].sh_link = 1;
      shdr[6].sh_addralign = W;
      shdr[6].sh_entsize = sizeof(Rel);
      plt_entries = static_cast<size_t>(pltrelsz / sizeof(Rel));

      // DT_JMPREL describes the relocation table, not the executable PLT
      // stubs. Their real location cannot be derived from the end of JMPREL
      // (T3's table is at 0x650 while its PLT is at 0x4e20), so section 7 stays
      // SHT_NULL unless a future decoder can prove the actual instruction span.

      uint64_t got_count = 0, got_size = 0, got_off = 0;
      if (pltgot && checked_add_u64(3, plt_entries, &got_count) &&
          checked_mul_u64(got_count, W, &got_size) &&
          r(pltgot, got_size, &got_off)) {
        shdr[14].sh_name = shstr_off(".got.plt");
        shdr[14].sh_type = SHT_PROGBITS;
        shdr[14].sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr[14].sh_addr = va(pltgot);
        shdr[14].sh_offset = got_off;
        shdr[14].sh_size = got_size;
        shdr[14].sh_addralign = W;
        shdr[6].sh_flags |= SHF_INFO_LINK;
        shdr[6].sh_info = 14;
        for (uint64_t i = 0; i < got_count; i++) {
          const size_t entry_off = static_cast<size_t>(got_off + i * W);
          Addr value{}, normalized{};
          memcpy(&value, fixed.data() + entry_off, sizeof(value));
          if (normalize_runtime_pointer(value, &normalized))
            memcpy(fixed.data() + entry_off, &normalized,
                   sizeof(normalized));
        }
      }
    }

    // .init_array / .fini_array: same shape, different section identity.
    struct ArrayFixup {
      int index;
      const char *name;
      uint32_t type;
      uint64_t addr;
      uint64_t size;
    };
    const ArrayFixup arrays[] = {
        {10, ".init_array", SHT_INIT_ARRAY, init_arr, init_sz},
        {11, ".fini_array", SHT_FINI_ARRAY, fini_arr, fini_sz}};
    for (const auto &array : arrays) {
      uint64_t array_off = 0;
      if (!array.addr || !array.size || array.size % W != 0 ||
          !r(array.addr, array.size, &array_off))
        continue;
      Shdr &section = shdr[array.index];
      section.sh_name = shstr_off(array.name);
      section.sh_type = array.type;
      section.sh_flags = SHF_ALLOC | SHF_WRITE;
      section.sh_addr = va(array.addr);
      section.sh_offset = array_off;
      section.sh_size = array.size;
      section.sh_addralign = W;
      section.sh_entsize = W;
      const uint64_t count = array.size / W;
      for (uint64_t i = 0; i < count; i++) {
        const size_t entry_off = static_cast<size_t>(array_off + i * W);
        Addr value{};
        memcpy(&value, fixed.data() + entry_off, sizeof(value));
        Addr normalized{};
        if (normalize_runtime_pointer(value, &normalized))
          memcpy(fixed.data() + entry_off, &normalized,
                 sizeof(normalized));
      }
    }
  }

  const size_t shstrtab_sz = sizeof(g_shstrtab);
  shdr[17].sh_name = shstr_off(".shstrtab");
  shdr[17].sh_type = SHT_STRTAB;
  while (fixed.size() % W)
    fixed.push_back(0);
  shdr[17].sh_offset = fixed.size();
  shdr[17].sh_size = shstrtab_sz;
  shdr[17].sh_addralign = 1;
  fixed.insert(fixed.end(), g_shstrtab, g_shstrtab + shstrtab_sz);
  while (fixed.size() % W)
    fixed.push_back(0);

  uint64_t sh_off = fixed.size();
  for (int i = 0; i < 22; i++) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&shdr[i]);
    fixed.insert(fixed.end(), p, p + sizeof(Shdr));
  }
  ehdr.e_shoff = sh_off;
  ehdr.e_shnum = 22;
  ehdr.e_shstrndx = 17;
  ehdr.e_shentsize = sizeof(Shdr);
  memcpy(fixed.data(), &ehdr, sizeof(ehdr));
  return fixed;
}

std::vector<uint8_t> SoFixer::repair(const std::vector<uint8_t> &data,
                                     uint64_t base_addr,
                                     const std::vector<uint8_t> *disk) {
  if (data.size() < 5)
    return data;
  return repair_elf<64>(data, base_addr, disk);
}

#ifndef PT_GNU_EH_FRAME
#define PT_GNU_EH_FRAME 0x6474E550
#endif

// .eh_frame_hdr layout (LSB spec):
//   u8 version(1), u8 eh_frame_ptr_enc, u8 fde_count_enc, u8 table_enc
//   encoded eh_frame_ptr, encoded fde_count,
//   fde_count x { initial_location, fde_ptr }  -- both encoded with table_enc
// Android toolchains emit table_enc = DW_EH_PE_datarel|sdata4 (0x3B), i.e. two
// int32 values relative to the start of .eh_frame_hdr. Anything else is
// rejected rather than guessed at.
template <int Bits>
static std::vector<uint64_t>
eh_frame_functions_impl(const std::vector<uint8_t> &data) {
  using E = ElfTypes<Bits>;
  static_assert(Bits == 64, "only ELF64 program headers are supported");
  std::vector<uint64_t> out;

  Elf64ProgramHeaders program_headers;
  if (!parse_elf64_program_headers(data, &program_headers))
    return out;

  uint64_t hdr_off = 0, hdr_size = 0;
  for (const auto &ph : program_headers.entries) {
    if (ph.p_type == PT_GNU_EH_FRAME) {
      hdr_off = ph.p_offset;
      hdr_size = ph.p_filesz;
      break;
    }
  }
  if (hdr_off == 0 || hdr_off > data.size() ||
      12 > data.size() - static_cast<size_t>(hdr_off))
    return out;

  // initial_location is datarel: relative to the *virtual address* of
  // .eh_frame_hdr. Returning file offsets happens to work only when the
  // segment maps at p_vaddr == p_offset.
  AddrMap amap(data);
  uint64_t hdr_va = hdr_off;
  if (amap.valid() && !amap.to_vaddr(hdr_off, &hdr_va))
    return out;

  const uint8_t *p = data.data() + hdr_off;
  if (p[0] != 1)
    return out;
  const uint8_t eh_ptr_enc = p[1], count_enc = p[2], table_enc = p[3];
  if (table_enc != 0x3B) // datarel | sdata4
    return out;

  size_t cur = 4;
  auto skip_encoded = [&](uint8_t enc) -> bool {
    switch (enc & 0x0F) {
    case 0x02: cur += 2; return true;              // udata2
    case 0x03: case 0x0B: cur += 4; return true;   // udata4 / sdata4
    case 0x04: case 0x0C: cur += 8; return true;   // udata8 / sdata8
    case 0x00: cur += E::WORD_SIZE; return true;   // absptr
    default: return false;
    }
  };
  if (!skip_encoded(eh_ptr_enc))
    return out;
  if ((count_enc & 0x0F) != 0x03 && (count_enc & 0x0F) != 0x0B)
    return out;
  if (cur > data.size() - static_cast<size_t>(hdr_off) ||
      4 > data.size() - static_cast<size_t>(hdr_off) - cur)
    return out;
  uint32_t fde_count;
  memcpy(&fde_count, p + cur, 4);
  cur += 4;

  if (fde_count == 0 || fde_count > 1000000)
    return out;
  uint64_t table_bytes = uint64_t(fde_count) * 8;
  if (cur > data.size() - static_cast<size_t>(hdr_off) ||
      table_bytes > data.size() - static_cast<size_t>(hdr_off) - cur)
    return out;
  if (hdr_size && cur + table_bytes > hdr_size)
    return out;

  out.reserve(fde_count);
  for (uint32_t i = 0; i < fde_count; i++) {
    int32_t initial_loc;
    memcpy(&initial_loc, p + cur + uint64_t(i) * 8, 4);
    uint64_t va = hdr_va;
    if (initial_loc >= 0) {
      if (va > std::numeric_limits<uint64_t>::max() -
                   static_cast<uint32_t>(initial_loc))
        continue;
      va += static_cast<uint32_t>(initial_loc);
    } else {
      const uint64_t delta = static_cast<uint64_t>(-int64_t(initial_loc));
      if (va <= delta)
        continue;
      va -= delta;
    }
    uint64_t probe = 0;
    // Keep only addresses that actually land in a mapped segment.
    if (!amap.valid() || amap.to_offset(va, &probe))
      out.push_back(va);
  }
  std::sort(out.begin(), out.end());
  out.erase(std::unique(out.begin(), out.end()), out.end());
  return out;
}



std::vector<uint64_t>
ElfParser::get_eh_frame_functions(const std::vector<uint8_t> &data) {
  if (data.size() < 64 || !is_elf(data))
    return {};
  return eh_frame_functions_impl<64>(data);
}


namespace {

constexpr size_t kMaxMangledSymbolBytes = 4096;
constexpr size_t kMaxDemangledOutputBytes = 16U * 1024U;
constexpr size_t kMaxDemangleComponentBytes = 1024;
constexpr size_t kMaxDemangleComponents = 128;
constexpr size_t kMaxDemangleParameters = 256;
constexpr size_t kMaxDemangleNesting = 32;
constexpr size_t kMaxDemangleRecursion = 8;

static bool is_decimal_digit(char c) {
  return c >= '0' && c <= '9';
}

static bool is_ascii_lower(char c) { return c >= 'a' && c <= 'z'; }
static bool is_ascii_upper(char c) { return c >= 'A' && c <= 'Z'; }

// Parse a source-name length without ever forming cursor + length.  The local
// cursor is committed only on success, so every caller can fail closed without
// trying to recover from a half-consumed hostile decimal field.
static bool parse_demangle_length(const std::string &input, size_t *cursor,
                                  size_t *length) {
  if (!cursor || !length || *cursor >= input.size() ||
      !is_decimal_digit(input[*cursor]))
    return false;

  size_t p = *cursor;
  size_t value = 0;
  while (p < input.size() && is_decimal_digit(input[p])) {
    const size_t digit = static_cast<size_t>(input[p] - '0');
    if (value > (kMaxDemangleComponentBytes - digit) / 10)
      return false;
    value = value * 10 + digit;
    ++p;
  }
  if (value == 0 || value > input.size() - p)
    return false;
  *cursor = p;
  *length = value;
  return true;
}

static bool append_demangled(std::string *output, const std::string &piece) {
  if (!output || output->size() > kMaxDemangledOutputBytes ||
      piece.size() > kMaxDemangledOutputBytes - output->size())
    return false;
  output->append(piece);
  return true;
}

static std::string demangle_symbol_fallback_impl(const std::string &mangled,
                                                 size_t recursion,
                                                 bool *valid);

static std::string demangle_symbol_fallback(const std::string &mangled) {
  bool valid = false;
  std::string result = demangle_symbol_fallback_impl(mangled, 0, &valid);
  return valid ? result : mangled;
}

} // namespace

// Itanium demangling is handed to libc++abi, which implements the whole ABI
// including substitutions and nested names. The hand-rolled parser below is
// kept only as a fallback for inputs __cxa_demangle rejects; on its own it
// mangled real signatures into nonsense such as
// "PurchaseItem(N const &, S, _, ShopItem)".
std::string ElfParser::demangle_symbol(const std::string &mangled) {
  if (mangled.size() > kMaxMangledSymbolBytes)
    return mangled;
  if (mangled.size() > 2 && mangled[0] == '_' && mangled[1] == 'Z') {
    int status = 0;
    char *out = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
    if (status == 0 && out) {
      const size_t length = strnlen(out, kMaxDemangledOutputBytes + 1);
      std::string s;
      if (length <= kMaxDemangledOutputBytes)
        s.assign(out, length);
      free(out);
      out = nullptr;
      if (!s.empty())
        return s;
    }
    if (out)
      free(out);
  }
  return demangle_symbol_fallback(mangled);
}

namespace {

static std::string demangle_symbol_fallback_impl(const std::string &mangled,
                                                 size_t recursion,
                                                 bool *valid) {
  if (valid)
    *valid = false;
  if (mangled.empty() || mangled.size() > kMaxMangledSymbolBytes ||
      recursion > kMaxDemangleRecursion)
    return mangled;

  auto finish = [&](std::string output) {
    if (output.size() > kMaxDemangledOutputBytes)
      return mangled;
    if (valid)
      *valid = true;
    return output;
  };

  if (mangled.find("_GLOBAL__") == 0) {
    if (mangled.find("_GLOBAL__I_") == 0)
      return finish("[global constructor] " + mangled.substr(11));
    if (mangled.find("_GLOBAL__D_") == 0)
      return finish("[global destructor] " + mangled.substr(11));
    if (mangled.find("_GLOBAL__sub_I_") == 0)
      return finish("[static init] " + mangled.substr(15));
    return finish(mangled);
  }

  if (mangled.find("_ZGV") == 0) {
    bool inner_valid = false;
    std::string inner = demangle_symbol_fallback_impl(
        "_Z" + mangled.substr(4), recursion + 1, &inner_valid);
    return inner_valid ? finish("[guard variable] " + inner) : mangled;
  }

  if (mangled.find("_ZTV") == 0) {
    bool inner_valid = false;
    std::string inner = demangle_symbol_fallback_impl(
        "_Z" + mangled.substr(4), recursion + 1, &inner_valid);
    return inner_valid ? finish("[vtable] " + inner) : mangled;
  }

  if (mangled.find("_ZTI") == 0) {
    bool inner_valid = false;
    std::string inner = demangle_symbol_fallback_impl(
        "_Z" + mangled.substr(4), recursion + 1, &inner_valid);
    return inner_valid ? finish("[typeinfo] " + inner) : mangled;
  }

  if (mangled.find("_ZTS") == 0) {
    bool inner_valid = false;
    std::string inner = demangle_symbol_fallback_impl(
        "_Z" + mangled.substr(4), recursion + 1, &inner_valid);
    return inner_valid ? finish("[typeinfo name] " + inner) : mangled;
  }

  if (mangled.find("_ZTh") == 0 || mangled.find("_ZTv") == 0) {
    size_t pos = 4;
    while (pos < mangled.size() && (is_decimal_digit(mangled[pos]) ||
                                    mangled[pos] == 'n' || mangled[pos] == '_'))
      pos++;
    if (pos < mangled.size()) {
      bool inner_valid = false;
      std::string inner = demangle_symbol_fallback_impl(
          "_Z" + mangled.substr(pos), recursion + 1, &inner_valid);
      if (inner_valid)
        return finish("[virtual thunk] " + inner);
    }
    return mangled;
  }

  if (mangled.find("_ZTc") == 0)
    return mangled;

  if (mangled[0] != '_')
    return finish(mangled);
  if (mangled.size() < 3 || mangled[1] != 'Z')
    return finish(mangled);

  std::string result;
  size_t pos = 2;
  bool is_const_method = false;
  bool is_volatile_method = false;
  bool malformed = false;
  bool nested_name = false;
  bool nested_name_closed = true;
  std::vector<std::string> components;

  while (pos < mangled.size()) {
    if (mangled[pos] == 'K') {
      is_const_method = true;
      pos++;
    } else if (mangled[pos] == 'V') {
      is_volatile_method = true;
      pos++;
    } else {
      break;
    }
  }

  if (pos < mangled.size() && mangled[pos] == 'N') {
    nested_name = true;
    nested_name_closed = false;
    pos++;
    while (
        pos < mangled.size() &&
        (mangled[pos] == 'K' || mangled[pos] == 'V' || mangled[pos] == 'r')) {
      if (mangled[pos] == 'K')
        is_const_method = true;
      pos++;
    }
  }

  auto parse_operator = [](const std::string &m, size_t &p) -> std::string {
    if (p + 2 > m.size())
      return "";
    std::string op = m.substr(p, 2);
    p += 2;
    if (op == "nw")
      return "operator new";
    if (op == "na")
      return "operator new[]";
    if (op == "dl")
      return "operator delete";
    if (op == "da")
      return "operator delete[]";
    if (op == "ps")
      return "operator+";
    if (op == "ng")
      return "operator-";
    if (op == "ad")
      return "operator&";
    if (op == "de")
      return "operator*";
    if (op == "co")
      return "operator~";
    if (op == "pl")
      return "operator+";
    if (op == "mi")
      return "operator-";
    if (op == "ml")
      return "operator*";
    if (op == "dv")
      return "operator/";
    if (op == "rm")
      return "operator%";
    if (op == "an")
      return "operator&";
    if (op == "or")
      return "operator|";
    if (op == "eo")
      return "operator^";
    if (op == "aS")
      return "operator=";
    if (op == "pL")
      return "operator+=";
    if (op == "mI")
      return "operator-=";
    if (op == "mL")
      return "operator*=";
    if (op == "dV")
      return "operator/=";
    if (op == "rM")
      return "operator%=";
    if (op == "aN")
      return "operator&=";
    if (op == "oR")
      return "operator|=";
    if (op == "eO")
      return "operator^=";
    if (op == "ls")
      return "operator<<";
    if (op == "rs")
      return "operator>>";
    if (op == "lS")
      return "operator<<=";
    if (op == "rS")
      return "operator>>=";
    if (op == "eq")
      return "operator==";
    if (op == "ne")
      return "operator!=";
    if (op == "lt")
      return "operator<";
    if (op == "gt")
      return "operator>";
    if (op == "le")
      return "operator<=";
    if (op == "ge")
      return "operator>=";
    if (op == "ss")
      return "operator<=>";
    if (op == "nt")
      return "operator!";
    if (op == "aa")
      return "operator&&";
    if (op == "oo")
      return "operator||";
    if (op == "pp")
      return "operator++";
    if (op == "mm")
      return "operator--";
    if (op == "cm")
      return "operator,";
    if (op == "pm")
      return "operator->*";
    if (op == "pt")
      return "operator->";
    if (op == "cl")
      return "operator()";
    if (op == "ix")
      return "operator[]";
    if (op == "qu")
      return "operator?";
    if (op == "cv")
      return "operator (type)";
    if (op == "li")
      return "operator \"\"";
    p -= 2;
    return "";
  };

  std::function<std::string(void)> parse_name = [&]() -> std::string {
    if (pos >= mangled.size())
      return "";

    if (mangled[pos] == 'C' && pos + 1 < mangled.size() &&
        is_decimal_digit(mangled[pos + 1])) {
      pos += 2;
      if (!components.empty())
        return components.back();
      return "[constructor]";
    }

    if (mangled[pos] == 'D' && pos + 1 < mangled.size() &&
        is_decimal_digit(mangled[pos + 1])) {
      pos += 2;
      if (!components.empty())
        return "~" + components.back();
      return "[destructor]";
    }

    if (pos + 2 <= mangled.size()) {
      std::string op = parse_operator(mangled, pos);
      if (!op.empty())
        return op;
    }

    if (mangled[pos] == 'S') {
      pos++;
      if (pos < mangled.size()) {
        char c = mangled[pos];
        if (c == 't') {
          pos++;
          return "std";
        }
        if (c == 'a') {
          pos++;
          return "std::allocator";
        }
        if (c == 'b') {
          pos++;
          return "std::basic_string";
        }
        if (c == 's') {
          pos++;
          return "std::string";
        }
        if (c == 'i') {
          pos++;
          return "std::istream";
        }
        if (c == 'o') {
          pos++;
          return "std::ostream";
        }
        if (c == 'd') {
          pos++;
          return "std::iostream";
        }
        if (c == '_') {
          pos++;
          return "[subst]";
        }
        if (is_decimal_digit(c) || is_ascii_upper(c)) {
          while (pos < mangled.size() && mangled[pos] != '_')
            pos++;
          if (pos >= mangled.size()) {
            malformed = true;
            return "";
          }
          pos++;
          return "[subst]";
        }
      }
      malformed = true;
      return "";
    }

    if (!is_decimal_digit(mangled[pos]))
      return "";

    size_t len = 0;
    if (!parse_demangle_length(mangled, &pos, &len)) {
      malformed = true;
      return "";
    }

    std::string name = mangled.substr(pos, len);
    pos += len;

    if (pos < mangled.size() && mangled[pos] == 'I') {
      pos++;
      std::string targs;
      size_t depth = 1;
      size_t argument_count = 0;
      while (pos < mangled.size() && depth > 0) {
        const char c = mangled[pos];
        if (c == 'I') {
          if (depth >= kMaxDemangleNesting) {
            malformed = true;
            return "";
          }
          ++depth;
          ++pos;
          continue;
        }
        if (c == 'E') {
          --depth;
          ++pos;
          continue;
        }
        if (c == 'P' || c == 'R' || c == 'K') {
          ++pos;
          continue;
        }

        std::string argument;
        if (c == 'i')
          argument = "int";
        else if (c == 'f')
          argument = "float";
        else if (c == 'd')
          argument = "double";
        else if (c == 'b')
          argument = "bool";
        else if (c == 'c')
          argument = "char";
        else if (c == 'v')
          argument = "void";

        if (!argument.empty()) {
          ++pos;
        } else if (is_decimal_digit(c)) {
          size_t tlen = 0;
          if (!parse_demangle_length(mangled, &pos, &tlen)) {
            malformed = true;
            return "";
          }
          argument = mangled.substr(pos, tlen);
          pos += tlen;
        } else {
          malformed = true;
          return "";
        }

        if (++argument_count > kMaxDemangleParameters ||
            !append_demangled(&targs,
                              targs.empty() ? argument : ", " + argument)) {
          malformed = true;
          return "";
        }
      }
      if (depth != 0 ||
          !append_demangled(&name,
                            targs.empty() ? "<...>" : "<" + targs + ">") ||
          name.size() > kMaxDemangleComponentBytes) {
        malformed = true;
        return "";
      }
    }

    return name;
  };

  while (pos < mangled.size()) {
    if (mangled[pos] == 'E') {
      if (!nested_name) {
        malformed = true;
        break;
      }
      pos++;
      nested_name_closed = true;
      break;
    }
    if (!is_decimal_digit(mangled[pos]) && mangled[pos] != 'C' &&
        mangled[pos] != 'D' &&
        mangled[pos] != 'S' &&
        !(pos + 2 <= mangled.size() && is_ascii_lower(mangled[pos]) &&
          is_ascii_lower(mangled[pos + 1]))) {
      break;
    }
    const size_t before = pos;
    std::string comp = parse_name();
    if (comp.empty()) {
      if (pos != before)
        malformed = true;
      break;
    }
    if (pos <= before) {
      malformed = true;
      break;
    }
    if (comp != "[subst]") {
      if (components.size() >= kMaxDemangleComponents ||
          comp.size() > kMaxDemangleComponentBytes) {
        malformed = true;
        break;
      }
      components.push_back(comp);
    }
  }

  if (nested_name && !nested_name_closed)
    malformed = true;
  if (components.empty())
    malformed = true;
  for (size_t i = 0; i < components.size(); i++) {
    if (!append_demangled(&result,
                          (i > 0 ? "::" : "") + components[i])) {
      malformed = true;
      break;
    }
  }

  std::string params;
  auto parse_type = [&]() -> std::string {
    if (pos >= mangled.size())
      return "";
    std::string prefix;
    size_t qualifier_count = 0;
    while (pos < mangled.size()) {
      char c = mangled[pos];
      if (c == 'P') {
        prefix += "*";
        pos++;
      } else if (c == 'R') {
        prefix += "&";
        pos++;
      } else if (c == 'O') {
        prefix += "&&";
        pos++;
      } else if (c == 'K') {
        prefix = "const " + prefix;
        pos++;
      } else if (c == 'V') {
        prefix = "volatile " + prefix;
        pos++;
      } else if (c == 'r') {
        prefix = "restrict " + prefix;
        pos++;
      } else
        break;
      if (++qualifier_count > kMaxDemangleNesting ||
          prefix.size() > kMaxDemangleComponentBytes) {
        malformed = true;
        return "";
      }
    }
    if (pos >= mangled.size()) {
      malformed = true;
      return "";
    }
    char c = mangled[pos++];
    std::string base;
    switch (c) {
    case 'v':
      base = "void";
      break;
    case 'w':
      base = "wchar_t";
      break;
    case 'b':
      base = "bool";
      break;
    case 'c':
      base = "char";
      break;
    case 'a':
      base = "signed char";
      break;
    case 'h':
      base = "unsigned char";
      break;
    case 's':
      base = "short";
      break;
    case 't':
      base = "unsigned short";
      break;
    case 'i':
      base = "int";
      break;
    case 'j':
      base = "unsigned int";
      break;
    case 'l':
      base = "long";
      break;
    case 'm':
      base = "unsigned long";
      break;
    case 'x':
      base = "long long";
      break;
    case 'y':
      base = "unsigned long long";
      break;
    case 'n':
      base = "__int128";
      break;
    case 'o':
      base = "unsigned __int128";
      break;
    case 'f':
      base = "float";
      break;
    case 'd':
      base = "double";
      break;
    case 'e':
      base = "long double";
      break;
    case 'g':
      base = "__float128";
      break;
    case 'z':
      base = "...";
      break;
    case 'D':
      if (pos < mangled.size()) {
        char d = mangled[pos++];
        if (d == 'n')
          base = "decltype(nullptr)";
        else if (d == 'a')
          base = "auto";
        else if (d == 'c')
          base = "decltype(auto)";
        else if (d == 'i')
          base = "char32_t";
        else if (d == 's')
          base = "char16_t";
        else if (d == 'u')
          base = "char8_t";
        else
          malformed = true;
      } else
        malformed = true;
      break;
    case 'u': {
      size_t len = 0;
      if (!parse_demangle_length(mangled, &pos, &len)) {
        malformed = true;
        break;
      }
      base = mangled.substr(pos, len);
      pos += len;
      break;
    }
    default:
      if (is_decimal_digit(c)) {
        pos--;
        size_t len = 0;
        if (!parse_demangle_length(mangled, &pos, &len)) {
          malformed = true;
          break;
        }
        base = mangled.substr(pos, len);
        pos += len;
      } else {
        malformed = true;
      }
      break;
    }
    if (malformed || base.empty()) {
      malformed = true;
      return "";
    }
    std::string parsed = prefix.empty() ? base : base + " " + prefix;
    if (parsed.size() > kMaxDemangleComponentBytes) {
      malformed = true;
      return "";
    }
    return parsed;
  };

  size_t parameter_count = 0;
  while (pos < mangled.size() && mangled[pos] != 'E') {
    const size_t before = pos;
    std::string ptype = parse_type();
    if (ptype.empty() || pos <= before) {
      malformed = true;
      break;
    }
    if (++parameter_count > kMaxDemangleParameters) {
      malformed = true;
      break;
    }
    if (ptype == "void" && params.empty()) {
      if (pos != mangled.size())
        malformed = true;
      break;
    }
    if (!append_demangled(&params,
                          params.empty() ? ptype : ", " + ptype)) {
      malformed = true;
      break;
    }
  }

  if (pos != mangled.size())
    malformed = true;
  if (!malformed && !result.empty()) {
    if (!append_demangled(&result, "(" + params + ")") ||
        (is_const_method && !append_demangled(&result, " const")) ||
        (is_volatile_method && !append_demangled(&result, " volatile"))) {
      malformed = true;
    }
  }

  return malformed || result.empty() ? mangled : finish(result);
}

} // namespace

bool ElfParser::is_objc_method(const std::string &symbol) {
  if (symbol.size() < 4)
    return false;
  if (symbol[0] == '-' || symbol[0] == '+') {
    if (symbol[1] == '[')
      return true;
  }
  if (symbol.find("_OBJC_") == 0)
    return true;
  if (symbol.find("objc_") == 0)
    return true;
  return false;
}

std::pair<std::string, std::string>
ElfParser::parse_objc_method(const std::string &sym) {
  if (sym.size() < 5)
    return {"", ""};
  if ((sym[0] == '-' || sym[0] == '+') && sym[1] == '[') {
    size_t space = sym.find(' ', 2);
    if (space != std::string::npos) {
      std::string cls = sym.substr(2, space - 2);
      size_t end = sym.find(']', space);
      if (end != std::string::npos) {
        std::string method = sym.substr(space + 1, end - space - 1);
        return {cls, method};
      }
    }
  }
  return {"", ""};
}

// Does this decoded byte run look like a real string rather than a chance
// XOR hit? The old test -- "4+ printable characters" -- fires on essentially
// every offset in a .text section (190k hits on an unobfuscated libc.so), so
// the bar here is deliberately much higher.
static bool looks_like_text(const std::string &s) {
  if (s.size() < 12)
    return false;

  size_t letters = 0, digits = 0, punct = 0, spaces = 0;
  size_t max_run = 0, run = 1;
  for (size_t i = 0; i < s.size(); i++) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (isalpha(c))
      letters++;
    else if (isdigit(c))
      digits++;
    else if (c == ' ')
      spaces++;
    else
      punct++;
    if (i && s[i] == s[i - 1]) {
      if (++run > max_run)
        max_run = run;
    } else {
      run = 1;
    }
  }

  // Mostly-letters, no long repeats, and not a wall of punctuation.
  if (letters * 2 < s.size())
    return false;
  if (max_run > 4)
    return false;
  if (punct + spaces > s.size() / 2)
    return false;
  (void)digits;

  // Require a pronounceable core: at least one vowel and one 4+ letter word.
  size_t word = 0, best_word = 0;
  bool vowel = false;
  for (char ch : s) {
    unsigned char c = static_cast<unsigned char>(ch);
    if (isalpha(c)) {
      word++;
      char l = static_cast<char>(tolower(c));
      if (l == 'a' || l == 'e' || l == 'i' || l == 'o' || l == 'u')
        vowel = true;
    } else {
      if (word > best_word)
        best_word = word;
      word = 0;
    }
  }
  if (word > best_word)
    best_word = word;
  return vowel && best_word >= 4;
}

std::vector<std::string>
ElfParser::find_encrypted_strings(const std::vector<uint8_t> &data,
                                  size_t max_input_bytes,
                                  size_t max_results, uint64_t deadline_ms,
                                  bool *truncated) {
  std::vector<std::string> results;
  bool was_truncated = data.size() > max_input_bytes;
  const size_t input_size = std::min(data.size(), max_input_bytes);
  if (max_results == 0) {
    if (truncated)
      *truncated = input_size >= 32 || was_truncated;
    return results;
  }
  if (input_size < 32) {
    if (truncated)
      *truncated = was_truncated;
    return results;
  }

  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(
                            std::min<uint64_t>(deadline_ms, 600000));

  std::set<std::string> seen;
  const size_t MIN_LEN = 12;

  for (size_t i = 0; i + MIN_LEN < input_size;) {
    if (std::chrono::steady_clock::now() >= deadline) {
      was_truncated = true;
      break;
    }
    // Skip windows that are already plaintext.
    size_t printable = 0;
    for (size_t j = 0; j < MIN_LEN; j++) {
      uint8_t b = data[i + j];
      if (b >= 0x20 && b <= 0x7E)
        printable++;
    }
    if (printable == MIN_LEN) {
      i++;
      continue;
    }

    size_t advance = 1;
    // A packed string is a run that decodes to printable text and is followed
    // by a NUL under the same key -- the terminator is the strongest signal
    // that this is a real string and not a coincidence.
    for (uint32_t key = 1; key < 256; key++) {
      // Cheap rejection before building any string: the first MIN_LEN bytes
      // must all decode to printable under this key.
      bool ok = true;
      for (size_t j = 0; j < MIN_LEN && ok; j++) {
        uint8_t c = data[i + j] ^ static_cast<uint8_t>(key);
        ok = (c >= 0x20 && c <= 0x7E);
      }
      if (!ok)
        continue;

      std::string decoded;
      size_t j = 0;
      bool terminated = false;
      for (; i + j < input_size && j < 256; j++) {
        uint8_t c = data[i + j] ^ static_cast<uint8_t>(key);
        if (c == 0) {
          terminated = true;
          break;
        }
        if (c < 0x20 || c > 0x7E)
          break;
        decoded.push_back(static_cast<char>(c));
      }
      if (!terminated || !looks_like_text(decoded))
        continue;
      if (seen.insert(decoded).second) {
        results.push_back("XOR(" + std::to_string(key) + "): " + decoded);
        if (results.size() >= max_results) {
          was_truncated = true;
          i = input_size;
          break;
        }
      }
      advance = j + 1;
      break;
    }
    i += advance;
  }
  if (truncated)
    *truncated = was_truncated;
  return results;
}

static uint64_t find_dynamic_entry(const std::vector<uint8_t> &data,
                                   int64_t tag) {
  Elf64ProgramHeaders program_headers;
  if (!parse_elf64_program_headers(data, &program_headers))
    return 0;
  for (const auto &ph : program_headers.entries) {
    if (ph.p_type != PT_DYNAMIC)
      continue;
    if (ph.p_offset >= data.size())
      continue;
    size_t dyn_bytes =
        std::min<uint64_t>(ph.p_filesz, data.size() - ph.p_offset);
    size_t dyn_count = dyn_bytes / sizeof(Elf64_Dyn);
    for (size_t j = 0; j < dyn_count; j++) {
      Elf64_Dyn dyn{};
      memcpy(&dyn, data.data() + ph.p_offset + j * sizeof(dyn), sizeof(dyn));
      if (dyn.d_tag == DT_NULL)
        break;
      if (dyn.d_tag == tag)
        return dyn.d_un.d_val;
    }
  }
  return 0;
}

bool ElfParser::has_relro(const std::vector<uint8_t> &data) {
  Elf64ProgramHeaders program_headers;
  if (!parse_elf64_program_headers(data, &program_headers))
    return false;
  for (const auto &ph : program_headers.entries) {
    if (ph.p_type == PT_GNU_RELRO)
      return true;
  }
  return false;
}

bool ElfParser::has_full_relro(const std::vector<uint8_t> &data) {
  if (!has_relro(data))
    return false;
  uint64_t flags = find_dynamic_entry(data, DT_FLAGS);
  return (flags & 0x8) != 0;
}


std::vector<uint64_t>
ElfParser::get_init_array(const std::vector<uint8_t> &data) {
  std::vector<uint64_t> funcs;

  uint64_t init_arr = find_dynamic_entry(data, DT_INIT_ARRAY);
  uint64_t init_sz = find_dynamic_entry(data, DT_INIT_ARRAYSZ);

  if (init_arr == 0 || init_sz == 0)
    return funcs;

  size_t init_off = 0;
  if ((init_sz % sizeof(uint64_t)) != 0 ||
      !vaddr_to_offset(data, init_arr, init_off) ||
      !byte_range_fits(data.size(), init_off, init_sz))
    return funcs;

  const size_t count = static_cast<size_t>(init_sz / sizeof(uint64_t));
  for (size_t i = 0; i < count; i++) {
    uint64_t value = 0;
    memcpy(&value, data.data() + init_off + i * sizeof(value),
           sizeof(value));
    if (value != 0)
      funcs.push_back(value);
  }
  return funcs;
}

std::vector<uint64_t>
ElfParser::get_fini_array(const std::vector<uint8_t> &data) {
  std::vector<uint64_t> funcs;

  uint64_t fini_arr = find_dynamic_entry(data, DT_FINI_ARRAY);
  uint64_t fini_sz = find_dynamic_entry(data, DT_FINI_ARRAYSZ);

  if (fini_arr == 0 || fini_sz == 0)
    return funcs;

  size_t fini_off = 0;
  if ((fini_sz % sizeof(uint64_t)) != 0 ||
      !vaddr_to_offset(data, fini_arr, fini_off) ||
      !byte_range_fits(data.size(), fini_off, fini_sz))
    return funcs;

  const size_t count = static_cast<size_t>(fini_sz / sizeof(uint64_t));
  for (size_t i = 0; i < count; i++) {
    uint64_t value = 0;
    memcpy(&value, data.data() + fini_off + i * sizeof(value),
           sizeof(value));
    if (value != 0)
      funcs.push_back(value);
  }
  return funcs;
}


static bool parse_pattern(const std::string &pattern,
                          std::vector<uint8_t> &bytes,
                          std::vector<bool> &mask) {
  bytes.clear();
  mask.clear();
  if (pattern.empty())
    return false;

  // A single ordinary token is an ASCII search. Hex byte patterns remain
  // space-separated ("de ad ?? ef") or may be made explicit with "hex:".
  // This keeps CLI strings such as API_KEY or T1_MARKER_ALPHA from being
  // rejected as malformed hexadecimal.
  bool explicit_hex = pattern.rfind("hex:", 0) == 0;
  bool explicit_text = pattern.rfind("text:", 0) == 0;
  if (explicit_text ||
      (!explicit_hex && pattern.find_first_of(" \t\r\n") == std::string::npos)) {
    size_t start = explicit_text ? 5 : 0;
    if (start >= pattern.size())
      return false;
    bytes.assign(pattern.begin() + static_cast<ptrdiff_t>(start),
                 pattern.end());
    mask.assign(bytes.size(), true);
    return true;
  }

  std::string hex_pattern = explicit_hex ? pattern.substr(4) : pattern;
  std::istringstream iss(hex_pattern);
  std::string token;
  while (iss >> token) {
    if (token == "?" || token == "??" || token == "**") {
      bytes.push_back(0);
      mask.push_back(false);
    } else {
      try {
        unsigned long v = std::stoul(token, nullptr, 16);
        if (v > 0xFF)
          return false;
        uint8_t b = static_cast<uint8_t>(v);
        bytes.push_back(b);
        mask.push_back(true);
      } catch (...) {
        return false;
      }
    }
  }
  return !bytes.empty();
}

std::vector<PatternMatch>
ElfParser::pattern_scan(const std::vector<uint8_t> &data,
                        const std::string &pattern) {
  std::vector<PatternMatch> results;
  std::vector<uint8_t> pat_bytes;
  std::vector<bool> pat_mask;

  if (!parse_pattern(pattern, pat_bytes, pat_mask))
    return results;

  size_t pat_len = pat_bytes.size();
  if (pat_len == 0 || data.size() < pat_len)
    return results;

  for (size_t i = 0; i <= data.size() - pat_len; i++) {
    bool match = true;
    for (size_t j = 0; j < pat_len && match; j++) {
      if (pat_mask[j] && data[i + j] != pat_bytes[j])
        match = false;
    }
    if (match)
      results.push_back(PatternMatch{i});
  }
  return results;
}






std::vector<uint64_t>
ElfParser::get_vtable_functions(const std::vector<uint8_t> &data,
                                uint64_t vtable_offset, uint64_t base_addr,
                                size_t max_bytes) {
  std::vector<uint64_t> funcs;
  if (vtable_offset >= data.size())
    return funcs;
  size_t table_off = static_cast<size_t>(vtable_offset);
  constexpr size_t ptr_size = 8;

  if (max_bytes == 0) {
    Elf64ProgramHeaders program_headers;
    if (!parse_elf64_program_headers(data, &program_headers))
      return funcs;
    for (const auto &ph : program_headers.entries) {
      if (ph.p_type != PT_LOAD)
        continue;
      uint64_t seg_off = ph.p_offset;
      uint64_t seg_end = ph.p_offset + ph.p_filesz;
      if (table_off >= seg_off && table_off < seg_end) {
        max_bytes = static_cast<size_t>(seg_end - table_off);
        break;
      }
    }
  }

  if (max_bytes == 0)
    max_bytes = data.size() - table_off;

  size_t max_off = table_off + max_bytes;
  if (max_off < table_off || max_off > data.size())
    max_off = data.size();

  for (size_t off = table_off; off + ptr_size <= max_off;
       off += ptr_size) {
    uint64_t raw_ptr = read_le64(data.data() + off);

    if (raw_ptr == 0)
      break;

    uint64_t absolute = raw_ptr;
    if (base_addr != 0) {
      if (raw_ptr < base_addr && raw_ptr < data.size()) {
        absolute = base_addr + raw_ptr;
      }
    }

    if (base_addr == 0 && absolute < 0x1000)
      break;

    funcs.push_back(absolute);
  }

  return funcs;
}

size_t ElfParser::write_rtti(std::ostream &out,
                             const std::vector<uint8_t> &data,
                             uint64_t base_addr,
                             const std::vector<ElfSymbol> &vtables) {
  if (data.size() < 64 || vtables.empty()) {
    out << "\n=== VTABLE/RTTI (0) ===\n";
    return 0;
  }

  std::vector<const ElfSymbol *> sorted;
  sorted.reserve(vtables.size());
  for (const auto &v : vtables)
    sorted.push_back(&v);
  std::sort(sorted.begin(), sorted.end(),
            [](const ElfSymbol *a, const ElfSymbol *b) {
              return a->offset < b->offset;
            });
  constexpr size_t ptr_size = 8;

  size_t valid = 0;
  for (const auto *s : sorted) {
    size_t vtable_off = 0;
    if (vaddr_to_offset(data, s->offset, vtable_off))
      valid++;
  }

  out << "\n=== VTABLE/RTTI (" << valid << ") ===\n";
  if (valid == 0)
    return 0;

  for (size_t i = 0; i < sorted.size(); i++) {
    const auto *s = sorted[i];
    size_t vtable_off = 0;
    if (!vaddr_to_offset(data, s->offset, vtable_off))
      continue;

    uint64_t vtable_addr = base_addr ? base_addr + s->offset : s->offset;
    // Itanium layout: a _ZTV symbol addresses the vtable object, which starts
    // with offset-to-top and then the typeinfo pointer. Reading two slots
    // *before* the symbol (as this used to) lands in whatever precedes the
    // vtable -- usually code, which is why typeinfo came out as instruction
    // bytes like 0xd61f0220 ("br x17").
    uint64_t typeinfo_addr = 0;
    auto read_ptr_at = [&](uint64_t off, uint64_t *out) -> bool {
      if (off + ptr_size > data.size())
        return false;
      memcpy(out, data.data() + off, ptr_size);
      return true;
    };
    // In a memory dump the stored pointer is an absolute runtime address, so
    // strip the load base before checking that it lands inside the image.
    auto resolves = [&](uint64_t v) {
      if (v == 0)
        return false;
      uint64_t rel = (base_addr && v >= base_addr) ? v - base_addr : v;
      size_t p = 0;
      return vaddr_to_offset(data, rel, p);
    };
    uint64_t cand = 0;
    if (read_ptr_at(vtable_off + ptr_size, &cand) && resolves(cand)) {
      typeinfo_addr = cand;
    } else if (vtable_off >= ptr_size * 2 &&
               read_ptr_at(vtable_off - ptr_size * 2, &cand) &&
               resolves(cand)) {
      // Fallback for images where the recorded address is the vtable pointer
      // an object holds rather than the start of the vtable object.
      typeinfo_addr = cand;
    }

    size_t vtable_bytes = static_cast<size_t>(s->size);
    if (vtable_bytes == 0 && i + 1 < sorted.size()) {
      uint64_t next_off = sorted[i + 1]->offset;
      if (next_off > s->offset)
        vtable_bytes = static_cast<size_t>(next_off - s->offset);
    }

    auto virtuals =
        get_vtable_functions(data, vtable_off, base_addr, vtable_bytes);

    out << "VTABLE 0x" << std::hex << std::setw(8) << std::setfill('0')
        << vtable_addr << std::dec << " " << demangle_symbol(s->name) << "\n";
    if (typeinfo_addr)
      out << "  typeinfo: 0x" << std::hex << typeinfo_addr << std::dec << "\n";
    else
      out << "  typeinfo: <unresolved>\n";
    if (!virtuals.empty()) {
      out << "  virtuals (" << std::dec << virtuals.size() << "):";
      for (auto fn : virtuals) {
        out << " 0x" << std::hex << fn;
      }
      out << std::dec << "\n";
    }
  }

  return valid;
}


std::vector<DecryptResult>
ElfParser::try_decrypt(const std::vector<uint8_t> &data, uint64_t offset,
                       size_t length) {
  std::vector<DecryptResult> results;

  if (offset > data.size() || length > data.size() - offset)
    return results;

  std::vector<uint8_t> encrypted(data.begin() + offset,
                                 data.begin() + offset + length);

  auto calc_printable_ratio = [](const std::vector<uint8_t> &buf) -> double {
    if (buf.empty())
      return 0.0;
    int printable = 0;
    for (uint8_t b : buf) {
      if ((b >= 0x20 && b <= 0x7E) || b == 0 || b == '\n' || b == '\r' ||
          b == '\t')
        printable++;
    }
    return (double)printable / buf.size();
  };

  // Markers must be long enough not to fire on random bytes. "api" and "key"
  // (the old list) occur by chance roughly once per 16MB of noise per key, i.e.
  // constantly across 254 XOR candidates.
  auto has_known_patterns = [](const std::vector<uint8_t> &buf) -> bool {
    static const char *kMarkers[] = {
        "http://", "https://", "android/", "java/lang", "com/google",
        "/data/",  "/system/", ".json",    ".xml",      "Content-Type",
        "Authorization", "Bearer ", "-----BEGIN", "sqlite", "application/"};
    std::string s(buf.begin(), buf.end());
    for (const char *m : kMarkers)
      if (s.find(m) != std::string::npos)
        return true;
    return false;
  };

  // Shared gate for single-key candidates: printable is not enough, the result
  // has to read like text.
  auto plausible = [&](const std::vector<uint8_t> &buf) -> bool {
    std::string s;
    for (uint8_t b : buf) {
      if (b == 0)
        break;
      s.push_back(static_cast<char>(b));
    }
    return looks_like_text(s) || has_known_patterns(buf);
  };

  auto is_base64_char = [](uint8_t c) -> bool {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
  };

  int base64_count = 0;
  for (uint8_t b : encrypted) {
    if (is_base64_char(b))
      base64_count++;
  }

  if (base64_count > (int)(length * 0.9) && length >= 4) {

    static const uint8_t b64_table[256] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54, 55, 56, 57,
        58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,
        7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64};

    std::vector<uint8_t> decoded;
    decoded.reserve(length * 3 / 4);
    uint32_t accum = 0;
    int bits = 0;
    for (uint8_t c : encrypted) {
      if (c == '=')
        break;
      uint8_t v = b64_table[c];
      if (v == 64)
        continue;
      accum = (accum << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        decoded.push_back((accum >> bits) & 0xFF);
      }
    }

    if (!decoded.empty() && calc_printable_ratio(decoded) > 0.7 &&
        plausible(decoded)) {
      DecryptResult r;
      r.offset = offset;
      r.decrypted = decoded;
      r.method = "BASE64";
      r.key_size = 0;
      results.push_back(r);
    }
  }

  for (uint8_t key = 1; key < 255; key++) {
    std::vector<uint8_t> decrypted = encrypted;
    for (auto &b : decrypted)
      b ^= key;

    double ratio = calc_printable_ratio(decrypted);
    bool has_patterns = has_known_patterns(decrypted);

    if ((ratio > 0.8 && plausible(decrypted)) ||
        (ratio > 0.6 && has_patterns)) {
      DecryptResult r;
      r.offset = offset;
      r.decrypted = decrypted;
      r.method = "XOR-BYTE";
      r.key_or_info[0] = key;
      r.key_size = 1;
      results.push_back(r);
      break;
    }
  }

  if (length >= 16 && results.empty()) {

    std::map<int, int> distance_counts;
    for (size_t win = 3; win <= 5; win++) {
      for (size_t i = 0; i + win < length; i++) {
        for (size_t j = i + win; j + win <= length; j++) {
          if (memcmp(encrypted.data() + i, encrypted.data() + j, win) == 0) {
            int dist = j - i;
            for (int d = 2; d <= 16; d++) {
              if (dist % d == 0)
                distance_counts[d]++;
            }
          }
        }
      }
    }

    std::vector<int> key_lengths = {4, 8, 16, 2, 3, 6};
    for (auto &[len, count] : distance_counts) {
      if (count > 2 && len >= 2 && len <= 16) {
        bool found = false;
        for (int kl : key_lengths)
          if (kl == len)
            found = true;
        if (!found)
          key_lengths.push_back(len);
      }
    }

    for (int key_len : key_lengths) {
      if (key_len > (int)length / 2)
        continue;

      std::vector<uint8_t> key(key_len, 0);
      bool key_found = true;

      for (int k = 0; k < key_len; k++) {
        std::vector<int> freq(256, 0);
        for (size_t i = k; i < length; i += key_len) {
          freq[encrypted[i]]++;
        }

        int max_idx = 0;
        for (int i = 0; i < 256; i++) {
          if (freq[i] > freq[max_idx])
            max_idx = i;
        }

        uint8_t best_key = 0;
        double best_ratio = 0;
        for (uint8_t common : {' ', 'e', 'a', 't', 'o', '\0'}) {
          uint8_t try_key = max_idx ^ common;
          std::vector<uint8_t> test;
          for (size_t i = k; i < length; i += key_len) {
            test.push_back(encrypted[i] ^ try_key);
          }
          double ratio = calc_printable_ratio(test);
          if (ratio > best_ratio) {
            best_ratio = ratio;
            best_key = try_key;
          }
        }

        if (best_ratio < 0.5) {
          key_found = false;
          break;
        }
        key[k] = best_key;
      }

      if (key_found) {
        std::vector<uint8_t> decrypted = encrypted;
        for (size_t i = 0; i < length; i++) {
          decrypted[i] ^= key[i % key_len];
        }

        double ratio = calc_printable_ratio(decrypted);
        if ((ratio > 0.7 && plausible(decrypted)) ||
            (ratio > 0.5 && has_known_patterns(decrypted))) {
          DecryptResult r;
          r.offset = offset;
          r.decrypted = decrypted;
          r.method = "XOR-MULTI-" + std::to_string(key_len);
          memcpy(r.key_or_info, key.data(), std::min(key.size(), (size_t)32));
          r.key_size = key_len;
          results.push_back(r);
          break;
        }
      }
    }
  }

  if (length >= 4 && results.empty()) {
    for (uint32_t key = 0x01010101; key < 0x10101010; key += 0x01010101) {
      std::vector<uint8_t> decrypted = encrypted;
      for (size_t i = 0; i + 4 <= decrypted.size(); i += 4) {
        write_le32(decrypted.data() + i, read_le32(decrypted.data() + i) ^ key);
      }

      double ratio = calc_printable_ratio(decrypted);
      if ((ratio > 0.8 && plausible(decrypted)) ||
          (ratio > 0.6 && has_known_patterns(decrypted))) {
        DecryptResult r;
        r.offset = offset;
        r.decrypted = decrypted;
        r.method = "XOR-DWORD";
        write_le32(r.key_or_info, key);
        r.key_size = 4;
        results.push_back(r);
        break;
      }
    }
  }

  if (results.empty()) {
    for (int delta = -128; delta <= 127; delta++) {
      if (delta == 0)
        continue;
      std::vector<uint8_t> decrypted = encrypted;
      for (auto &b : decrypted)
        b = (uint8_t)(b + delta);

      double ratio = calc_printable_ratio(decrypted);
      if ((ratio > 0.8 && plausible(decrypted)) ||
          (ratio > 0.6 && has_known_patterns(decrypted))) {
        DecryptResult r;
        r.offset = offset;
        r.decrypted = decrypted;
        r.method = (delta > 0) ? "ADD" : "SUB";
        r.key_or_info[0] = (uint8_t)std::abs(delta);
        r.key_size = 1;
        results.push_back(r);
        break;
      }
    }
  }

  return results;
}


std::vector<DecryptResult>
ElfParser::auto_decrypt_strings(const std::vector<uint8_t> &data) {
  return auto_decrypt_strings(data, AutoDecryptLimits{}, nullptr);
}

std::vector<DecryptResult>
ElfParser::auto_decrypt_strings(const std::vector<uint8_t> &data,
                                const AutoDecryptLimits &limits,
                                AutoDecryptStatus *status) {
  std::vector<DecryptResult> results;
  AutoDecryptStatus scan;
  const size_t input_limit = std::min(data.size(), limits.max_input_bytes);
  scan.input_bytes = input_limit;
  scan.input_truncated = input_limit < data.size();

  const size_t WINDOW = 64;
  if (input_limit < WINDOW) {
    if (status)
      *status = scan;
    return results;
  }

  using MonotonicClock = std::chrono::steady_clock;
  // Clamp hostile duration values before converting them to the clock's signed
  // representation.  Ten years is effectively unlimited for a synchronous
  // analysis call while still making the addition well-defined.
  constexpr uint64_t kMaxDeadlineMs =
      uint64_t{10} * 365U * 24U * 60U * 60U * 1000U;
  const uint64_t deadline_ms =
      std::min<uint64_t>(limits.deadline_ms, kMaxDeadlineMs);
  const auto deadline = MonotonicClock::now() +
                        std::chrono::milliseconds(deadline_ms);

  auto should_stop = [&]() {
    if (limits.cancel && limits.cancel->load(std::memory_order_relaxed)) {
      scan.cancelled = true;
      return true;
    }
    if (MonotonicClock::now() >= deadline) {
      scan.deadline_reached = true;
      return true;
    }
    return false;
  };

  // try_decrypt is expensive (254 XOR passes plus multi-byte key search over a
  // 64-byte window). Running it at every offset costs ~45s on a 5MB library and
  // buries the output in noise, so probe only where a high-entropy, non-ASCII
  // block actually starts, and step over each block that is consumed.
  for (size_t i = 0; i <= input_limit - WINDOW;) {
    if (should_stop())
      break;
    if (scan.probes >= limits.max_probes) {
      scan.probe_limit_reached = true;
      break;
    }
    ++scan.probes;

    size_t printable = 0, zeros = 0;
    for (size_t j = 0; j < 32; j++) {
      uint8_t b = data[i + j];
      if (b >= 0x20 && b <= 0x7E)
        printable++;
      if (b == 0)
        zeros++;
    }
    // Plaintext, padding or sparse data: nothing to decrypt here.
    if (printable > 24 || zeros > 8) {
      i += 16;
      continue;
    }
    if (calculate_entropy(data.data() + i, WINDOW) < 4.5) {
      i += 16;
      continue;
    }

    if (scan.candidates >= limits.max_candidates) {
      scan.candidate_limit_reached = true;
      break;
    }
    ++scan.candidates;
    auto decrypted = try_decrypt(data, i, WINDOW);
    if (!decrypted.empty()) {
      const size_t remaining = limits.max_results -
                               std::min(limits.max_results, results.size());
      const size_t retain = std::min(remaining, decrypted.size());
      results.insert(results.end(), decrypted.begin(),
                     decrypted.begin() + static_cast<ptrdiff_t>(retain));
      if (retain < decrypted.size() || results.size() >= limits.max_results) {
        scan.result_limit_reached = true;
        break;
      }
      i += WINDOW;
    } else {
      i += 16;
    }
  }
  scan.retained_results = results.size();
  if (status)
    *status = scan;
  return results;
}



namespace {

static_assert(std::atomic<sig_atomic_t>::is_always_lock_free,
              "trace-init signal atomics must be lock-free");
std::atomic<sig_atomic_t> g_trace_init_running{0};
std::atomic<sig_atomic_t> g_trace_init_signal{0};
thread_local std::string g_trace_init_status = "not started";

void trace_init_signal_handler(int signal) {
  g_trace_init_signal.store(signal, std::memory_order_relaxed);
  g_trace_init_running.store(0, std::memory_order_relaxed);
}

// SIGINT/SIGTERM must not reach main.cpp's fatal handler while a temporary BRK
// exists. The dispositions are process-wide (so signals delivered to another
// worker are cooperative too); the mask closes the setup window on this
// thread. Callers restore every instruction before this guard is destroyed.
class TraceInitSignalWindow {
public:
  bool prepare() {
    sigemptyset(&blocked_);
    sigaddset(&blocked_, SIGINT);
    sigaddset(&blocked_, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blocked_, &previous_mask_) != 0)
      return false;
    mask_blocked_ = true;
    g_trace_init_running.store(1, std::memory_order_relaxed);
    g_trace_init_signal.store(0, std::memory_order_relaxed);

    struct sigaction sa = {};
    sa.sa_handler = trace_init_signal_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, &previous_int_) != 0) {
      reset();
      return false;
    }
    have_int_ = true;
    if (sigaction(SIGTERM, &sa, &previous_term_) != 0) {
      reset();
      return false;
    }
    have_term_ = true;
    prepared_ = true;
    return true;
  }

  bool unblock() {
    if (!prepared_)
      return false;
    if (!mask_blocked_)
      return true;
    if (sigprocmask(SIG_SETMASK, &previous_mask_, nullptr) != 0)
      return false;
    mask_blocked_ = false;
    return true;
  }

  bool interrupted() const {
    return g_trace_init_running.load(std::memory_order_relaxed) == 0;
  }

  ~TraceInitSignalWindow() {
    // Close the teardown race too: while dispositions are being restored, an
    // INT/TERM handled by the cooperative handler must either be observed here
    // or remain pending for the original handler after the mask is restored.
    // Reading once before sigaction() was insufficient; a signal in that
    // interval could be recorded after the read and then silently cleared.
    sigset_t teardown_previous{};
    bool teardown_blocked =
        sigprocmask(SIG_BLOCK, &blocked_, &teardown_previous) == 0;
    int interrupted_signal =
        g_trace_init_signal.load(std::memory_order_relaxed);
    g_trace_init_running.store(0, std::memory_order_relaxed);
    if (have_term_) {
      sigaction(SIGTERM, &previous_term_, nullptr);
      have_term_ = false;
    }
    if (have_int_) {
      sigaction(SIGINT, &previous_int_, nullptr);
      have_int_ = false;
    }
    int late_signal = g_trace_init_signal.load(std::memory_order_relaxed);
    if (late_signal != 0)
      interrupted_signal = late_signal;
    g_trace_init_signal.store(0, std::memory_order_relaxed);
    prepared_ = false;

    if (teardown_blocked) {
      const sigset_t &final_mask =
          mask_blocked_ ? previous_mask_ : teardown_previous;
      sigprocmask(SIG_SETMASK, &final_mask, nullptr);
      mask_blocked_ = false;
    } else if (mask_blocked_) {
      sigprocmask(SIG_SETMASK, &previous_mask_, nullptr);
      mask_blocked_ = false;
    }
    // The cooperative handler only delays cancellation until every temporary
    // instruction is restored. Re-raise under the original disposition so
    // Ctrl-C/TERM still terminates the command as requested.
    if (interrupted_signal != 0)
      kill(getpid(), interrupted_signal);
  }

private:
  void reset() {
    g_trace_init_running.store(0, std::memory_order_relaxed);
    g_trace_init_signal.store(0, std::memory_order_relaxed);
    if (have_term_) {
      sigaction(SIGTERM, &previous_term_, nullptr);
      have_term_ = false;
    }
    if (have_int_) {
      sigaction(SIGINT, &previous_int_, nullptr);
      have_int_ = false;
    }
    if (mask_blocked_) {
      sigprocmask(SIG_SETMASK, &previous_mask_, nullptr);
      mask_blocked_ = false;
    }
    prepared_ = false;
  }

  sigset_t blocked_{};
  sigset_t previous_mask_{};
  struct sigaction previous_int_ {};
  struct sigaction previous_term_ {};
  bool mask_blocked_ = false;
  bool have_int_ = false;
  bool have_term_ = false;
  bool prepared_ = false;
};

} // namespace

std::string RuntimeAnalyzer::last_trace_status() {
  return g_trace_init_status;
}

size_t RuntimeAnalyzer::trace_init_array(
    int pid, uint64_t base, const std::string &expected_name,
    const std::vector<uint8_t> &expected_image,
    const std::vector<uint64_t> &init_funcs) {
  g_trace_init_status = "starting";
  TraceInitSignalWindow signal_window;
  if (!signal_window.prepare()) {
    g_trace_init_status = "cooperative signal setup failed";
    return 0;
  }

  bool attached = ProcessTracer::attach(pid);
  if (!attached) {
    g_trace_init_status = "all-thread attach failed";
    return 0;
  }

  auto detach_safely = [&]() {
    if (!attached)
      return true;
    bool ok = ProcessTracer::detach(pid);
    if (!ok)
      ok = ProcessTracer::recover_attached(pid);
    if (!ok) {
      // Never release an ambiguously attached or potentially patched tracee.
      kill(pid, SIGKILL);
      ProcessTracer::cleanup_all_attached();
      ProcessTracer::reset_attach_bookkeeping();
    }
    attached = false;
    return ok;
  };

  auto normalize_name = [](std::string value) {
    size_t deleted = value.find(" (deleted)");
    if (deleted != std::string::npos)
      value.resize(deleted);
    return value;
  };
  const std::string wanted_name = normalize_name(expected_name);
  Elf64ProgramHeaders program_headers;
  bool image_valid =
      parse_elf64_program_headers(expected_image, &program_headers) &&
      program_headers.header.e_machine == EM_AARCH64;
  uint64_t header_vaddr = 0;
  bool have_header_load = false;
  if (image_valid) {
    const uint64_t phdr_span =
        static_cast<uint64_t>(program_headers.header.e_phnum) *
        sizeof(Elf64_Phdr);
    uint64_t header_bytes = 0;
    image_valid =
        checked_add_u64(program_headers.header.e_phoff, phdr_span,
                        &header_bytes);
    for (const auto &ph : program_headers.entries) {
      if (!image_valid || ph.p_type != PT_LOAD || ph.p_offset != 0 ||
          ph.p_filesz < header_bytes)
        continue;
      if (have_header_load && header_vaddr != ph.p_vaddr) {
        image_valid = false;
        break;
      }
      header_vaddr = ph.p_vaddr;
      have_header_load = true;
    }
    image_valid = image_valid && have_header_load &&
                  header_vaddr <=
                      std::numeric_limits<uint64_t>::max() - base;
  }
  const uint64_t header_address = image_valid ? base + header_vaddr : 0;
  auto maps = Memory::read_maps(pid);
  bool base_matches = false;
  for (const auto &m : maps) {
    if (header_address >= m.start && header_address < m.end && m.readable() &&
        normalize_name(m.name) == wanted_name) {
      base_matches = true;
      break;
    }
  }

  // expected_image is an ELF *file layout*: consecutive bytes after the first
  // PT_LOAD are not necessarily consecutive in memory. Verify file bytes via
  // each PT_LOAD's p_offset -> p_vaddr mapping instead of memcmp(base, image).
  bool identity_matches =
      image_valid && base_matches &&
      expected_image.size() >= sizeof(Elf64_Ehdr);
  std::vector<uint8_t> actual;
  if (identity_matches) {
    size_t verified = 0;
    if (identity_matches) {
      try {
        actual.resize(4096);
      } catch (...) {
        identity_matches = false;
      }
      for (const auto &ph : program_headers.entries) {
        if (!identity_matches || verified >= actual.size())
          break;
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
          continue;
        size_t amount = static_cast<size_t>(std::min<uint64_t>(
            ph.p_filesz, actual.size() - verified));
        if (ph.p_offset > expected_image.size() ||
            amount > expected_image.size() - ph.p_offset ||
            ph.p_vaddr > std::numeric_limits<uint64_t>::max() - base ||
            !ProcessTracer::read_memory(pid, base + ph.p_vaddr,
                                        actual.data(), amount) ||
            memcmp(actual.data(), expected_image.data() + ph.p_offset,
                   amount) != 0) {
          identity_matches = false;
          break;
        }
        verified += amount;
      }
      identity_matches =
          identity_matches && verified >= sizeof(Elf64_Ehdr);
    }
  }
  if (!identity_matches || signal_window.interrupted()) {
    g_trace_init_status = signal_window.interrupted()
                              ? "interrupted before patching"
                              : "module identity changed after snapshot";
    detach_safely();
    return 0;
  }

  struct TraceThread {
    int tid = 0;
    bool alive = true;
    bool stopped = true;
    bool newborn = false;
    int pending_signal = 0;
    bool interrupt_requested = false;
  };
  struct ForeignChild {
    int tid = 0;
    int tgid = 0;
    bool alive = true;
    bool stopped = true;
    int pending_signal = 0;
  };
  std::vector<TraceThread> trace_threads;
  std::vector<ForeignChild> foreign_children;
  try {
    // Matches ProcessTracer's bounded attached-thread table. Reserving before
    // any patch also makes CLONE adoption allocation-free while BRKs exist.
    trace_threads.reserve(4096);
    foreign_children.reserve(4096);
    std::vector<int> initial_tids;
    if (!ProcessTracer::list_threads_complete(pid, &initial_tids))
      throw std::runtime_error("incomplete thread enumeration");
    for (int tid : initial_tids) {
      if (trace_threads.size() == trace_threads.capacity())
        throw std::runtime_error("too many trace threads");
      trace_threads.push_back({tid, true, true, false, 0});
    }
  } catch (...) {
    g_trace_init_status = "thread-state allocation failed";
    detach_safely();
    return 0;
  }
  bool have_leader = false;
  for (const auto &thread : trace_threads) {
    have_leader = have_leader || thread.tid == pid;
    if (!ProcessTracer::follow_thread_clones(thread.tid)) {
      g_trace_init_status = "PTRACE_O_TRACECLONE/EXITKILL setup failed";
      detach_safely();
      return 0;
    }
  }
  if (!have_leader) {
    g_trace_init_status = "thread-group leader was not attached";
    detach_safely();
    return 0;
  }

  const uint32_t brk_inst = 0xD4200000; // brk #0
  struct PatchRecord {
    uint64_t address = 0;
    uint32_t original = 0;
    bool active_or_unknown = false;
  };
  std::vector<PatchRecord> patches;
  try {
    patches.reserve(init_funcs.size());
    std::set<uint64_t> seen;
    for (uint64_t func : init_funcs) {
      if (!seen.insert(func).second)
        continue;
      bool executable_in_module = false;
      for (const auto &m : maps) {
        if (func >= m.start && func < m.end &&
            m.perms.find('x') != std::string::npos &&
            normalize_name(m.name) == wanted_name) {
          executable_in_module = true;
          break;
        }
      }
      if (!executable_in_module)
        continue;
      uint32_t original = 0;
      if (!ProcessTracer::read_memory(pid, func, &original, sizeof(original)) ||
          original == brk_inst)
        continue;
      patches.push_back({func, original, false});
    }
  } catch (...) {
    g_trace_init_status = "patch registry allocation/read failed";
    detach_safely();
    return 0;
  }

  auto restore_one = [&](PatchRecord &patch, int stopped_tid) {
    if (!patch.active_or_unknown)
      return true;
    for (int attempt = 0; attempt < 3; attempt++) {
      ExecutableWriteResult result =
          MemoryInjector::write_executable_checked(
              stopped_tid, patch.address, &patch.original,
              sizeof(patch.original));
      if (result == ExecutableWriteResult::WrittenVerified) {
        patch.active_or_unknown = false;
        return true;
      }
      if (result == ExecutableWriteResult::NotWritten) {
        uint32_t verify = 0;
        if (ProcessTracer::read_memory(stopped_tid, patch.address, &verify,
                                       sizeof(verify)) &&
            verify == patch.original) {
          patch.active_or_unknown = false;
          return true;
        }
      }
    }
    return false;
  };
  auto restore_all = [&](int stopped_tid) {
    bool ok = true;
    for (auto &patch : patches)
      ok = restore_one(patch, stopped_tid) && ok;
    return ok;
  };
  auto restore_foreign_copy = [&](int stopped_pid) {
    // A FORK child owns a private copy of every instruction as it existed at
    // the fork event. Restore all candidates, not only the ones still active
    // in the parent. A VFORK child shares the mapping, for which the same
    // verified writes are harmless and restore both views.
    for (const auto &patch : patches) {
      bool restored = false;
      for (int attempt = 0; attempt < 3; attempt++) {
        ExecutableWriteResult result =
            MemoryInjector::write_executable_checked(
                stopped_pid, patch.address, &patch.original,
                sizeof(patch.original));
        if (result == ExecutableWriteResult::WrittenVerified) {
          restored = true;
          break;
        }
        uint32_t verify = 0;
        if (ProcessTracer::read_memory(stopped_pid, patch.address, &verify,
                                       sizeof(verify)) &&
            verify == patch.original) {
          restored = true;
          break;
        }
      }
      if (!restored)
        return false;
    }
    return true;
  };
  auto active_count = [&]() {
    size_t count = 0;
    for (const auto &patch : patches)
      count += patch.active_or_unknown ? 1 : 0;
    return count;
  };

  if (!ProcessTracer::begin_patch_transaction(pid)) {
    g_trace_init_status = "another patch transaction is active";
    detach_safely();
    return 0;
  }
  bool patch_transaction_active = true;
  auto end_patch_transaction = [&]() {
    if (!patch_transaction_active)
      return;
    ProcessTracer::end_patch_transaction(pid);
    patch_transaction_active = false;
  };

  bool install_safe = true;
  for (auto &patch : patches) {
    if (signal_window.interrupted())
      break;
    // Mark first: StateUnknown means the instruction may already have changed
    // even though the helper could not verify its final state.
    patch.active_or_unknown = true;
    ExecutableWriteResult result = MemoryInjector::write_executable_checked(
        pid, patch.address, &brk_inst, sizeof(brk_inst));
    if (result == ExecutableWriteResult::WrittenVerified)
      continue;
    if (result == ExecutableWriteResult::NotWritten) {
      uint32_t verify = 0;
      if (ProcessTracer::read_memory(pid, patch.address, &verify,
                                     sizeof(verify)) &&
          verify == patch.original) {
        patch.active_or_unknown = false;
        continue;
      }
    }
    install_safe = false;
    break;
  }

  if (!install_safe || signal_window.interrupted() || active_count() == 0) {
    if (!install_safe)
      g_trace_init_status = "temporary BRK install/verification failed";
    else if (signal_window.interrupted())
      g_trace_init_status = "interrupted while installing BRKs";
    else
      g_trace_init_status = "no verified init-array patch candidates";
    bool restored = restore_all(pid);
    if (!restored)
      kill(pid, SIGKILL);
    end_patch_transaction();
    bool detached = detach_safely();
    (void)detached;
    return 0;
  }

  auto find_patch_at_pc = [&](uint64_t pc, bool *rewind_pc) -> PatchRecord * {
    for (auto &patch : patches) {
      if (pc == patch.address) {
        *rewind_pc = false;
        return &patch;
      }
      if (pc >= 4 && pc - 4 == patch.address) {
        *rewind_pc = true;
        return &patch;
      }
    }
    return nullptr;
  };
  auto thread_is_listed = [&](int tid) {
    // PTRACE_CONT/waitpid can transiently report ESRCH/ECHILD. Only retire a
    // TID after procfs confirms that the exact thread-group member is gone;
    // every other result is ambiguous and therefore fail-closed.
    char task_path[96] = {};
    int length = snprintf(task_path, sizeof(task_path),
                          "/proc/%d/task/%d", pid, tid);
    if (length < 0 || static_cast<size_t>(length) >= sizeof(task_path))
      return true;
    int task_fd = open(task_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (task_fd >= 0) {
      close(task_fd);
      return true;
    }
    return errno != ENOENT;
  };
  auto resume_thread = [&](TraceThread &thread, int signal = 0) {
    if (!thread.alive || !thread.stopped)
      return true;
    errno = 0;
    if (ProcessTracer::continue_process(thread.tid, signal)) {
      thread.stopped = false;
      return true;
    }
    int continue_errno = errno;
    if (continue_errno == ESRCH && !thread_is_listed(thread.tid)) {
      thread.alive = false;
      thread.stopped = false;
      return true;
    }
    errno = continue_errno;
    return false;
  };
  const char *trace_ambiguity_detail = nullptr;
  auto terminate_unclaimed_child = [&](int child) {
    int child_tgid = 0;
    if (!ProcessTracer::read_thread_group_id(child, &child_tgid) ||
        child_tgid <= 0)
      child_tgid = child;
    // The child is at a waitpid-proven ptrace stop. Detaching with SIGKILL
    // binds termination to that exact task; if even this verified release is
    // ambiguous, terminally drain every task whose TracerPid is ours.
    if (ProcessTracer::release_auto_attached_child(
            child, SIGKILL, child_tgid, false))
      return;
    ProcessTracer::terminal_drain_owned_tracees();
  };
  auto register_auto_child = [&](int child, bool resume_same_group) {
    // A FORK/VFORK/CLONE event identifies a kernel-owned child, but its procfs
    // identity and pidfd are not guaranteed to be publishable until the
    // separate auto-attach stop is observed. Consume that stop first. This
    // closes the window in which a valid new child was previously rejected as
    // an ambiguous numeric PID and the original group was killed needlessly.
    int pending_signal = 0;
    bool child_stopped = false;
    for (int retry = 0; retry < 200; retry++) {
      int status = 0;
      errno = 0;
      pid_t waited = waitpid(child, &status, __WALL | WNOHANG);
      if (waited == child) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
          return true;
        }
        if (!WIFSTOPPED(status))
          continue;
        const int stop_signal = WSTOPSIG(status);
        const unsigned event =
            (static_cast<unsigned>(status) >> 16) & 0xffffu;
        pending_signal =
            (stop_signal == SIGSTOP || event != 0) ? 0 : stop_signal;
        child_stopped = true;
        break;
      }
      if (waited < 0) {
        if (errno == EINTR)
          continue;
        if ((errno == ECHILD || errno == ESRCH) &&
            kill(child, 0) < 0 && errno == ESRCH) {
          return true;
        }
        break;
      }
      usleep(1000);
    }
    if (!child_stopped) {
      trace_ambiguity_detail = "auto-child initial stop was ambiguous";
      ProcessTracer::terminal_drain_owned_tracees();
      return false;
    }

    int child_tgid = 0;
    bool original_group = false;
    for (int retry = 0; retry < 200; retry++) {
      if (ProcessTracer::claim_auto_attached_tracee(
              pid, child, &child_tgid, &original_group))
        break;
      usleep(1000);
    }
    if (child_tgid <= 0) {
      trace_ambiguity_detail = "stopped auto-child identity claim failed";
      terminate_unclaimed_child(child);
      return false;
    }

    if (original_group) {
      if (trace_threads.size() == trace_threads.capacity() ||
          !ProcessTracer::follow_thread_clones(child)) {
        trace_ambiguity_detail = "same-group auto-child setup failed";
        ProcessTracer::terminal_drain_owned_tracees();
        return false;
      }
      trace_threads.push_back(
          {child, true, true, false, pending_signal, false});
      if (resume_same_group && !resume_thread(trace_threads.back())) {
        trace_ambiguity_detail = "same-group auto-child resume failed";
        return false;
      }
      return true;
    }

    if (foreign_children.size() == foreign_children.capacity()) {
      trace_ambiguity_detail = "foreign-child registry exhausted";
      if (!ProcessTracer::release_auto_attached_child(
              child, SIGKILL, child_tgid, child_tgid == child))
        ProcessTracer::terminal_drain_owned_tracees();
      return false;
    }
    // A different address space may contain a private copy of every live BRK.
    // Retain its exact stopped TID until both parent and child copies have been
    // restored and verified. A non-leader is tied to its already-pinned TGID.
    foreign_children.push_back(
        {child, child_tgid, true, true, pending_signal});
    return true;
  };

  bool trace_safe = true;
  for (auto &thread : trace_threads)
    trace_safe = resume_thread(thread) && trace_safe;
  if (!trace_safe || !signal_window.unblock()) {
    g_trace_init_status = !trace_safe ? "could not resume every traced TID"
                                     : "could not unblock cooperative signals";
    // Some threads may already be running through patched text. A terminal
    // stop is safer than attempting a racy partial rollback.
    kill(pid, SIGKILL);
    end_patch_transaction();
    detach_safely();
    return 0;
  }

  // Non-blocking waits cover every attached TID. CLONE children are adopted
  // before their first resume so no untraced worker can execute a temporary
  // BRK and take the process down with a default SIGTRAP.
  const int poll_step_ms = 10;
  const int max_wait_ms = 1500;
  const int max_stops = 10000;
  int waited_ms = 0;
  int quiet_after_restore_ms = 0;
  int observed_stops = 0;
  size_t breakpoint_hits = 0;
  size_t fork_events = 0;
  size_t vfork_events = 0;
  size_t clone_events = 0;
  size_t quiesce_clone_events = 0;
  bool abort_trace = false;

  while (waited_ms < max_wait_ms && observed_stops < max_stops &&
         !signal_window.interrupted() && !abort_trace) {
    bool handled_event = false;
    for (size_t index = 0; index < trace_threads.size(); index++) {
      TraceThread &thread = trace_threads[index];
      if (!thread.alive || thread.stopped)
        continue;

      int status = 0;
      pid_t w = waitpid(thread.tid, &status, __WALL | WNOHANG);
      if (w == 0)
        continue;
      if (w < 0) {
        if (errno == EINTR)
          continue;
        if (errno == ECHILD || errno == ESRCH) {
          if (!thread_is_listed(thread.tid)) {
            thread.alive = false;
            thread.stopped = false;
            continue;
          }
          trace_safe = false;
          trace_ambiguity_detail = "observation wait lost a listed TID";
          abort_trace = true;
          break;
        }
        trace_safe = false;
        trace_ambiguity_detail = "observation waitpid failed";
        abort_trace = true;
        break;
      }

      handled_event = true;
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        thread.alive = false;
        thread.stopped = false;
        break;
      }
      if (!WIFSTOPPED(status))
        break;

      thread.stopped = true;
      observed_stops++;
      const int stop_signal = WSTOPSIG(status);
      const unsigned event =
          (static_cast<unsigned>(status) >> 16) & 0xffffu;

      if (thread.newborn) {
        thread.newborn = false;
        if (!ProcessTracer::follow_thread_clones(thread.tid) ||
            !resume_thread(thread)) {
          trace_safe = false;
          trace_ambiguity_detail = "newborn clone setup/resume failed";
          abort_trace = true;
        }
        break;
      }

      if (event == 1u || event == 2u || event == 3u) {
        // PTRACE_EVENT_FORK / VFORK / CLONE
        fork_events += event == 1u ? 1 : 0;
        vfork_events += event == 2u ? 1 : 0;
        clone_events += event == 3u ? 1 : 0;
        int child = 0;
        bool known = false;
        if (!ProcessTracer::event_child(thread.tid, &child)) {
          trace_safe = false;
          trace_ambiguity_detail = "child event payload was invalid";
          abort_trace = true;
          break;
        }
        for (const auto &existing : trace_threads)
          known = known || existing.tid == child;
        if (!known && !register_auto_child(child, true)) {
          trace_safe = false;
          abort_trace = true;
          break;
        }
        if (event == 2u) {
          // A vfork parent cannot make progress until its separate child
          // exits or execs.  register_auto_child() deliberately retains that
          // child at its initial ptrace stop while copied/shared temporary
          // BRKs are present, so resuming the parent here deadlocks the pair:
          // the parent stays vfork-suspended and the child stays tracer-held.
          // Keep the parent at its event stop and leave the observation loop.
          // The common rollback below restores both address spaces, releases
          // the child first, and only then detaches/resumes this parent.
          abort_trace = true;
          break;
        }
        if (!resume_thread(thread)) {
          trace_safe = false;
          trace_ambiguity_detail = "event parent resume failed";
          abort_trace = true;
        }
        break;
      }

      if (event == 128u) {
        // Unsolicited PTRACE_EVENT_STOP is a seized job-control group-stop.
        // SIGTRAP is reserved for Hayabusa's PTRACE_INTERRUPT requests, none
        // of which are outstanding during the observation phase.
        if (stop_signal == SIGTRAP) {
          trace_safe = false;
          trace_ambiguity_detail = "unsolicited interrupt-style event stop";
        } else {
          thread.pending_signal = stop_signal;
        }
        abort_trace = true;
        break;
      }
      if (event != 0) {
        trace_safe = false;
        trace_ambiguity_detail = "unexpected ptrace event during observation";
        abort_trace = true;
        break;
      }

      uint64_t pc = 0;
      if (!ProcessTracer::get_pc(thread.tid, &pc)) {
        trace_safe = false;
        trace_ambiguity_detail = "breakpoint-stop PC read failed";
        abort_trace = true;
        break;
      }
      bool rewind_pc = false;
      PatchRecord *matched =
          stop_signal == SIGTRAP ? find_patch_at_pc(pc, &rewind_pc) : nullptr;
      if (matched) {
        if (matched->active_or_unknown &&
            !restore_one(*matched, thread.tid)) {
          trace_safe = false;
          trace_ambiguity_detail = "breakpoint rollback at hit failed";
          abort_trace = true;
          break;
        }
        if (rewind_pc &&
            !ProcessTracer::set_pc(thread.tid, matched->address)) {
          trace_safe = false;
          trace_ambiguity_detail = "breakpoint PC rewind failed";
          abort_trace = true;
          break;
        }
        breakpoint_hits++;
        if (!resume_thread(thread)) {
          trace_safe = false;
          trace_ambiguity_detail = "breakpoint-hit TID resume failed";
          abort_trace = true;
        }
        break;
      }

      // Hold a genuine signal on this exact stopped TID. It is delivered only
      // after every other TID is quiesced and all temporary BRKs are restored.
      thread.pending_signal = stop_signal;
      abort_trace = true;
      break;
    }

    if (!trace_safe || abort_trace)
      break;
    if (handled_event) {
      quiet_after_restore_ms = 0;
      continue;
    }

    usleep(poll_step_ms * 1000);
    waited_ms += poll_step_ms;
    if (active_count() == 0) {
      quiet_after_restore_ms += poll_step_ms;
      if (quiet_after_restore_ms >= 20)
        break;
    } else {
      quiet_after_restore_ms = 0;
    }
  }

  // Quiesce every still-running TID without injecting a target-visible
  // SIGSTOP. waitpid may first expose a pending BRK, signal, or CLONE event;
  // whichever ptrace stop wins is already a complete quiescence boundary.
  for (auto &thread : trace_threads)
    // A TRACECLONE child already has a kernel-generated initial stop pending.
    // Consume that stop below; it needs no additional interrupt.
    if (thread.alive && !thread.stopped && !thread.newborn) {
      errno = 0;
      if (ProcessTracer::interrupt(thread.tid)) {
        thread.interrupt_requested = true;
      } else if (errno == EIO) {
        // A ptrace stop was already pending but not yet consumed. Waiting for
        // it is sufficient to quiesce this TID; no interrupt debt exists.
      } else if (errno == ESRCH && !thread_is_listed(thread.tid)) {
        thread.alive = false;
      } else {
        trace_safe = false;
        trace_ambiguity_detail = "quiesce interrupt failed";
      }
    }

  bool quiesce_wait_failed = false;
  for (int round = 0; round < 200; round++) {
    bool all_stopped = true;
    bool made_progress = false;
    for (size_t index = 0; index < trace_threads.size(); index++) {
      TraceThread &thread = trace_threads[index];
      if (!thread.alive || thread.stopped)
        continue;
      all_stopped = false;

      int status = 0;
      pid_t w = waitpid(thread.tid, &status, __WALL | WNOHANG);
      if (w == 0)
        continue;
      if (w < 0) {
        if (errno == EINTR)
          continue;
        if (errno == ECHILD || errno == ESRCH) {
          if (!thread_is_listed(thread.tid)) {
            thread.alive = false;
            thread.stopped = false;
            made_progress = true;
            continue;
          }
          trace_safe = false;
          trace_ambiguity_detail = "quiesce wait lost a listed TID";
          quiesce_wait_failed = true;
          break;
        }
        trace_safe = false;
        trace_ambiguity_detail = "quiesce waitpid failed";
        continue;
      }
      made_progress = true;
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        thread.alive = false;
        thread.stopped = false;
        continue;
      }
      if (!WIFSTOPPED(status))
        continue;

      thread.stopped = true;
      const int stop_signal = WSTOPSIG(status);
      const unsigned event =
          (static_cast<unsigned>(status) >> 16) & 0xffffu;
      const bool requested_before_stop = thread.interrupt_requested;
      // Any ptrace stop is a complete quiescence boundary. INTERRUPT is not a
      // target signal and leaves no detach-visible debt when another stop wins
      // the race, so an exact event-128 acknowledgement is unnecessary.
      thread.interrupt_requested = false;
      if (event == 1u || event == 2u || event == 3u) {
        fork_events += event == 1u ? 1 : 0;
        vfork_events += event == 2u ? 1 : 0;
        clone_events += event == 3u ? 1 : 0;
        quiesce_clone_events += event == 3u ? 1 : 0;
        int child = 0;
        bool known = false;
        if (!ProcessTracer::event_child(thread.tid, &child)) {
          trace_safe = false;
          trace_ambiguity_detail = "quiesce child event payload was invalid";
          continue;
        }
        for (const auto &existing : trace_threads)
          known = known || existing.tid == child;
        if (!known && !register_auto_child(child, false))
          trace_safe = false;
        continue;
      }
      if (thread.newborn) {
        thread.newborn = false;
        continue;
      }

      if (event == 128u) {
        const bool ours = requested_before_stop;
        if (stop_signal != SIGTRAP) {
          if (thread.pending_signal != 0 &&
              thread.pending_signal != stop_signal) {
            trace_safe = false;
            trace_ambiguity_detail = "conflicting pending job-control signal";
          } else {
            // A seized group-stop can satisfy an interrupt while retaining
            // the target's exact job-control signal for verified detach.
            thread.pending_signal = stop_signal;
          }
        } else if (!ours) {
          trace_safe = false;
          trace_ambiguity_detail = "unrequested quiesce event stop";
        }
        continue;
      }
      if (event != 0) {
        trace_safe = false;
        trace_ambiguity_detail = "unexpected ptrace event during quiescence";
        continue;
      }

      bool rewind_pc = false;
      uint64_t pc = 0;
      PatchRecord *matched = nullptr;
      if (stop_signal == SIGTRAP) {
        if (!ProcessTracer::get_pc(thread.tid, &pc)) {
          trace_safe = false;
          trace_ambiguity_detail = "quiesce SIGTRAP PC read failed";
          continue;
        }
        matched = find_patch_at_pc(pc, &rewind_pc);
      }
      if (matched) {
        if (matched->active_or_unknown &&
            !restore_one(*matched, thread.tid))
          trace_safe = false;
        if (!trace_safe && !trace_ambiguity_detail)
          trace_ambiguity_detail = "quiesce breakpoint rollback failed";
        if (rewind_pc &&
            !ProcessTracer::set_pc(thread.tid, matched->address))
          trace_safe = false;
        if (!trace_safe && !trace_ambiguity_detail)
          trace_ambiguity_detail = "quiesce breakpoint PC rewind failed";
        breakpoint_hits++;
      } else {
        // Keep a genuine signal pending on this exact stopped TID. It is
        // replayed only after every temporary instruction is restored.
        thread.pending_signal = stop_signal;
      }
    }
    if (quiesce_wait_failed)
      break;
    if (all_stopped)
      break;
    if (!made_progress)
      usleep(5000);
  }

  bool any_alive = false;
  bool every_alive_stopped = true;
  int stopped_writer = 0;
  for (const auto &thread : trace_threads) {
    if (!thread.alive)
      continue;
    any_alive = true;
    every_alive_stopped = every_alive_stopped && thread.stopped;
    if (thread.stopped && (stopped_writer == 0 || thread.tid == pid))
      stopped_writer = thread.tid;
  }

  // Keep PTRACE_O_EXITKILL armed until every address space is clean. If the
  // tracer crashes during rollback, the kernel must kill rather than detach a
  // target that can still contain a temporary BRK.
  const char *trace_failure_detail = nullptr;
  bool restored = every_alive_stopped;
  if (!every_alive_stopped)
    trace_failure_detail = "not every original thread was quiesced";
  if (any_alive) {
    if (restored && stopped_writer == 0) {
      restored = false;
      trace_failure_detail = "no stopped writer remained for parent rollback";
    }
    if (restored && !restore_all(stopped_writer)) {
      restored = false;
      trace_failure_detail = "parent breakpoint rollback was not verified";
    }
  }
  if (restored) {
    for (const auto &child : foreign_children) {
      if (child.alive &&
          (!child.stopped || !restore_foreign_copy(child.tid))) {
        restored = false;
        trace_failure_detail = child.stopped
                                   ? "child breakpoint rollback was not verified"
                                   : "a copied address space was not stopped";
        break;
      }
    }
  }
  if (restored && !trace_safe) {
    restored = false;
    trace_failure_detail = trace_ambiguity_detail
                               ? trace_ambiguity_detail
                               : "ptrace observation or quiescence became ambiguous";
  }

  // Existing events and children are represented above; all code copies are
  // now verified clean and all TIDs remain stopped. Disabling clone/EXITKILL
  // options closes the final event-generation race without weakening
  // fail-closed rollback.
  if (restored) {
    for (const auto &thread : trace_threads) {
      if (thread.alive &&
          !ProcessTracer::clear_trace_options(thread.tid)) {
        restored = false;
        trace_failure_detail = "could not clear original trace options";
        break;
      }
    }
  }
  bool child_ownership_ambiguous = false;
  auto is_last_live_group_member = [&](const ForeignChild &wanted) {
    for (const auto &candidate : foreign_children)
      if (&candidate != &wanted && candidate.alive &&
          candidate.tgid == wanted.tgid)
        return false;
    return true;
  };
  auto kill_and_release_child = [&](ForeignChild &child) {
    if (!child.alive)
      return;
    // Bind termination to the exact ptrace-owned TID before dropping
    // ownership; never target a potentially reused numeric PID with kill(2).
    if (ProcessTracer::release_auto_attached_child(
            child.tid, SIGKILL, child.tgid,
            is_last_live_group_member(child)))
      child.alive = false;
    else
      child_ownership_ambiguous = true;
  };
  if (!restored) {
    for (auto &child : foreign_children)
      kill_and_release_child(child);
    kill(pid, SIGKILL);
    end_patch_transaction();
  } else {
    // Every separate child is still stopped and its own address space is now
    // verified clean. Only now may it leave ptrace ownership and run.
    bool terminal_child_drain = false;
    for (auto &child : foreign_children) {
      if (!child.alive)
        continue;
      if (terminal_child_drain) {
        kill_and_release_child(child);
        continue;
      }
      if (ProcessTracer::release_auto_attached_child(
              child.tid, child.pending_signal, child.tgid,
              is_last_live_group_member(child))) {
        child.alive = false;
        continue;
      }
      // Do not break here. Later children are still ptrace-owned and may also
      // contain copied temporary code; each one must be terminally drained.
      restored = false;
      trace_failure_detail = "verified child release failed";
      terminal_child_drain = true;
      kill_and_release_child(child);
      kill(pid, SIGKILL);
    }
    end_patch_transaction();
    for (const auto &thread : trace_threads) {
      if (!restored)
        break;
      if (!thread.alive || thread.pending_signal == 0)
        continue;
      if (!ProcessTracer::detach_thread_with_signal(
              pid, thread.tid, thread.pending_signal)) {
        restored = false;
        trace_failure_detail = "pending signal delivery detach failed";
        kill(pid, SIGKILL);
        break;
      }
    }
  }
  if (child_ownership_ambiguous) {
    // The lock-free child table is the last-resort ownership registry. A
    // failed verified release must drain every registered child before this
    // function can forget it; cleanup also terminally stops the patched
    // original group. The fatal sentinel deliberately prevents later patch
    // transactions in this Hayabusa process.
    ProcessTracer::cleanup_all_attached();
    ProcessTracer::reset_attach_bookkeeping();
    attached = false;
    restored = false;
    trace_failure_detail = "child ownership remained ambiguous";
  }
  bool detached = detach_safely();
  if (!restored) {
    g_trace_init_status = "trace restore/signal delivery failed; target killed";
    if (trace_failure_detail) {
      g_trace_init_status += " (";
      g_trace_init_status += trace_failure_detail;
      g_trace_init_status += ")";
    }
  } else if (!detached)
    g_trace_init_status = "verified detach failed; target killed";
  else if (breakpoint_hits != 0)
    g_trace_init_status = "completed with verified breakpoint hits";
  else
    g_trace_init_status = "completed safely with no breakpoint hits";
  if (restored && detached) {
    g_trace_init_status += "; ptrace-events fork=" +
                           std::to_string(fork_events) + " vfork=" +
                           std::to_string(vfork_events) + " clone=" +
                           std::to_string(clone_events) + " quiesce-clone=" +
                           std::to_string(quiesce_clone_events);
  }
  return restored && detached ? breakpoint_hits : 0;
}



double ElfParser::calculate_entropy(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0.0;

  size_t freq[256] = {0};
  for (size_t i = 0; i < size; i++) {
    freq[data[i]]++;
  }

  double entropy = 0.0;
  for (int i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      double p = (double)freq[i] / size;
      entropy -= p * log2(p);
    }
  }

  return entropy;
}

std::vector<EntropyInfo>
ElfParser::find_high_entropy_regions(const std::vector<uint8_t> &data,
                                     size_t block_size, double threshold,
                                     size_t max_results) {
  std::vector<EntropyInfo> results;

  if (block_size == 0 || data.size() < block_size)
    return results;

  size_t step = std::max<size_t>(1, block_size / 2);
  uint64_t region_start = 0;
  bool in_high_entropy = false;
  double max_entropy = 0;

  for (size_t i = 0; i + block_size <= data.size(); i += step) {
    double entropy = calculate_entropy(data.data() + i, block_size);

    if (entropy >= threshold) {
      if (!in_high_entropy) {
        region_start = i;
        in_high_entropy = true;
        max_entropy = entropy;
      } else {
        max_entropy = std::max(max_entropy, entropy);
      }
    } else if (in_high_entropy) {
      if (results.size() >= max_results)
        return results;
      EntropyInfo info;
      info.offset = region_start;
      info.size = i - region_start;
      info.entropy = max_entropy;
      info.likely_encrypted = (max_entropy > 7.5);
      info.likely_compressed = (max_entropy > 7.0 && max_entropy <= 7.5);
      results.push_back(info);
      in_high_entropy = false;
    }
  }

  if (in_high_entropy) {
    if (results.size() >= max_results)
      return results;
    EntropyInfo info;
    info.offset = region_start;
    info.size = data.size() - region_start;
    info.entropy = max_entropy;
    info.likely_encrypted = (max_entropy > 7.5);
    info.likely_compressed = (max_entropy > 7.0 && max_entropy <= 7.5);
    results.push_back(info);
  }

  return results;
}

static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const uint8_t AES_RCON[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                     0x20, 0x40, 0x80, 0x1b, 0x36};

std::vector<AESKeyInfo>
ElfParser::detect_aes_keys(const std::vector<uint8_t> &data) {
  std::vector<AESKeyInfo> results;

  for (size_t i = 0; i + 256 <= data.size(); i++) {
    if (data[i] == AES_SBOX[0] &&
        memcmp(data.data() + i, AES_SBOX, sizeof(AES_SBOX)) == 0) {
      AESKeyInfo info{};
      info.offset = i;
      info.key_size = 0;
      info.detection_method = "S-BOX";
      info.confidence = 1.0;
      results.push_back(info);
      i += 255;
    }
  }

  struct ScheduleShape {
    size_t key_bytes;
    size_t expanded_bytes;
    int nk;
    int nr;
    const char *name;
  };
  static constexpr ScheduleShape shapes[] = {
      {16, 176, 4, 10, "KEY-SCHEDULE-128"},
      {24, 208, 6, 12, "KEY-SCHEDULE-192"},
      {32, 240, 8, 14, "KEY-SCHEDULE-256"},
  };

  for (const auto &shape : shapes) {
    for (size_t off = 0; off + shape.expanded_bytes <= data.size(); ++off) {
      const int total_words = 4 * (shape.nr + 1);
      int matched_words = 0;
      bool valid = true;
      for (int word = shape.nk; word < total_words; word++) {
        uint8_t temp[4];
        memcpy(temp, data.data() + off + (word - 1) * 4, sizeof(temp));
        if (word % shape.nk == 0) {
          uint8_t first = temp[0];
          temp[0] = AES_SBOX[temp[1]];
          temp[1] = AES_SBOX[temp[2]];
          temp[2] = AES_SBOX[temp[3]];
          temp[3] = AES_SBOX[first];
          temp[0] ^= AES_RCON[word / shape.nk];
        } else if (shape.nk == 8 && word % shape.nk == 4) {
          for (uint8_t &b : temp)
            b = AES_SBOX[b];
        }

        bool word_ok = true;
        for (int j = 0; j < 4; j++) {
          uint8_t expected =
              data[off + (word - shape.nk) * 4 + j] ^ temp[j];
          if (data[off + word * 4 + j] != expected) {
            word_ok = false;
            break;
          }
        }
        if (!word_ok) {
          valid = false;
          break;
        }
        matched_words++;
      }

      if (!valid)
        continue;
      AESKeyInfo info{};
      info.offset = off;
      memcpy(info.key, data.data() + off, shape.key_bytes);
      info.key_size = shape.key_bytes;
      info.detection_method = shape.name;
      info.confidence =
          static_cast<double>(matched_words) / (total_words - shape.nk);
      results.push_back(info);
      off += shape.expanded_bytes - 1;
    }
  }

  return results;
}
