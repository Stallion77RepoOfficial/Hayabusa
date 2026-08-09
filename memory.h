#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <limits>
#include <map>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

// Read a little-endian scalar out of a byte buffer.
//
// Dumped images are byte arrays with no alignment guarantee, so
// `*(uint32_t *)(p + off)` is both undefined behaviour and a strict-aliasing
// violation -- at -O3 the compiler is entitled to assume it never happens. The
// memcpy compiles to the same single LDR on AArch64 and is well defined.
// Callers must bounds-check before calling; this only fixes the load itself.
inline uint32_t read_le32(const void *p) {
  uint32_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

inline uint64_t read_le64(const void *p) {
  uint64_t v;
  memcpy(&v, p, sizeof(v));
  return v;
}

inline void write_le32(void *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }

// A bounded, alignment-safe view of an ELF64 program-header table.  Keep this
// as the single validation gate for read-only program-header walks: dumped
// images are untrusted byte arrays and need not align either structure.
struct Elf64ProgramHeaders {
  Elf64_Ehdr header{};
  std::vector<Elf64_Phdr> entries;
};

inline bool parse_elf64_program_headers(const uint8_t *data, size_t size,
                                        Elf64ProgramHeaders *out) {
  if (!out)
    return false;
  *out = {};
  if (!data || size < sizeof(Elf64_Ehdr))
    return false;

  Elf64ProgramHeaders parsed;
  memcpy(&parsed.header, data, sizeof(parsed.header));
  const auto &eh = parsed.header;
  if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64 ||
      eh.e_ident[EI_DATA] != ELFDATA2LSB ||
      eh.e_ident[EI_VERSION] != EV_CURRENT || eh.e_version != EV_CURRENT ||
      eh.e_ehsize != sizeof(Elf64_Ehdr) ||
      eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum == 0 ||
      eh.e_phnum > 4096 || eh.e_phoff == 0 || eh.e_phoff > size ||
      eh.e_phnum >
          (size - static_cast<size_t>(eh.e_phoff)) /
              sizeof(Elf64_Phdr)) {
    return false;
  }

  try {
    parsed.entries.resize(eh.e_phnum);
  } catch (...) {
    return false;
  }
  for (size_t i = 0; i < parsed.entries.size(); ++i) {
    const size_t offset = static_cast<size_t>(eh.e_phoff) +
                          i * sizeof(Elf64_Phdr);
    memcpy(&parsed.entries[i], data + offset, sizeof(Elf64_Phdr));
    const auto &ph = parsed.entries[i];
    if (ph.p_type != PT_LOAD)
      continue;
    if (ph.p_filesz > ph.p_memsz || ph.p_offset > size ||
        ph.p_filesz > size - static_cast<size_t>(ph.p_offset) ||
        ph.p_vaddr > std::numeric_limits<uint64_t>::max() - ph.p_memsz) {
      return false;
    }
  }

  *out = std::move(parsed);
  return true;
}

inline bool
parse_elf64_program_headers(const std::vector<uint8_t> &data,
                            Elf64ProgramHeaders *out) {
  return parse_elf64_program_headers(data.data(), data.size(), out);
}

// One line of /proc/<pid>/maps. Single source of truth for map parsing --
// Memory::read_maps() is the only parser in the codebase.
struct MapEntry {
  uint64_t start;
  uint64_t end;
  uint64_t offset;
  std::string perms;
  std::string name;

  size_t size() const { return static_cast<size_t>(end - start); }
  bool readable() const { return perms.find('r') != std::string::npos; }
  bool writable() const { return perms.find('w') != std::string::npos; }
};

struct ElfSymbol {
  std::string name;
  uint64_t offset;
  uint64_t size;
  std::string type;
};

struct ElfString {
  uint64_t offset;
  std::string value;
};

// Materialisation limits for untrusted string tables.  A scan still walks the
// input once so total_matches remains useful, but it never retains more than
// these bounds.  Oversized printable runs are counted and omitted rather than
// silently returning a prefix as if it were the complete string.
struct StringScanLimits {
  size_t max_results = 100000;
  size_t max_retained_bytes = 16U * 1024U * 1024U;
  size_t max_string_bytes = 64U * 1024U;
};

struct StringScanStatus {
  size_t total_matches = 0;
  size_t retained_results = 0;
  size_t retained_bytes = 0;
  bool truncated = false;
};

struct PatternMatch {
  uint64_t offset;
};

struct DecryptResult {
  uint64_t offset;
  std::vector<uint8_t> decrypted;
  std::string method;
  uint8_t key_or_info[32];
  size_t key_size;
};

// Work limits for automatic deobfuscation.  max_probes bounds cheap window
// classification, max_candidates bounds calls into the expensive decryptor,
// and max_results bounds retained output.  deadline_ms uses CLOCK_MONOTONIC via
// std::chrono::steady_clock.  A zero limit means that category has no budget.
// cancel, when non-null, must outlive the call.
struct AutoDecryptLimits {
  size_t max_input_bytes = 16U * 1024U * 1024U;
  size_t max_probes = 1024U * 1024U;
  size_t max_candidates = 4096;
  size_t max_results = 1024;
  uint64_t deadline_ms = 5000;
  const std::atomic<bool> *cancel = nullptr;
};

struct AutoDecryptStatus {
  size_t input_bytes = 0;
  size_t probes = 0;
  size_t candidates = 0;
  size_t retained_results = 0;
  bool input_truncated = false;
  bool probe_limit_reached = false;
  bool candidate_limit_reached = false;
  bool result_limit_reached = false;
  bool deadline_reached = false;
  bool cancelled = false;

  bool truncated() const {
    return input_truncated || probe_limit_reached || candidate_limit_reached ||
           result_limit_reached || deadline_reached || cancelled;
  }
};

struct EntropyInfo {
  uint64_t offset;
  size_t size;
  double entropy;
  bool likely_encrypted;
  bool likely_compressed;
};

struct AESKeyInfo {
  uint64_t offset;
  uint8_t key[32];
  size_t key_size;
  std::string detection_method;
  double confidence;
};

class Memory {
public:
  static std::vector<MapEntry> read_maps(int pid);
  static std::vector<uint8_t> dump(int pid, uint64_t addr, size_t size);
};

class Utils {
public:
  static std::string format_size(size_t bytes);
};

class ElfParser {
public:
  // True only for a little-endian ELFCLASS64 image. AArch64 is the only
  // supported target, so this doubles as the 32-bit rejection point.
  static bool is_elf(const std::vector<uint8_t> &data);
  static bool is_file_backed_vaddr(const std::vector<uint8_t> &data,
                                   uint64_t vaddr);
  static std::vector<ElfSymbol> get_symbols(const std::vector<uint8_t> &data);
  static size_t count_symbols(const std::vector<uint8_t> &data);
  static size_t write_symbols(std::ostream &out,
                              const std::vector<uint8_t> &data,
                              std::vector<ElfSymbol> *vtables = nullptr);
  static std::vector<ElfString> get_strings(const std::vector<uint8_t> &data,
                                            size_t min_len);
  static std::vector<ElfString>
  get_strings(const std::vector<uint8_t> &data, size_t min_len,
              const StringScanLimits &limits, StringScanStatus *status);
  static size_t write_strings(std::ostream &out,
                              const std::vector<uint8_t> &data, size_t min_len);
  static size_t write_rtti(std::ostream &out, const std::vector<uint8_t> &data,
                           uint64_t base_addr,
                           const std::vector<ElfSymbol> &vtables,
                           size_t max_results);

  struct PltEntry {
    uint64_t offset;
    uint64_t got_offset;
    std::string symbol_name;
    uint32_t symbol_index;
  };
  static std::vector<PltEntry>
  get_plt_entries(const std::vector<uint8_t> &data);

  // Call sites that reach an imported function, as (site vaddr, symbol).
  // Decodes AArch64 BL; a site is only reported when its computed target lands
  // exactly on a known PLT stub.
  // A function name recovered by joining a pointer table with a name table --
  // the same idea il2cpp metadata exploits, applied to whatever registration
  // structures a module happens to contain.
  struct RecoveredName {
    uint64_t func_vaddr;
    std::string name;
    std::string signature; // JNI descriptor when the table carries one
    std::string source;    // which table shape produced this binding
  };
  // base_addr: load address when `data` is a memory dump. Pointers inside a
  // dumped image are already relocated to absolute addresses, so they have to
  // be normalised before they can be resolved back into the image.
  static std::vector<RecoveredName>
  recover_names(const std::vector<uint8_t> &data, uint64_t base_addr = 0);

  // A C++ class recovered from RTTI alone, with no symbol table involved.
  // typeinfo objects carry the mangled class name, and a vtable is identified
  // by the typeinfo pointer sitting in its second slot -- the same
  // pointer-table/name-table join, applied to the Itanium ABI.
  struct RttiClass {
    uint64_t typeinfo_vaddr;
    uint64_t vtable_vaddr;          // 0 when no vtable references it
    std::string name;               // demangled
    std::vector<uint64_t> vfuncs;   // virtual method addresses, in slot order
  };
  static std::vector<RttiClass> scan_rtti_tables(const std::vector<uint8_t> &data,
                                                 uint64_t base_addr = 0);

  // A field inferred from how code touches an object, not from any name table.
  struct FieldAccess {
    uint64_t offset;
    uint32_t width;   // bytes touched by the widest access seen
    bool read;
    bool written;
    uint32_t hits;    // distinct instructions that touched it
  };
  // Layout of a class, reconstructed from the `this` accesses its virtual
  // methods perform. Field *names* do not exist in a C++ binary; offsets,
  // widths and access direction do.
  struct StructLayout {
    std::string name;
    uint64_t vtable_vaddr;
    uint64_t min_size;              // highest touched offset + its width
    std::vector<FieldAccess> fields;
  };
  static std::vector<StructLayout>
  recover_struct_layouts(const std::vector<uint8_t> &data,
                         uint64_t base_addr = 0);

  // Runs of consecutive pointers that all land on function entry points:
  // vtables, dispatch tables, il2cpp-style methodPointers arrays.
  struct PointerTable {
    uint64_t vaddr;
    size_t count;
    std::vector<uint64_t> targets; // module-relative, in table order
  };
  static std::vector<PointerTable>
  find_function_tables(const std::vector<uint8_t> &data,
                       uint64_t base_addr = 0,
                       bool *truncated = nullptr);

  struct ImportCall {
    uint64_t site;
    std::string symbol;
  };
  static std::vector<ImportCall>
  find_import_calls(const std::vector<uint8_t> &data,
                    uint64_t base_addr = 0);

  // Function entry points recovered from PT_GNU_EH_FRAME's binary-search
  // table. Works on fully stripped modules, where .dynsym is empty but unwind
  // data still describes every function. Returns virtual addresses, sorted.
  static std::vector<uint64_t>
  get_eh_frame_functions(const std::vector<uint8_t> &data);

  static std::string demangle_symbol(const std::string &mangled);
  static bool is_objc_method(const std::string &symbol);
  static std::pair<std::string, std::string>
  parse_objc_method(const std::string &sym);

  static std::vector<std::string>
  find_encrypted_strings(const std::vector<uint8_t> &data,
                         size_t max_input_bytes = 16U * 1024U * 1024U,
                         size_t max_results = 1024,
                         uint64_t deadline_ms = 5000,
                         bool *truncated = nullptr);

  static bool has_relro(const std::vector<uint8_t> &data);
  static bool has_full_relro(const std::vector<uint8_t> &data);
  static std::vector<uint64_t> get_init_array(const std::vector<uint8_t> &data);
  static std::vector<uint64_t> get_fini_array(const std::vector<uint8_t> &data);

  static std::vector<PatternMatch>
  pattern_scan(const std::vector<uint8_t> &data, const std::string &pattern);

  static std::string generate_signature(const std::vector<uint8_t> &data,
                                        uint64_t offset, size_t length = 32);

  static std::vector<uint64_t>
  get_vtable_functions(const std::vector<uint8_t> &data, uint64_t vtable_offset,
                       uint64_t base_addr = 0, size_t max_bytes = 0);

  static std::map<uint64_t, std::vector<uint64_t>>
  build_string_xref_map(const std::vector<uint8_t> &data,
                        uint64_t base_addr = 0,
                        size_t max_strings = 100000,
                        size_t max_xrefs = 100000,
                        size_t max_string_bytes = 16U * 1024U * 1024U,
                        bool *truncated = nullptr);

  static std::vector<DecryptResult>
  try_decrypt(const std::vector<uint8_t> &data, uint64_t offset, size_t length);

  static std::vector<DecryptResult>
  auto_decrypt_strings(const std::vector<uint8_t> &data);
  static std::vector<DecryptResult>
  auto_decrypt_strings(const std::vector<uint8_t> &data,
                       const AutoDecryptLimits &limits,
                       AutoDecryptStatus *status);

  static std::vector<uint8_t>
  find_encryption_key(const std::vector<uint8_t> &data,
                      uint64_t base_addr = 0);

  static double calculate_entropy(const uint8_t *data, size_t size);

  static std::vector<EntropyInfo>
  find_high_entropy_regions(const std::vector<uint8_t> &data,
                            size_t block_size = 256, double threshold = 7.0,
                            size_t max_results = 100000);

  static std::vector<AESKeyInfo>
  detect_aes_keys(const std::vector<uint8_t> &data);

};

class SoFixer {
public:
  static std::vector<uint8_t> repair(const std::vector<uint8_t> &data,
                                     uint64_t base_addr,
                                     const std::vector<uint8_t> *disk = nullptr);
};

class RuntimeAnalyzer {
public:
  static size_t trace_init_array(int pid, uint64_t base,
                                 const std::string &expected_name,
                                 const std::vector<uint8_t> &expected_image,
                                 const std::vector<uint64_t> &init_funcs);
  static std::string last_trace_status();
};
