#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct ModuleInfo {
  uint64_t base;
  size_t size;
  std::string name;
  std::string perms;
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

struct PatternMatch {
  uint64_t offset;
  std::string pattern;
  std::string context;
};

struct RTTIInfo {
  uint64_t vtable_addr;
  uint64_t typeinfo_addr;
  std::string class_name;
  std::string demangled_name;
  std::vector<uint64_t> virtual_functions;
  uint64_t base_class_typeinfo;
};

struct StringXref {
  uint64_t string_offset;
  std::string string_value;
  std::vector<uint64_t> references;
  std::string ref_type;
};

struct DecryptResult {
  uint64_t offset;
  std::vector<uint8_t> original;
  std::vector<uint8_t> decrypted;
  std::string method;
  uint8_t key_or_info[32];
  size_t key_size;
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

struct HeuristicFunction {
  uint64_t start_addr;
  uint64_t end_addr;
  size_t size;
  bool has_prologue;
  bool has_epilogue;
  int stack_frame_size;
  std::vector<uint64_t> call_targets;
};

class Memory {
public:
  static std::vector<ModuleInfo> get_maps(int pid);
  static std::vector<uint8_t> dump(int pid, uint64_t addr, size_t size);
};

class Utils {
public:
  static int get_pid(const std::string &pkg);
  static std::vector<std::string> get_apk_paths(const std::string &pkg);
  static void launch_app(const std::string &pkg);
  static std::string format_size(size_t bytes);
};

class ElfParser {
public:
  static bool is_elf(const std::string &path);
  static bool is_elf(const std::vector<uint8_t> &data);
  static bool is_elf32(const std::vector<uint8_t> &data);
  static std::vector<ElfSymbol> get_symbols(const std::vector<uint8_t> &data);
  static std::vector<ElfString> get_strings(const std::vector<uint8_t> &data,
                                            size_t min_len);

  struct PltEntry {
    uint64_t offset;
    uint64_t got_offset;
    std::string symbol_name;
    uint32_t symbol_index;
  };
  static std::vector<PltEntry>
  get_plt_entries(const std::vector<uint8_t> &data);
  static uint64_t resolve_plt_symbol(int pid, const std::vector<uint8_t> &data,
                                     const std::string &symbol_name);

  static std::string demangle_symbol(const std::string &mangled);
  static bool is_objc_method(const std::string &symbol);
  static std::pair<std::string, std::string>
  parse_objc_method(const std::string &sym);

  static std::vector<std::string>
  find_encrypted_strings(const std::vector<uint8_t> &data);

  static bool has_relro(const std::vector<uint8_t> &data);
  static bool has_full_relro(const std::vector<uint8_t> &data);
  static std::pair<uint64_t, uint64_t>
  get_tls_range(const std::vector<uint8_t> &data);
  static std::vector<uint64_t> get_init_array(const std::vector<uint8_t> &data);
  static std::vector<uint64_t> get_fini_array(const std::vector<uint8_t> &data);

  static std::vector<PatternMatch>
  pattern_scan(const std::vector<uint8_t> &data, const std::string &pattern);

  static std::vector<PatternMatch>
  pattern_scan_multi(const std::vector<uint8_t> &data,
                     const std::vector<std::string> &patterns);

  static std::string generate_signature(const std::vector<uint8_t> &data,
                                        uint64_t offset, size_t length = 32);

  static std::vector<RTTIInfo> scan_rtti(const std::vector<uint8_t> &data,
                                         uint64_t base_addr = 0);

  static RTTIInfo find_vtable_by_name(const std::vector<uint8_t> &data,
                                      const std::string &class_name,
                                      uint64_t base_addr = 0);

  static std::vector<uint64_t>
  get_vtable_functions(const std::vector<uint8_t> &data, uint64_t vtable_offset,
                       uint64_t base_addr = 0);

  static StringXref find_string_xrefs(const std::vector<uint8_t> &data,
                                      const std::string &str,
                                      uint64_t base_addr = 0);

  static std::vector<StringXref>
  find_string_xrefs_pattern(const std::vector<uint8_t> &data,
                            const std::string &pattern, uint64_t base_addr = 0);

  static std::map<uint64_t, std::vector<uint64_t>>
  build_string_xref_map(const std::vector<uint8_t> &data,
                        uint64_t base_addr = 0);

  static std::vector<DecryptResult>
  try_decrypt(const std::vector<uint8_t> &data, uint64_t offset, size_t length);

  static std::vector<uint8_t> decrypt_xor(const std::vector<uint8_t> &data,
                                          const std::vector<uint8_t> &key);

  static std::vector<uint8_t> decrypt_rc4(const std::vector<uint8_t> &data,
                                          const std::vector<uint8_t> &key);

  static std::vector<DecryptResult>
  auto_decrypt_strings(const std::vector<uint8_t> &data);

  static std::vector<uint8_t>
  find_encryption_key(const std::vector<uint8_t> &data);

  static double calculate_entropy(const uint8_t *data, size_t size);

  static std::vector<EntropyInfo>
  find_high_entropy_regions(const std::vector<uint8_t> &data,
                            size_t block_size = 256, double threshold = 7.0);

  static std::vector<AESKeyInfo>
  detect_aes_keys(const std::vector<uint8_t> &data);

  static std::vector<HeuristicFunction>
  find_functions_stripped(const std::vector<uint8_t> &data,
                          uint64_t base_addr = 0);

  static std::vector<RTTIInfo>
  scan_vtables_stripped(const std::vector<uint8_t> &data,
                        uint64_t base_addr = 0);

  static std::vector<StringXref>
  find_all_string_xrefs(const std::vector<uint8_t> &data,
                        uint64_t base_addr = 0);
};

class SoFixer {
public:
  static std::vector<uint8_t> repair(const std::vector<uint8_t> &data,
                                     uint64_t base_addr);
};

class RuntimeAnalyzer {
public:
  static std::vector<uint8_t> read_decrypted(int pid, uint64_t addr,
                                             size_t size);

  static std::vector<std::pair<uint64_t, size_t>>
  find_decrypted_regions(int pid, uint64_t base,
                         const std::vector<uint8_t> &disk_data);

  static bool trace_init_array(int pid, uint64_t base,
                               const std::vector<uint64_t> &init_funcs);

  static std::vector<uint8_t> dump_after_function(int pid, uint64_t func_addr,
                                                  uint64_t target_addr,
                                                  size_t size);

  static std::vector<uint64_t> find_instances_by_vtable(int pid,
                                                        uint64_t vtable_addr);
};
