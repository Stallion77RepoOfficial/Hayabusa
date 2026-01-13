#pragma once
#include <cstdint>
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
};

class SoFixer {
public:
  static std::vector<uint8_t> repair(const std::vector<uint8_t> &data,
                                     uint64_t base_addr);
};