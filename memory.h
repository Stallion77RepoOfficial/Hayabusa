#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct ModuleInfo {
  unsigned long base;
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
  static std::vector<uint8_t> dump(int pid, unsigned long addr, size_t size);
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
};

class SoFixer {
public:
  static std::vector<uint8_t> repair(const std::vector<uint8_t> &data,
                                     uint64_t base_addr);
};