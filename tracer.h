#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

enum class ArchMode { ARM32, ARM64 };

struct TracedRegion {
  uint64_t base;
  uint64_t size;
  std::vector<uint8_t> data;
  bool captured;
};

struct JITRegion {
  uint64_t addr;
  size_t size;
  std::vector<uint8_t> code;
};

struct RelinkEntry {
  uint64_t call_site;
  uint64_t target_addr;
  std::string symbol_name;
  std::vector<uint8_t> original_bytes;
};

class ProcessTracer {
public:
  static void set_arch(ArchMode mode);
  static ArchMode get_arch();
  static bool attach(int pid);
  static bool detach(int pid);
  static bool read_memory(int pid, uint64_t addr, void *buf, size_t len);
  static bool write_memory(int pid, uint64_t addr, const void *buf, size_t len);
  static bool set_protection(int pid, uint64_t addr, size_t len, int prot);
  static bool single_step(int pid);
  static bool continue_process(int pid);
  static bool wait_for_stop(int pid, int *status);
  static uint64_t get_register(int pid, int reg);
  static bool set_register(int pid, int reg, uint64_t val);
  static uint64_t get_pc(int pid);
  static std::vector<uint8_t> dump_on_demand(int pid, uint64_t base,
                                             size_t size, int duration_sec);
  static std::vector<JITRegion> capture_jit(int pid, int duration_sec);
};

class FunctionHooker {
public:
  static bool inject_library(int pid, const std::string &lib_path);
  static bool hook_function(int pid, uint64_t target, uint64_t hook,
                            uint64_t *original);
  static bool unhook_function(int pid, uint64_t target, uint64_t original);
  static uint64_t allocate_remote(int pid, size_t size);
  static bool free_remote(int pid, uint64_t addr, size_t size);
  static uint64_t find_remote_symbol(int pid, const std::string &lib,
                                     const std::string &sym);
};

class StaticRelinker {
public:
  static std::vector<uint8_t> relink(const std::vector<uint8_t> &elf_data,
                                     int pid, uint64_t base_addr);
  static std::vector<RelinkEntry>
  find_external_calls(const std::vector<uint8_t> &data, uint64_t base);
  static bool resolve_symbol(int pid, const std::string &name, uint64_t *addr);
  static std::vector<uint8_t> embed_function(int pid, uint64_t addr,
                                             size_t max_size);
};
