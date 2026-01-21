#pragma once
#include <cstdint>
#include <elf.h>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

template <int Bits> struct ElfTypes;

template <> struct ElfTypes<32> {
  using Ehdr = Elf32_Ehdr;
  using Phdr = Elf32_Phdr;
  using Shdr = Elf32_Shdr;
  using Sym = Elf32_Sym;
  using Dyn = Elf32_Dyn;
  using Rel = Elf32_Rel;
  using Rela = Elf32_Rela;
  using Addr = uint32_t;
  static constexpr size_t WORD_SIZE = 4;
  static constexpr uint8_t ELFCLASS = ELFCLASS32;
  static constexpr uint16_t EM_ARCH = EM_ARM;
  static constexpr int R_RELATIVE = 23;
  static constexpr int R_JUMP_SLOT = 22;
  static inline uint8_t ST_TYPE(uint8_t info) { return ELF32_ST_TYPE(info); }
  static inline uint8_t ST_BIND(uint8_t info) { return ELF32_ST_BIND(info); }
  static inline uint8_t ST_INFO(uint8_t b, uint8_t t) {
    return ELF32_ST_INFO(b, t);
  }
  static inline uint32_t R_SYM(uint32_t info) { return ELF32_R_SYM(info); }
  static inline uint32_t R_TYPE(uint32_t info) { return ELF32_R_TYPE(info); }
};

template <> struct ElfTypes<64> {
  using Ehdr = Elf64_Ehdr;
  using Phdr = Elf64_Phdr;
  using Shdr = Elf64_Shdr;
  using Sym = Elf64_Sym;
  using Dyn = Elf64_Dyn;
  using Rel = Elf64_Rel;
  using Rela = Elf64_Rela;
  using Addr = uint64_t;
  static constexpr size_t WORD_SIZE = 8;
  static constexpr uint8_t ELFCLASS = ELFCLASS64;
  static constexpr uint16_t EM_ARCH = 183;
  static constexpr int R_RELATIVE = 1027;
  static constexpr int R_JUMP_SLOT = 1026;
  static inline uint8_t ST_TYPE(uint8_t info) { return ELF64_ST_TYPE(info); }
  static inline uint8_t ST_BIND(uint8_t info) { return ELF64_ST_BIND(info); }
  static inline uint8_t ST_INFO(uint8_t b, uint8_t t) {
    return ELF64_ST_INFO(b, t);
  }
  static inline uint64_t R_SYM(uint64_t info) { return ELF64_R_SYM(info); }
  static inline uint64_t R_TYPE(uint64_t info) { return ELF64_R_TYPE(info); }
};

enum class ArchMode { ARM32, ARM64 };

enum class InstructionType {
  Unknown,
  Branch,
  BranchLink,
  BranchRegister,
  Return,
  Load,
  Store,
  Adrp,
  Add,
  ConditionalBranch,
  Other
};

struct DecodedInstruction {
  InstructionType type;
  uint32_t raw;
  uint64_t address;
  int64_t immediate;
  uint8_t rd;
  uint8_t rn;
  uint8_t rm;
  bool is_return;
  bool is_call;
  bool is_indirect;
  uint64_t target_address;
};

struct CallInfo {
  uint64_t call_site_offset;
  uint64_t target_address;
  uint64_t resolved_address;
  std::string symbol_name;
  bool is_plt_call;
  bool is_external;
};

struct RelinkEntry {
  uint64_t call_site;
  uint64_t target_addr;
  std::string symbol_name;
};

struct EmbedContext {
  int pid;
  uint64_t base_addr;
  std::string self_library;
  std::set<uint64_t> embedded_addresses;
  std::map<uint64_t, uint64_t> address_to_offset;
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> pending_embeds;
  size_t total_embedded_size;
  int current_depth;
  static constexpr int MAX_DEPTH = 4;
  static constexpr size_t MAX_TOTAL_SIZE = 16 * 1024 * 1024;
};

struct LibraryRange {
  uint64_t start;
  uint64_t end;
  std::string name;
};

namespace InstructionDecoder {

DecodedInstruction decode_arm64(uint32_t inst, uint64_t address);
DecodedInstruction decode_arm32(uint32_t inst, uint64_t address);
DecodedInstruction decode(uint32_t inst, uint64_t address, ArchMode arch);

bool is_function_end_arm64(const uint8_t *code, size_t offset, size_t size);
bool is_function_end_arm32(const uint8_t *code, size_t offset, size_t size);
size_t find_function_end(const uint8_t *code, size_t max_size, ArchMode arch);

std::vector<CallInfo> scan_calls_arm64(const uint8_t *code, size_t size,
                                       uint64_t base);
std::vector<CallInfo> scan_calls_arm32(const uint8_t *code, size_t size,
                                       uint64_t base);
std::vector<CallInfo> scan_calls(const uint8_t *code, size_t size,
                                 uint64_t base, ArchMode arch);

uint64_t resolve_plt_arm64(int pid, uint64_t plt_addr);
uint64_t resolve_plt_arm32(int pid, uint64_t plt_addr);
uint64_t resolve_plt(int pid, uint64_t plt_addr, ArchMode arch);

}

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
  static std::vector<LibraryRange> get_library_ranges(int pid);
  static std::string
  find_library_for_address(const std::vector<LibraryRange> &ranges,
                           uint64_t addr);
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
  static std::vector<uint8_t> embed_function(int pid, uint64_t addr,
                                             size_t max_size = 0);
  static void recursive_embed(EmbedContext &ctx, uint64_t addr);
  static bool resolve_symbol(int pid, const std::string &name, uint64_t *addr);
  static std::vector<RelinkEntry>
  find_external_calls(const std::vector<uint8_t> &data, uint64_t base);
};

class ZygoteTracer {
public:
  static int find_zygote_pid();
  static bool attach_zygote(int zygote_pid);
  static int wait_for_fork(int zygote_pid, const std::string &target_pkg);
  static bool intercept_dlopen(int pid);

  static void register_attached_pid(int pid);
  static void unregister_attached_pid(int pid);
  static void cleanup_all_attached();
  static std::set<int> &get_attached_pids();
};

struct RemoteCallResult {
  uint64_t return_value;
  bool success;
  int error_code;
  std::string error_message;
};

struct HookInfo {
  uint64_t target_addr;
  uint64_t hook_addr;
  uint64_t trampoline_addr;
  std::vector<uint8_t> original_bytes;
  size_t patch_size;
  bool active;
};

struct ShellcodeInfo {
  uint64_t code_addr;
  uint64_t data_addr;
  size_t code_size;
  size_t data_size;
};

class MemoryInjector {
public:
  static uint64_t remote_mmap(int pid, uint64_t addr, size_t size, int prot,
                              int flags);
  static bool remote_munmap(int pid, uint64_t addr, size_t size);
  static bool remote_mprotect(int pid, uint64_t addr, size_t size, int prot);

  static RemoteCallResult call_remote(int pid, uint64_t func_addr,
                                      const std::vector<uint64_t> &args);
  static RemoteCallResult call_remote_void(int pid, uint64_t func_addr,
                                           const std::vector<uint64_t> &args);

  static uint64_t remote_dlopen(int pid, const std::string &path, int flags);
  static uint64_t remote_dlsym(int pid, uint64_t handle,
                               const std::string &symbol);
  static bool remote_dlclose(int pid, uint64_t handle);
  static std::string remote_dlerror(int pid);

  static bool inject_shellcode(int pid, const std::vector<uint8_t> &shellcode,
                               uint64_t *exec_addr);
  static bool inject_and_run_shellcode(int pid,
                                       const std::vector<uint8_t> &shellcode,
                                       uint64_t *result);
  static std::vector<uint8_t>
  generate_shellcode_arm64(uint64_t func_addr,
                           const std::vector<uint64_t> &args);
  static std::vector<uint8_t>
  generate_shellcode_arm32(uint64_t func_addr,
                           const std::vector<uint64_t> &args);
  static std::vector<uint8_t>
  generate_dlopen_shellcode_arm64(const std::string &lib_path);
  static std::vector<uint8_t>
  generate_dlopen_shellcode_arm32(const std::string &lib_path);

  static bool install_inline_hook(int pid, uint64_t target, uint64_t hook,
                                  HookInfo *info);
  static bool remove_inline_hook(int pid, const HookInfo &info);
  static bool hook_got_entry(int pid, uint64_t got_addr, uint64_t new_value,
                             uint64_t *old_value);
  static bool hook_plt_entry(int pid, uint64_t base, const std::string &symbol,
                             uint64_t hook);

  static uint64_t find_got_entry(int pid, uint64_t base,
                                 const std::string &symbol);
  static std::vector<std::pair<std::string, uint64_t>>
  dump_got(int pid, uint64_t base, const std::vector<uint8_t> &elf_data);

  static std::vector<std::pair<std::string, uint64_t>>
  find_jni_functions(int pid, const std::string &lib_name);
  static bool hook_jni_function(int pid, uint64_t jni_func, uint64_t hook,
                                uint64_t *original);

  static uint64_t find_libc_function(int pid, const std::string &func_name);
  static uint64_t find_linker_function(int pid, const std::string &func_name);
  static bool write_string_remote(int pid, uint64_t addr,
                                  const std::string &str);
  static std::string read_string_remote(int pid, uint64_t addr, size_t max_len);
};

struct SeccompInfo {
  bool seccomp_enabled;
  int seccomp_mode;
  uint64_t filter_count;
  std::string filter_flags;
};

class SeccompBypass {
public:
  static SeccompInfo get_seccomp_status(int pid);

  static bool disable_seccomp(int pid);
  static bool patch_seccomp_filter(int pid);
  static bool use_memfd_workaround(int pid);

  static int spawn_without_seccomp(const std::string &cmd);
  static bool inject_seccomp_disabler(int pid);
};

struct RelinkConfig {
  int max_depth;
  size_t max_total_size;
  bool embed_data_refs;
  bool fix_relocations;
  bool inline_plt_calls;
  std::set<std::string> exclude_libs;
  std::set<std::string> include_only_libs;
};

class StaticRelinkerEx {
public:
  static std::vector<uint8_t> relink_full(const std::vector<uint8_t> &elf_data,
                                          int pid, uint64_t base_addr,
                                          const RelinkConfig &config);

  static std::vector<uint8_t> extract_function_with_deps(int pid, uint64_t addr,
                                                         int max_depth = 8);

  static bool patch_relocations(std::vector<uint8_t> &data,
                                const std::map<uint64_t, uint64_t> &addr_map);
};

struct CryptoKeyInfo {
  uint64_t key_addr;
  std::vector<uint8_t> key_data;
  std::string algorithm;
  std::string source;
  double confidence;
  time_t capture_time;
};

struct CryptoCallInfo {
  uint64_t func_addr;
  std::string func_name;
  std::vector<uint8_t> input_data;
  std::vector<uint8_t> output_data;
  std::vector<uint8_t> key_data;
  std::vector<uint8_t> iv_data;
};

class CryptoAnalyzer {
public:
  static std::vector<CryptoKeyInfo>
  scan_for_keys(const std::vector<uint8_t> &data, uint64_t base_addr);

  static std::vector<CryptoKeyInfo>
  extract_runtime_keys(int pid, uint64_t base,
                       const std::vector<uint8_t> &data);
  static std::vector<CryptoKeyInfo> trace_key_derivation(int pid,
                                                         uint64_t crypto_func);

  static std::vector<CryptoCallInfo> monitor_crypto_calls(int pid,
                                                          int duration_sec);

  static std::vector<uint8_t> dump_ssl_session_keys(int pid);
  static std::vector<CryptoKeyInfo> extract_openssl_keys(int pid);
  static std::vector<CryptoKeyInfo> extract_boringssl_keys(int pid);

  static bool hook_aes_encrypt(int pid, uint64_t *original);
  static bool hook_aes_decrypt(int pid, uint64_t *original);
};
