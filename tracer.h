#pragma once
#include "memory.h"
#include <cstdint>
#include <elf.h>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

// AArch64 only. The primary template is left undefined on purpose: any
// leftover reference to a 32-bit variant becomes a compile error rather than
// silently taking an untested path.
template <int Bits> struct ElfTypes;

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
  static constexpr int R_RELATIVE = 1027;  // R_AARCH64_RELATIVE
  static constexpr int R_JUMP_SLOT = 1026; // R_AARCH64_JUMP_SLOT
  // AArch64 uses RELA (explicit addend field).
  using RelType = Elf64_Rela;
  static constexpr bool HAS_ADDEND = true;
  static constexpr int SHT_REL_TYPE = 4; // SHT_RELA
  static constexpr int DT_REL_TAG = DT_RELA;
  static constexpr int DT_RELSZ_TAG = DT_RELASZ;
  static constexpr int DT_RELENT_TAG = DT_RELAENT;
  static constexpr const char *REL_DYN_NAME = ".rela.dyn";
  static constexpr const char *REL_PLT_NAME = ".rela.plt";
  static constexpr uint64_t DYN_ENTSIZE = 16;
  static constexpr uint64_t PLT_ALIGN = 16;
  static constexpr uint64_t PLT_HEADER_SIZE = 32;
  static constexpr uint64_t PLT_ENTRY_SIZE = 16;
  static inline uint8_t ST_TYPE(uint8_t info) { return ELF64_ST_TYPE(info); }
  static inline uint8_t ST_BIND(uint8_t info) { return ELF64_ST_BIND(info); }
  static inline uint8_t ST_INFO(uint8_t b, uint8_t t) {
    return ELF64_ST_INFO(b, t);
  }
  static inline uint64_t R_SYM(uint64_t info) { return ELF64_R_SYM(info); }
  static inline uint64_t R_TYPE(uint64_t info) { return ELF64_R_TYPE(info); }
};

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
  int64_t immediate;
  uint8_t rd;
  uint8_t rm;
  bool is_return;
  bool is_call;
  bool is_indirect;
  uint64_t target_address;
};

enum class SyscallStopKind {
  Unknown,
  Entry,
  Exit,
};

enum class SignalStopKind {
  Delivery,
  GroupStop,
  Unknown,
};

enum class PatchSupervisionResult {
  Stopped,
  GroupStopped,
  TargetGone,
  Failed,
};

struct SyscallStopInfo {
  SyscallStopKind kind = SyscallStopKind::Unknown;
  uint64_t number = 0;
  uint64_t args[6] = {0};
  int64_t return_value = 0;
  bool is_error = false;
};

// A code write may fail after touching the tracee. Temporary-patch callers
// must distinguish that dangerous state from a write that provably changed
// nothing.
enum class ExecutableWriteResult {
  NotWritten,
  WrittenVerified,
  StateUnknown,
};

struct CallInfo {
  uint64_t call_site_offset;
  uint64_t target_address;
  std::string symbol_name;
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
  size_t total_embedded_size;
  int current_depth;
};

namespace InstructionDecoder {

DecodedInstruction decode(uint32_t inst, uint64_t address);

bool is_function_end(const uint8_t *code, size_t offset, size_t size);
size_t find_function_end(const uint8_t *code, size_t max_size);

std::vector<CallInfo> scan_calls(const uint8_t *code, size_t size,
                                 uint64_t base);

uint64_t resolve_plt(int pid, uint64_t plt_addr);

} // namespace InstructionDecoder

class ProcessTracer {
public:
  // Attaches to every thread of the target, not only the group leader.
  static bool attach(int pid);
  static bool detach(int pid);
  // Enumerate every visible thread. The status-returning form is fail-closed:
  // an unreadable or empty /proc/<pid>/task is never treated as {pid}.
  static bool list_threads_complete(int pid, std::vector<int> *out);
  static std::vector<int> list_threads(int pid);
  static bool read_thread_group_id(int tid, int *tgid);
  static bool read_memory(int pid, uint64_t addr, void *buf, size_t len);
  static bool write_memory(int pid, uint64_t addr, const void *buf, size_t len);
  static bool continue_process(int pid, int signal = 0);
  // Stop a seized tracee with PTRACE_EVENT_STOP and no target-visible signal.
  static bool interrupt(int tid);
  static bool get_syscall(int pid, uint64_t *nr, uint64_t *args, size_t n);
  static bool get_syscall_stop(int pid, SyscallStopInfo *info);
  static bool syscall_step(int pid, int signal = 0);
  static bool follow_children(int pid);
  // Trace CLONE/FORK/VFORK events during short-lived patch transactions.
  static bool follow_thread_clones(int tid);
  // Disable ptrace event generation after every seized tracee has reached a
  // verified quiescent stop, before a short-lived patch transaction detaches.
  static bool clear_trace_options(int tid);
  // Classify a job-control stop. `event` is the wait-status ptrace event;
  // seized PTRACE_EVENT_STOP reports group-stop state differently from legacy
  // ATTACH and cannot be inferred from GETSIGINFO/EINVAL alone.
  static SignalStopKind classify_signal_stop(int tid, int signal,
                                             unsigned event = 0);
  // Record a kernel-auto-attached thread child so verified detach/recovery
  // owns it together with the original thread group.
  static bool adopt_attached_thread(int tgid, int tid);
  // Claim a TRACEFORK/VFORK/CLONE child only after waitpid has reported its
  // kernel-generated initial ptrace stop. Threads in the original group are
  // adopted into that lease; process leaders receive an exact pidfd; threads
  // in a descendant group are accepted only while that group's leader pidfd
  // is already tracked. `tracee_tgid` and `original_group` are written only
  // after the complete ownership claim succeeds.
  static bool claim_auto_attached_tracee(int original_tgid, int tid,
                                         int *tracee_tgid,
                                         bool *original_group);
  // Record a separate-process child inherited through TRACEFORK/VFORK/CLONE.
  // Fatal signal cleanup kills every recorded child while temporary code may
  // still exist in its copied address space.
  static bool track_auto_attached_child(int child);
  static void untrack_auto_attached_child(int child);
  // Forget the per-TID fatal-cleanup slot after a verified descendant thread
  // has exited or detached. This deliberately leaves the descendant leader's
  // pidfd tracked until the caller has released the whole thread group.
  static void forget_auto_attached_tracee(int tgid, int tid);
  // Release a separately tracked child whose initial ptrace stop was already
  // consumed. The optional signal preserves a genuine signal-delivery stop.
  // Set `release_group` false while other TIDs in the descendant group remain;
  // the caller must untrack the group leader after releasing the final member.
  static bool release_auto_attached_child(int child, int signal = 0,
                                          int tgid = 0,
                                          bool release_group = true);
  static bool event_child(int pid, int *child);
  static bool get_pc(int pid, uint64_t *pc);
  static bool set_pc(int pid, uint64_t pc);
  static std::vector<MapEntry> get_library_ranges(int pid);
  // Marks a period in which detaching a live tracee would resume patched
  // instructions. Fatal cleanup kills that target instead.
  static bool begin_patch_transaction(int pid);
  static void end_patch_transaction(int pid);
  // Run every seized thread without detaching it while temporary code is live.
  // Fork/vfork children are terminally contained before they can execute a
  // copied patch; thread clones remain traced. On a non-terminal return every
  // surviving parent thread is stopped and still owned by this tracer.
  static PatchSupervisionResult supervise_patch_target(
      int pid, const std::function<bool()> &keep_running,
      const std::function<void()> &on_tick = {});
  // Detach every still-attached tracee. Safe to call from a terminating signal
  // path; PTRACE_DETACH resumes ptrace-stopped tasks without destroying a real
  // job-control stop.
  static void cleanup_all_attached();
  // Terminal normal-context fallback for an auto-attached child whose exact
  // identity could not be published or released. Kills every task still
  // ptrace-owned by this tracer after draining the signal-safe registries.
  static void terminal_drain_owned_tracees();
  // Normal-context retry for one tracee. Collapses stale nested refs before
  // invoking the verified detach path; unlike cleanup_all_attached(), this
  // keeps refcount bookkeeping coherent when the process continues running.
  static bool recover_attached(int pid);
  // Last-resort normal-context bookkeeping reset after every verified detach
  // retry failed and the tracee is being terminated.
  static void reset_attach_bookkeeping();
  // Deliver one pending target signal to its exact TID only after temporary
  // code has been restored. The group refcount remains owned by detach().
  static bool detach_thread_with_signal(int tgid, int tid, int signal);
  static std::string
  find_library_for_address(const std::vector<MapEntry> &ranges, uint64_t addr);
};

struct RemoteCallResult;

class FunctionHooker {
public:
  static RemoteCallResult inject_library(int pid, const std::string &lib_path);
  static uint64_t allocate_remote(int pid, size_t size);
  static bool free_remote(int pid, uint64_t addr, size_t size);
  static uint64_t find_remote_symbol(int pid, const std::string &lib,
                                     const std::string &sym);
};

class StaticRelinker {
public:
  static std::vector<uint8_t> embed_function(int pid, uint64_t addr,
                                             size_t max_size = 0);
  static bool resolve_symbol(int pid, const std::string &name, uint64_t *addr);
  static std::vector<RelinkEntry>
  find_external_calls(const std::vector<uint8_t> &data, uint64_t base);
};

struct RemoteCallResult {
  uint64_t return_value = 0;
  bool success = false;
  // True means recovery proved that the process exited or deliberately killed
  // it fail-closed. Callers must not issue another ptrace/memory operation for
  // this PID; it may already have been recycled.
  bool target_gone = false;
  // A completed call raced a genuine job-control stop. The call result is
  // valid, but follow-up remote syscalls must be skipped so detach(0) preserves
  // the owner's stopped state.
  bool target_group_stopped = false;
  std::string error_message;
};

struct RemoteStringResult {
  std::string value;
  bool success = false;
  bool target_gone = false;
  bool target_group_stopped = false;
  std::string error_message;
};

struct HookInfo {
  uint64_t target_addr;
  uint64_t trampoline_addr;
  std::vector<uint8_t> original_bytes;
  size_t patch_size;
  bool active;
  std::string error; // why install failed, when it did
};

// An installed logging hook: the stub bumps a counter and records the first
// four integer arguments of the first 8 calls, then falls through to the
// relocated original code.
struct LoggingHook {
  HookInfo info;
  uint64_t stub_addr;
  size_t stub_size;
  uint64_t record_addr;
  static constexpr size_t SLOTS = 8;
};

struct CallRecord {
  uint64_t args[4];
};

class MemoryInjector {
public:
  static RemoteCallResult call_remote(int pid, uint64_t func_addr,
                                      const std::vector<uint64_t> &args);

  static RemoteCallResult remote_dlopen(int pid, const std::string &path,
                                        int flags);
  static RemoteStringResult remote_dlerror(int pid);

  static bool install_inline_hook(int pid, uint64_t target, uint64_t hook,
                                  HookInfo *info);
  static bool remove_inline_hook(int pid, const HookInfo &info);

  static bool install_logging_hook(int pid, uint64_t target, LoggingHook *out);
  static bool remove_logging_hook(int pid, const LoggingHook &hook);
  // Returns total call count; fills `out` with up to LoggingHook::SLOTS records.
  static uint64_t read_logging_hook(int pid, const LoggingHook &hook,
                                    std::vector<CallRecord> *out);

  // Overwrite a function with an immediate `ret`. `target` must be a 4-byte
  // aligned AArch64 entry point; anything else is rejected.
  static ExecutableWriteResult
  stub_out_function(int pid, uint64_t target,
                    std::vector<uint8_t> *original);
  static bool restore_function(int pid, uint64_t target,
                               const std::vector<uint8_t> &original);
  // Verified ptrace text write with AArch64 instruction-cache coherency.
  static ExecutableWriteResult
  write_executable_checked(int pid, uint64_t target, const void *data,
                           size_t size);
  static bool write_executable(int pid, uint64_t target, const void *data,
                               size_t size);

  static uint64_t find_linker_function(int pid, const std::string &func_name);
  static std::string read_string_remote(int pid, uint64_t addr, size_t max_len);
};

struct RelinkConfig {
  int max_depth;
  size_t max_total_size;
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
                                const std::map<uint64_t, uint64_t> &addr_map,
                                uint64_t base_addr);
};

struct CryptoKeyInfo {
  uint64_t key_addr;
  std::vector<uint8_t> key_data;
  std::string algorithm;
  std::string source;
  double confidence;
};

enum class CryptoHookResult {
  NotFound,
  SafeFailure,
  Installed,
  StateUnknown,
};

struct CryptoRestoreResult {
  size_t restored = 0;
  size_t remaining = 0;

  bool all_clean() const { return remaining == 0; }
};

class CryptoAnalyzer {
public:
  static std::vector<CryptoKeyInfo>
  scan_for_keys(const std::vector<uint8_t> &data, uint64_t base_addr);

  static CryptoHookResult hook_aes_encrypt(int pid, uint64_t *original);
  static CryptoHookResult hook_aes_decrypt(int pid, uint64_t *original);
  static CryptoRestoreResult restore_aes_hooks(int pid);
};
