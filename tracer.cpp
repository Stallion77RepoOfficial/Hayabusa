#include "tracer.h"
#include "memory.h"
#include "rizin_bridge.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <iterator>
#include <linux/ptrace.h>
#include <limits>
#include <mutex>
#include <set>
#include <signal.h>
#include <sstream>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" {
long ptrace(int request, ...);
ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov,
                         unsigned long liovcnt, const struct iovec *remote_iov,
                         unsigned long riovcnt, unsigned long flags);
ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov,
                          unsigned long liovcnt, const struct iovec *remote_iov,
                          unsigned long riovcnt, unsigned long flags);
}

#define PTRACE_PEEKDATA 2
#define PTRACE_POKEDATA 5
#define PTRACE_DETACH 17
#define PTRACE_CONT 7
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define PTRACE_SEIZE 0x4206
#define PTRACE_INTERRUPT 0x4207
#ifndef PTRACE_GETEVENTMSG
#define PTRACE_GETEVENTMSG 0x4201
#endif
#define NT_PRSTATUS 1
#ifndef NT_FPREGSET
#define NT_FPREGSET 2
#endif
// Keep these local fallbacks: older Android NDK UAPI headers omit the arm64
// scalable-vector notes even when the device kernel implements them.
#ifndef NT_ARM_SVE
#define NT_ARM_SVE 0x405
#endif
#ifndef NT_ARM_TLS
#define NT_ARM_TLS 0x401
#endif
#ifndef NT_ARM_SYSTEM_CALL
#define NT_ARM_SYSTEM_CALL 0x404
#endif
#ifndef NT_ARM_PACA_KEYS
#define NT_ARM_PACA_KEYS 0x407
#endif
#ifndef NT_ARM_PACG_KEYS
#define NT_ARM_PACG_KEYS 0x408
#endif
#ifndef NT_ARM_TAGGED_ADDR_CTRL
#define NT_ARM_TAGGED_ADDR_CTRL 0x409
#endif
#ifndef NT_ARM_PAC_ENABLED_KEYS
#define NT_ARM_PAC_ENABLED_KEYS 0x40a
#endif
#ifndef NT_ARM_SSVE
#define NT_ARM_SSVE 0x40b
#endif
#ifndef NT_ARM_ZA
#define NT_ARM_ZA 0x40c
#endif
#ifndef NT_ARM_ZT
#define NT_ARM_ZT 0x40d
#endif
#ifndef NT_ARM_FPMR
#define NT_ARM_FPMR 0x40e
#endif
#ifndef NT_ARM_POE
#define NT_ARM_POE 0x40f
#endif
#ifndef NT_ARM_GCS
#define NT_ARM_GCS 0x410
#endif
#ifndef TRAP_BRKPT
#define TRAP_BRKPT 1
#endif
#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

struct HayabusaPtraceSyscallEntry {
  uint64_t nr;
  uint64_t args[6];
};

struct HayabusaPtraceSyscallExit {
  int64_t rval;
  uint8_t is_error;
};

struct HayabusaPtraceSyscallInfo {
  uint8_t op;
  uint8_t pad[3];
  uint32_t arch;
  uint64_t instruction_pointer;
  uint64_t stack_pointer;
  union {
    HayabusaPtraceSyscallEntry entry;
    HayabusaPtraceSyscallExit exit;
  } payload;
};
static_assert(offsetof(HayabusaPtraceSyscallInfo, payload) == 24);
static_assert(sizeof(HayabusaPtraceSyscallInfo) == 80);

static constexpr uint8_t kSyscallInfoEntry = 1;
static constexpr uint8_t kSyscallInfoExit = 2;
static constexpr unsigned kPtraceEventFork = 1;
static constexpr unsigned kPtraceEventVfork = 2;
static constexpr unsigned kPtraceEventClone = 3;
static constexpr unsigned kPtraceEventStop = 128;
using AttachDeadline = std::chrono::steady_clock::time_point;

// Every thread we successfully PTRACE_SEIZE lands in g_attached so that a
// crash or signal can still detach and resume the tracee instead of leaving it
// stopped forever.
//
// This is a fixed array of atomics rather than a std::map behind a mutex on
// purpose: cleanup_all_attached() runs from a signal handler, which can
// interrupt a thread that already holds the lock, and because the handler calls
// _exit() straight afterwards such a deadlock would hang the tool permanently.
// Plain int atomics are lock-free on AArch64 and need no allocation, so the
// handler can walk this table without taking anything. g_attach_mu below
// serialises writers only; the handler never touches it.
//
// ptrace() and kill() are thin syscall wrappers with no userspace state, so
// calling them from the handler is safe even though POSIX does not list them.
static constexpr size_t kMaxAttachedThreads = 4096;
// Keep ownership and payload in one lock-free word. Two atomics allow an ABA
// race: a signal handler can clear `tgid`, a new attach can reuse the slot, and
// then the handler can accidentally consume/detach the new `tid`.
struct AttachedThread {
  std::atomic<uint64_t> state{0}; // high=tgid, low=tid; zero marks the slot free
};
static_assert(std::atomic<uint64_t>::is_always_lock_free);
static AttachedThread g_attached[kMaxAttachedThreads];
// A fork/vfork child can hold a private copy of temporary text patches without
// belonging to the original thread group. Keep a second fixed, signal-safe
// ownership table so fatal cleanup never detaches such a child into a BRK.
// Pack child PID and its pidfd into one CAS-owned word. Fatal cleanup can then
// signal the exact kernel task even after the numeric PID has been recycled,
// without racing a separate descriptor atomic.
static std::atomic<uint64_t> g_patch_children[kMaxAttachedThreads];
static_assert(std::atomic<uint64_t>::is_always_lock_free);
static std::mutex g_patch_child_mu;
static std::map<int, uint64_t> g_patch_child_tokens;
static constexpr int kFatalCleanupStarted = -1;
static constexpr int kDangerousTransactionPreparing = -2;
static constexpr int kDangerousTransactionRetiring = -3;
static std::atomic<int> g_active_patch_tgid{0};
static std::atomic<int> g_active_tracee_pidfd{-1};
static std::atomic<uint64_t> g_active_patch_generation{0};
static std::atomic<uint64_t> g_patch_generation_counter{0};
static_assert(std::atomic<int>::is_always_lock_free);
static_assert(std::atomic<uint64_t>::is_always_lock_free);
static thread_local int g_dangerous_transaction_depth = 0;
static thread_local int g_dangerous_transaction_tgid = 0;
static thread_local uint64_t g_dangerous_transaction_generation = 0;

static uint64_t attached_state(int tgid, int tid) {
  return (uint64_t(static_cast<uint32_t>(tgid)) << 32) |
         uint32_t(tid);
}

static int attached_tgid(uint64_t state) {
  return static_cast<int>(state >> 32);
}

static int attached_tid(uint64_t state) {
  return static_cast<int>(state & 0xffffffffu);
}

static uint64_t patch_child_state(int child, int pidfd) {
  return (uint64_t(static_cast<uint32_t>(child)) << 32) |
         (static_cast<uint32_t>(pidfd) + 1u);
}

static int patch_child_pid(uint64_t state) {
  return static_cast<int>(state >> 32);
}

static int patch_child_pidfd(uint64_t state) {
  const uint32_t encoded = static_cast<uint32_t>(state);
  return encoded == 0 ? -1 : static_cast<int>(encoded - 1u);
}

// Per-process attach refcount, so nested attach/detach pairs do not resume a
// tracee another caller is still using.
static constexpr size_t kMaxTracees = 64;
struct TraceeRef {
  int pid = 0; // 0 marks the slot free
  int refs = 0;
  int owner_tid = 0;
};
static TraceeRef g_tracees[kMaxTracees];
static std::mutex g_attach_mu;

static int tracer_thread_id() {
  long tid = syscall(SYS_gettid);
  return tid > 0 && tid <= INT_MAX ? static_cast<int>(tid) : 0;
}

static bool current_thread_holds_tracee_lease(int pid) {
  const int owner_tid = tracer_thread_id();
  if (owner_tid == 0)
    return false;
  std::lock_guard<std::mutex> lock(g_attach_mu);
  for (const auto &ref : g_tracees)
    if (ref.pid == pid && ref.refs > 0 && ref.owner_tid == owner_tid)
      return true;
  return false;
}

static int pidfd_send_signal_retry(int pidfd, int signal) {
  if (pidfd < 0) {
    errno = EBADF;
    return -1;
  }
  int rc = -1;
  do {
    errno = 0;
    rc = static_cast<int>(
        syscall(SYS_pidfd_send_signal, pidfd, signal, nullptr, 0));
  } while (rc < 0 && errno == EINTR);
  return rc;
}

static bool active_patch_identity_alive(int pid, uint64_t generation = 0) {
  if (pid <= 0 ||
      g_active_patch_tgid.load(std::memory_order_acquire) != pid)
    return false;
  const uint64_t observed_generation =
      g_active_patch_generation.load(std::memory_order_acquire);
  if (observed_generation == 0 ||
      (generation != 0 && observed_generation != generation))
    return false;
  const int pidfd = g_active_tracee_pidfd.load(std::memory_order_acquire);
  if (pidfd < 0 || pidfd_send_signal_retry(pidfd, 0) < 0)
    return false;
  return g_active_patch_tgid.load(std::memory_order_acquire) == pid &&
         g_active_patch_generation.load(std::memory_order_acquire) ==
             observed_generation &&
         g_active_tracee_pidfd.load(std::memory_order_acquire) == pidfd;
}

static bool thread_is_member(int tgid, int tid) {
  char path[96];
  int n = snprintf(path, sizeof(path), "/proc/%d/task/%d", tgid, tid);
  return n > 0 && static_cast<size_t>(n) < sizeof(path) &&
         access(path, F_OK) == 0;
}

enum class StopWaitResult { Stopped, Gone, Failed };

static bool detach_thread_verified(int tgid, int tid, int signal);
static void terminate_all_owned_tracees_from_proc();
static bool proc_tracee_is_owned_by_self(int pid);

// A FORK/VFORK/CLONE event can beat a detach interrupt. The child is already
// ptrace-owned at that point, even if its separate initial event-stop has not
// reached waitpid yet. Consume and release it before the parent (mandatory for
// vfork), or terminally drain every owned tracee if ownership/code state is
// ambiguous. Returning while silently forgetting the child is never safe.
static bool resolve_child_event_before_detach(int parent_tgid, int parent_tid) {
  unsigned long message = 0;
  if (ptrace(PTRACE_GETEVENTMSG, parent_tid, nullptr, &message) < 0 ||
      message == 0 || message > static_cast<unsigned long>(INT_MAX)) {
    kill(parent_tgid, SIGKILL);
    terminate_all_owned_tracees_from_proc();
    return false;
  }
  const int child = static_cast<int>(message);

  bool child_stopped = false;
  for (int retry = 0; retry < 400; retry++) {
    int status = 0;
    errno = 0;
    pid_t waited = waitpid(child, &status, __WALL | WNOHANG);
    if (waited == child) {
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        return true;
      }
      if (WIFSTOPPED(status)) {
        child_stopped = true;
        break;
      }
      continue;
    }
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      if (errno == ECHILD || errno == ESRCH) {
        int observed_tgid = 0;
        errno = 0;
        const bool gone =
            !ProcessTracer::read_thread_group_id(child, &observed_tgid) &&
            kill(child, 0) < 0 && errno == ESRCH;
        if (gone) {
          return true;
        }
      }
      break;
    }
    usleep(1000);
  }

  int child_tgid = 0;
  bool original_group = false;
  for (int retry = 0; child_stopped && retry < 200; retry++) {
    if (ProcessTracer::claim_auto_attached_tracee(
            parent_tgid, child, &child_tgid, &original_group))
      break;
    usleep(1000);
  }

  const bool patches_live =
      g_active_patch_tgid.load(std::memory_order_acquire) == parent_tgid;
  if (child_stopped && child_tgid > 0 && !patches_live &&
      detach_thread_verified(child_tgid, child, 0)) {
    ProcessTracer::forget_auto_attached_tracee(child_tgid, child);
    if (!original_group)
      ProcessTracer::untrack_auto_attached_child(child_tgid);
    return true;
  }

  // There is no byte registry here from which a copied fork address space can
  // be restored. While a patch transaction is live, or when child ownership
  // cannot be proven, killing both sides is the only non-executing outcome.
  // PTRACE_KILL is bound to this exact auto-attached task; unlike kill(2) on a
  // number it cannot hit an unrelated process after a rapid PID reuse.
  ptrace(PTRACE_KILL, child, nullptr, nullptr);
  terminate_all_owned_tracees_from_proc();
  // Do not leave a killed-but-unreaped numeric PID in the fixed registry: a
  // later PID reuse could make fatal cleanup target an unrelated process.
  // This terminal path deliberately poisons further patch transactions and
  // atomically drains every ownership slot before returning failure.
  ProcessTracer::cleanup_all_attached();
  return false;
}

// A live tracee can report ESRCH to PTRACE_DETACH merely because it is not in a
// ptrace-stop. PTRACE_INTERRUPT creates an unambiguous PTRACE_EVENT_STOP without
// injecting SIGSTOP into the target, so genuine job-control state cannot
// coalesce with (or be cleared by) Hayabusa's detach recovery.
static StopWaitResult stop_and_wait_for_detach(int tgid, int tid) {
  errno = 0;
  if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
    if (errno == ESRCH && !thread_is_member(tgid, tid))
      return StopWaitResult::Gone;
    // EIO commonly means a seized tracee is already in a ptrace-stop whose
    // wait status has not been consumed yet. Poll it below instead of adding a
    // target-visible signal.
    if (errno != EIO)
      return StopWaitResult::Failed;
  }

  for (int retry = 0; retry < 200; retry++) {
    int status = 0;
    errno = 0;
    pid_t waited = waitpid(tid, &status, __WALL | WNOHANG);
    if (waited == tid) {
      if (WIFEXITED(status) || WIFSIGNALED(status))
        return StopWaitResult::Gone;
      if (WIFSTOPPED(status)) {
        const int stop_signal = WSTOPSIG(status);
        const unsigned event =
            (static_cast<unsigned>(status) >> 16) & 0xffffu;
        if (event == 1u || event == 2u || event == 3u) {
          if (!resolve_child_event_before_detach(tgid, tid))
            return StopWaitResult::Failed;
          // Child ownership was resolved before the parent. The parent event
          // stop is now a legal detach point.
          return StopWaitResult::Stopped;
        }
        if (event != 0) {
          // A ptrace event-stop is already a legal PTRACE_DETACH point. Running
          // the tracee here can execute a clone/fork child through temporary
          // instructions while detach recovery is still in progress.
          return StopWaitResult::Stopped;
        }
        if (stop_signal == (SIGTRAP | 0x80)) {
          if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) >= 0)
            continue;
          return errno == ESRCH && !thread_is_member(tgid, tid)
                     ? StopWaitResult::Gone
                     : StopWaitResult::Failed;
        }

        siginfo_t info{};
        errno = 0;
        if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) >= 0) {
          // This delivery stop predates our interrupt. Deliver the genuine
          // signal to the same TID; the pending PTRACE_INTERRUPT then regains
          // control without manufacturing a second signal.
          if (ptrace(PTRACE_CONT, tid, nullptr,
                     reinterpret_cast<void *>(
                         static_cast<intptr_t>(stop_signal))) >= 0)
            continue;
          return errno == ESRCH && !thread_is_member(tgid, tid)
                     ? StopWaitResult::Gone
                     : StopWaitResult::Failed;
        }
        if (errno == EINVAL) {
          // PTRACE_GETSIGINFO rejects a job-control group-stop. It is already a
          // safe detach point, and detaching with signal 0 preserves that stop.
          return StopWaitResult::Stopped;
        }
        return errno == ESRCH && !thread_is_member(tgid, tid)
                   ? StopWaitResult::Gone
                   : StopWaitResult::Failed;
      }
      continue;
    }
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      if ((errno == ECHILD || errno == ESRCH) &&
          !thread_is_member(tgid, tid))
        return StopWaitResult::Gone;
      return StopWaitResult::Failed;
    }
    usleep(1000);
  }
  return thread_is_member(tgid, tid) ? StopWaitResult::Failed
                                     : StopWaitResult::Gone;
}

static bool detach_thread_verified(int tgid, int tid, int signal) {
  int detach_signal = signal;
  // A ptrace event may already be pending but not yet consumed. PTRACE_DETACH
  // can succeed directly from that hidden stop; for a child event this would
  // orphan the kernel-auto-attached child. Peek with waitpid first and resolve
  // that ownership before attempting the otherwise-fast direct detach.
  int pending_status = 0;
  errno = 0;
  pid_t pending = waitpid(tid, &pending_status, __WALL | WNOHANG);
  if (pending == tid) {
    if (WIFEXITED(pending_status) || WIFSIGNALED(pending_status))
      return true;
    if (WIFSTOPPED(pending_status)) {
      const unsigned event =
          (static_cast<unsigned>(pending_status) >> 16) & 0xffffu;
      if ((event == 1u || event == 2u || event == 3u) &&
          !resolve_child_event_before_detach(tgid, tid))
        return false;
      const int stop_signal = WSTOPSIG(pending_status);
      if (event == 0 && stop_signal != (SIGTRAP | 0x80)) {
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) >= 0 &&
            info.si_signo == stop_signal) {
          bool genuine_delivery = true;
          if (stop_signal == SIGTRAP) {
            const bool internal_trace =
                info.si_code == TRAP_TRACE ||
                (info.si_code == SI_USER && info.si_pid == 0 &&
                 info.si_uid == 0);
            const bool explicit_user =
                info.si_code == SI_TKILL || info.si_code == SI_QUEUE ||
                (info.si_code == SI_USER && info.si_pid > 0);
            if (internal_trace) {
              genuine_delivery = false;
            } else if (!explicit_user &&
                       g_active_patch_tgid.load(std::memory_order_acquire) ==
                           tgid) {
              // A hidden BRK stop while this TGID owns temporary code cannot
              // safely be guessed as either tool or target state.
              kill(tgid, SIGKILL);
              terminate_all_owned_tracees_from_proc();
              ProcessTracer::cleanup_all_attached();
              return false;
            }
          }
          if (genuine_delivery && detach_signal != 0) {
            // Two already-observed deliveries cannot be encoded in one
            // PTRACE_DETACH. Deliver this stop first, then queue the caller's
            // previously preserved signal on the exact same TID.
            if (ptrace(PTRACE_DETACH, tid, nullptr,
                       reinterpret_cast<void *>(
                           static_cast<intptr_t>(stop_signal))) < 0) {
              kill(tgid, SIGKILL);
              terminate_all_owned_tracees_from_proc();
              ProcessTracer::cleanup_all_attached();
              return false;
            }
            errno = 0;
            if (syscall(SYS_tgkill, tgid, tid, detach_signal) == 0 ||
                errno == ESRCH)
              return true;
            kill(tgid, SIGKILL);
            return false;
          }
          if (genuine_delivery)
            detach_signal = stop_signal;
        }
      }
    }
  } else if (pending < 0 && errno != EINTR && errno != ECHILD &&
             errno != ESRCH) {
    return false;
  }

  errno = 0;
  int rc = ptrace(
      PTRACE_DETACH, tid, nullptr,
      reinterpret_cast<void *>(static_cast<intptr_t>(detach_signal)));
  if (rc >= 0)
    return true;

  int detach_errno = errno;
  if (detach_errno == ESRCH && !thread_is_member(tgid, tid))
    return true;

  StopWaitResult stopped = stop_and_wait_for_detach(tgid, tid);
  if (stopped == StopWaitResult::Gone)
    return true;
  if (stopped != StopWaitResult::Stopped)
    return false;

  errno = 0;
  rc = ptrace(PTRACE_DETACH, tid, nullptr,
              reinterpret_cast<void *>(static_cast<intptr_t>(detach_signal)));
  if (rc >= 0)
    return true;
  return errno == ESRCH && !thread_is_member(tgid, tid);
}

void ProcessTracer::cleanup_all_attached() {
  // Signal-handler context: no locks, no allocation. The exchange makes this
  // idempotent and safe against a detach() racing on the same slot. Publish a
  // permanent fatal-cleanup sentinel before observing the active transaction:
  // otherwise begin_patch_transaction() can win after our load and install a
  // temporary patch which this handler never sees.
  int patched_tgid = g_active_patch_tgid.exchange(
      kFatalCleanupStarted, std::memory_order_acq_rel);
  g_active_patch_generation.exchange(0, std::memory_order_acq_rel);
  int active_pidfd =
      g_active_tracee_pidfd.exchange(-1, std::memory_order_acq_rel);
  if (patched_tgid > 0 && active_pidfd >= 0) {
    // Retry an interrupted pidfd signal. A non-ESRCH failure is not treated as
    // success: the ptrace-owned threads below are killed before ownership is
    // released, and EXITKILL remains armed during supervised execution.
    (void)pidfd_send_signal_retry(active_pidfd, SIGKILL);
  }
  for (auto &slot : g_patch_children) {
    uint64_t child_state = slot.exchange(0, std::memory_order_acq_rel);
    int child = patch_child_pid(child_state);
    int child_pidfd = patch_child_pidfd(child_state);
    if (child <= 0)
      continue;
    // A separate child may contain a copied temporary patch. SIGKILL must be
    // pending before the tracer releases ownership, so it cannot execute it.
    // Bind a pidfd and recheck TracerPid after opening: a reaped registry entry
    // must never PTRACE_KILL a replacement that reused the numeric PID.
    if (child_pidfd >= 0) {
      (void)pidfd_send_signal_retry(child_pidfd, SIGKILL);
      close(child_pidfd);
    }
  }
  for (auto &slot : g_attached) {
    uint64_t state = slot.state.exchange(0, std::memory_order_acq_rel);
    if (state == 0)
      continue;
    int tgid = attached_tgid(state);
    int tid = attached_tid(state);
    if (tid <= 0)
      continue;
    if (tgid == patched_tgid) {
      // A fatal Hayabusa signal must never resume temporary BRKs/hooks.
      ptrace(PTRACE_KILL, tid, nullptr, nullptr);
      continue;
    }
    ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
  }
  if (active_pidfd >= 0)
    close(active_pidfd);
}

void ProcessTracer::terminal_drain_owned_tracees() {
  cleanup_all_attached();
  terminate_all_owned_tracees_from_proc();
}

bool ProcessTracer::begin_patch_transaction(int pid) {
  if (pid <= 0)
    return false;
  if (g_dangerous_transaction_depth != 0) {
    if (g_dangerous_transaction_tgid != pid ||
        g_active_patch_tgid.load(std::memory_order_acquire) != pid ||
        g_dangerous_transaction_generation == 0 ||
        g_active_patch_generation.load(std::memory_order_acquire) !=
            g_dangerous_transaction_generation)
      return false;
    g_dangerous_transaction_depth++;
    return true;
  }

  int expected = 0;
  if (!g_active_patch_tgid.compare_exchange_strong(
          expected, kDangerousTransactionPreparing,
          std::memory_order_acq_rel, std::memory_order_relaxed))
    return false;

  errno = 0;
  int pidfd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
  if (pidfd < 0) {
    expected = kDangerousTransactionPreparing;
    g_active_patch_tgid.compare_exchange_strong(
        expected, 0, std::memory_order_acq_rel,
        std::memory_order_relaxed);
    return false;
  }
  if (pidfd_send_signal_retry(pidfd, 0) < 0) {
    close(pidfd);
    expected = kDangerousTransactionPreparing;
    g_active_patch_tgid.compare_exchange_strong(
        expected, 0, std::memory_order_acq_rel,
        std::memory_order_relaxed);
    return false;
  }

  uint64_t generation =
      g_patch_generation_counter.fetch_add(1, std::memory_order_acq_rel) + 1;
  if (generation == 0) {
    generation =
        g_patch_generation_counter.fetch_add(1, std::memory_order_acq_rel) + 1;
  }
  g_active_tracee_pidfd.store(pidfd, std::memory_order_release);
  g_active_patch_generation.store(generation, std::memory_order_release);
  expected = kDangerousTransactionPreparing;
  if (!g_active_patch_tgid.compare_exchange_strong(
          expected, pid, std::memory_order_acq_rel,
          std::memory_order_relaxed)) {
    int owned_fd = pidfd;
    if (g_active_tracee_pidfd.compare_exchange_strong(
            owned_fd, -1, std::memory_order_acq_rel,
            std::memory_order_relaxed))
      close(pidfd);
    uint64_t owned_generation = generation;
    g_active_patch_generation.compare_exchange_strong(
        owned_generation, 0, std::memory_order_acq_rel,
        std::memory_order_relaxed);
    return false;
  }
  g_dangerous_transaction_tgid = pid;
  g_dangerous_transaction_generation = generation;
  g_dangerous_transaction_depth = 1;
  return true;
}

void ProcessTracer::end_patch_transaction(int pid) {
  if (g_dangerous_transaction_depth <= 0 ||
      g_dangerous_transaction_tgid != pid)
    return;
  if (--g_dangerous_transaction_depth != 0)
    return;
  const uint64_t generation = g_dangerous_transaction_generation;
  g_dangerous_transaction_tgid = 0;
  g_dangerous_transaction_generation = 0;
  if (generation == 0 ||
      g_active_patch_generation.load(std::memory_order_acquire) != generation)
    return;
  int expected = pid;
  if (g_active_patch_tgid.compare_exchange_strong(
          expected, kDangerousTransactionRetiring, std::memory_order_acq_rel,
          std::memory_order_relaxed)) {
    // Keep RETIRING published until this generation's descriptor is gone. A
    // new transaction therefore cannot reuse the same descriptor number while
    // this epilogue is still able to close it.
    int pidfd =
        g_active_tracee_pidfd.exchange(-1, std::memory_order_acq_rel);
    if (pidfd >= 0)
      close(pidfd);
    uint64_t owned_generation = generation;
    g_active_patch_generation.compare_exchange_strong(
        owned_generation, 0, std::memory_order_acq_rel,
        std::memory_order_relaxed);
    expected = kDangerousTransactionRetiring;
    g_active_patch_tgid.compare_exchange_strong(
        expected, 0, std::memory_order_acq_rel,
        std::memory_order_relaxed);
  }
}

class ScopedDangerousTransaction {
public:
  explicit ScopedDangerousTransaction(int pid)
      : pid_(pid), active_(ProcessTracer::begin_patch_transaction(pid)) {}
  ~ScopedDangerousTransaction() {
    if (active_)
      ProcessTracer::end_patch_transaction(pid_);
  }
  bool active() const { return active_; }

private:
  int pid_ = 0;
  bool active_ = false;
};

bool ProcessTracer::recover_attached(int pid) {
  const int owner_tid = tracer_thread_id();
  if (owner_tid == 0)
    return false;
  {
    std::lock_guard<std::mutex> lock(g_attach_mu);
    for (auto &ref : g_tracees) {
      if (ref.pid == pid && ref.refs > 0) {
        if (ref.owner_tid != owner_tid)
          return false;
        ref.refs = 1;
        break;
      }
    }
  }
  return detach(pid);
}

bool ProcessTracer::detach_thread_with_signal(int tgid, int tid, int signal) {
  const int owner_tid = tracer_thread_id();
  if (owner_tid == 0)
    return false;
  std::lock_guard<std::mutex> lock(g_attach_mu);
  bool owns_group = false;
  for (const auto &ref : g_tracees)
    owns_group = owns_group ||
                 (ref.pid == tgid && ref.refs > 0 &&
                  ref.owner_tid == owner_tid);
  if (!owns_group)
    return false;

  uint64_t wanted = attached_state(tgid, tid);
  for (auto &slot : g_attached) {
    uint64_t state = slot.state.load(std::memory_order_acquire);
    if (state != wanted)
      continue;
    if (!detach_thread_verified(tgid, tid, signal))
      return false;
    slot.state.compare_exchange_strong(state, 0,
                                       std::memory_order_acq_rel,
                                       std::memory_order_relaxed);
    return true;
  }
  return !thread_is_member(tgid, tid);
}

void ProcessTracer::reset_attach_bookkeeping() {
  std::lock_guard<std::mutex> lock(g_attach_mu);
  for (auto &slot : g_attached)
    slot.state.store(0, std::memory_order_release);
  for (auto &ref : g_tracees)
    ref = TraceeRef{};
}

bool ProcessTracer::list_threads_complete(int pid, std::vector<int> *out) {
  if (!out || pid <= 0)
    return false;
  out->clear();
  std::string dir = "/proc/" + std::to_string(pid) + "/task";
  DIR *d = opendir(dir.c_str());
  if (!d)
    return false;

  int read_error = 0;
  for (;;) {
    errno = 0;
    struct dirent *e = readdir(d);
    if (!e) {
      read_error = errno;
      break;
    }
    if (e->d_name[0] < '0' || e->d_name[0] > '9')
      continue;
    char *tail = nullptr;
    errno = 0;
    long value = strtol(e->d_name, &tail, 10);
    if (errno != 0 || !tail || *tail != '\0' || value <= 0 ||
        value > INT_MAX)
      continue;
    if (out->size() >= kMaxAttachedThreads) {
      read_error = E2BIG;
      break;
    }
    out->push_back(static_cast<int>(value));
  }
  int close_result = closedir(d);
  if (read_error != 0 || close_result != 0 || out->empty()) {
    out->clear();
    return false;
  }
  std::sort(out->begin(), out->end());
  out->erase(std::unique(out->begin(), out->end()), out->end());
  return true;
}

std::vector<int> ProcessTracer::list_threads(int pid) {
  std::vector<int> tids;
  (void)list_threads_complete(pid, &tids);
  return tids;
}

bool ProcessTracer::read_thread_group_id(int tid, int *tgid) {
  if (!tgid || tid <= 0)
    return false;
  char path[64];
  int path_length = snprintf(path, sizeof(path), "/proc/%d/status", tid);
  if (path_length <= 0 || static_cast<size_t>(path_length) >= sizeof(path))
    return false;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return false;

  char status[4096];
  ssize_t amount = -1;
  do {
    amount = read(fd, status, sizeof(status));
  } while (amount < 0 && errno == EINTR);
  int close_result = close(fd);
  if (amount <= 0 || close_result != 0)
    return false;

  const size_t length = static_cast<size_t>(amount);
  for (size_t line = 0; line < length;) {
    size_t end = line;
    while (end < length && status[end] != '\n')
      end++;
    if (end - line >= 5 && memcmp(status + line, "Tgid:", 5) == 0) {
      size_t cursor = line + 5;
      while (cursor < end &&
             (status[cursor] == ' ' || status[cursor] == '\t'))
        cursor++;
      if (cursor == end || status[cursor] < '0' || status[cursor] > '9')
        return false;
      unsigned value = 0;
      while (cursor < end && status[cursor] >= '0' &&
             status[cursor] <= '9') {
        unsigned digit = static_cast<unsigned>(status[cursor] - '0');
        if (value > (static_cast<unsigned>(INT_MAX) - digit) / 10)
          return false;
        value = value * 10 + digit;
        cursor++;
      }
      while (cursor < end && (status[cursor] == ' ' ||
                              status[cursor] == '\t' ||
                              status[cursor] == '\r'))
        cursor++;
      if (cursor != end || value == 0)
        return false;
      *tgid = static_cast<int>(value);
      return true;
    }
    line = end < length ? end + 1 : length;
  }
  return false;
}

// Mirrors the kernel's `struct user_pt_regs` (arch/arm64 UAPI). PTRACE_GETREGSET
// fills it by NT_PRSTATUS, so the layout is not ours to choose.
struct user_regs_struct_64 {
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
};
static_assert(sizeof(user_regs_struct_64) == 34 * 8,
              "user_pt_regs layout changed; NT_PRSTATUS transfers would "
              "silently read or write the wrong fields");
static_assert(offsetof(user_regs_struct_64, pc) == 32 * 8, "pc offset");

// AArch64's legacy FPSIMD regset is 32 x 128-bit V registers followed by
// FPSR, FPCR, and two reserved words. Do not accept a prefix: restoring a
// truncated vector image is silent target corruption.
static constexpr size_t kAarch64FpsimdBytes = 528;
static constexpr size_t kMaxAarch64RegsetBytes = 1024 * 1024;

struct RawRegisterSet {
  unsigned note = 0;
  std::vector<uint8_t> bytes;
};

struct RemoteRegisterSnapshot {
  RawRegisterSet gpr;
  std::vector<RawRegisterSet> extended;
};

enum class RawRegsetRead { Present, Unsupported, Failed };

static bool unsupported_arm64_regset_errno(int error) {
  return error == EINVAL || error == EIO || error == ENODEV ||
         error == ENOSYS || error == EOPNOTSUPP;
}

static RawRegsetRead read_raw_regset_capped(int tid, unsigned note,
                                            size_t maximum,
                                            RawRegisterSet *out) {
  if (!out || tid <= 0 || maximum == 0 ||
      maximum > kMaxAarch64RegsetBytes)
    return RawRegsetRead::Failed;

  std::vector<uint8_t> bytes;
  try {
    bytes.assign(maximum, 0);
  } catch (...) {
    return RawRegsetRead::Failed;
  }
  struct iovec iov = {bytes.data(), bytes.size()};
  errno = 0;
  if (ptrace(PTRACE_GETREGSET, tid, note, &iov) < 0) {
    return unsupported_arm64_regset_errno(errno)
               ? RawRegsetRead::Unsupported
               : RawRegsetRead::Failed;
  }
  // Equality with the deliberately oversized cap cannot distinguish an exact
  // image from a kernel-truncated one, so reject it as ambiguous.
  if (iov.iov_len == 0 || iov.iov_len >= maximum)
    return RawRegsetRead::Failed;
  bytes.resize(iov.iov_len);
  out->note = note;
  out->bytes = std::move(bytes);
  return RawRegsetRead::Present;
}

static bool read_exact_fixed_regset(int tid, unsigned note, size_t size,
                                    RawRegisterSet *out) {
  if (!out || tid <= 0 || size == 0 || size > kMaxAarch64RegsetBytes)
    return false;
  std::vector<uint8_t> bytes;
  try {
    bytes.assign(size, 0);
  } catch (...) {
    return false;
  }
  struct iovec iov = {bytes.data(), bytes.size()};
  if (ptrace(PTRACE_GETREGSET, tid, note, &iov) < 0 || iov.iov_len != size)
    return false;
  out->note = note;
  out->bytes = std::move(bytes);
  return true;
}

static bool scalable_regset_has_exact_header_size(const RawRegisterSet &set) {
  // user_sve_header/user_za_header share a leading 32-bit current size and
  // 32-bit maximum size. Reading with a large iovec must return exactly the
  // current image, never an arbitrary prefix.
  if (set.bytes.size() < 8)
    return false;
  uint32_t current = 0;
  uint32_t maximum = 0;
  memcpy(&current, set.bytes.data(), sizeof(current));
  memcpy(&maximum, set.bytes.data() + sizeof(current), sizeof(maximum));
  return current == set.bytes.size() && maximum >= current &&
         maximum <= kMaxAarch64RegsetBytes;
}

static bool save_optional_fixed_regset(int tid, unsigned note, size_t size,
                                       RemoteRegisterSnapshot *snapshot,
                                       size_t alternate_size = 0) {
  if (!snapshot || size == 0 || size >= kMaxAarch64RegsetBytes)
    return false;
  RawRegisterSet optional;
  RawRegsetRead read =
      read_raw_regset_capped(tid, note, size + 1, &optional);
  if (read == RawRegsetRead::Unsupported)
    return true;
  if (read != RawRegsetRead::Present ||
      (optional.bytes.size() != size &&
       (alternate_size == 0 || optional.bytes.size() != alternate_size)))
    return false;
  try {
    snapshot->extended.push_back(std::move(optional));
  } catch (...) {
    return false;
  }
  return true;
}

static bool save_remote_registers(int tid, RemoteRegisterSnapshot *snapshot) {
  if (!snapshot)
    return false;
  *snapshot = {};
  if (!read_exact_fixed_regset(tid, NT_PRSTATUS,
                               sizeof(user_regs_struct_64), &snapshot->gpr))
    return false;

  // A PTRACE_SINGLESTEP completion is reported with PSTATE.SS set even after
  // the user register image has been restored. It is tracer execution state,
  // not persistent target state: PTRACE_CONT clears it and SETREGSET at the
  // later BRK stop cannot recreate it. Do not snapshot/reinject that transient
  // bit into the remote call's caller context.
  user_regs_struct_64 normalized_gpr{};
  memcpy(&normalized_gpr, snapshot->gpr.bytes.data(), sizeof(normalized_gpr));
  normalized_gpr.pstate &= ~(uint64_t{1} << 21);
  memcpy(snapshot->gpr.bytes.data(), &normalized_gpr,
         sizeof(normalized_gpr));

  RawRegisterSet primary;
  RawRegsetRead sve = read_raw_regset_capped(
      tid, NT_ARM_SVE, kMaxAarch64RegsetBytes, &primary);
  if (sve == RawRegsetRead::Present) {
    if (!scalable_regset_has_exact_header_size(primary))
      return false;
    try {
      snapshot->extended.push_back(std::move(primary));
    } catch (...) {
      return false;
    }
  } else if (sve == RawRegsetRead::Unsupported) {
    if (!read_exact_fixed_regset(tid, NT_FPREGSET, kAarch64FpsimdBytes,
                                 &primary))
      return false;
    try {
      snapshot->extended.push_back(std::move(primary));
    } catch (...) {
      return false;
    }
  } else {
    return false;
  }

  // These fixed-size, writable thread regsets are outside user_pt_regs. TLS
  // contains TPIDR_EL0 and TPIDR2_EL0; SYSTEM_CALL contains the kernel's
  // syscall-number slot. The remaining controls are architectural per-thread
  // state on newer arm64 kernels. Unsupported notes are normal, but a partial
  // image is not safe to restore.
  if (!save_optional_fixed_regset(tid, NT_ARM_TLS,
                                  2 * sizeof(uint64_t), snapshot,
                                  sizeof(uint64_t)))
    return false;
  for (const auto &[note, size] :
       std::array<std::pair<unsigned, size_t>, 7>{
           std::pair<unsigned, size_t>{NT_ARM_SYSTEM_CALL, sizeof(int32_t)},
           {NT_ARM_PACA_KEYS, 8 * sizeof(uint64_t)},
           {NT_ARM_PACG_KEYS, 2 * sizeof(uint64_t)},
           {NT_ARM_TAGGED_ADDR_CTRL, sizeof(uint64_t)},
           {NT_ARM_PAC_ENABLED_KEYS, sizeof(uint64_t)},
           {NT_ARM_POE, sizeof(uint64_t)},
           {NT_ARM_GCS, 3 * sizeof(uint64_t)},
       }) {
    if (!save_optional_fixed_regset(tid, note, size, snapshot))
      return false;
  }

  // Streaming SVE and ZA are independent architectural state on SME-capable
  // kernels. Preserve them opportunistically; unsupported notes are normal on
  // Android devices without SME and must not make injection unavailable.
  for (unsigned note : {static_cast<unsigned>(NT_ARM_SSVE),
                        static_cast<unsigned>(NT_ARM_ZA)}) {
    RawRegisterSet optional;
    RawRegsetRead read = read_raw_regset_capped(
        tid, note, kMaxAarch64RegsetBytes, &optional);
    if (read == RawRegsetRead::Unsupported)
      continue;
    if (read != RawRegsetRead::Present ||
        !scalable_regset_has_exact_header_size(optional))
      return false;
    try {
      snapshot->extended.push_back(std::move(optional));
    } catch (...) {
      return false;
    }
  }

  // SME2's ZT tile and the newer floating-point mode register have no SVE
  // size header, but GETREGSET still reports their exact byte count through the
  // iovec. Preserve them when a newer kernel exposes them.
  for (unsigned note : {static_cast<unsigned>(NT_ARM_ZT),
                        static_cast<unsigned>(NT_ARM_FPMR)}) {
    RawRegisterSet optional;
    RawRegsetRead read = read_raw_regset_capped(
        tid, note, kMaxAarch64RegsetBytes, &optional);
    if (read == RawRegsetRead::Unsupported)
      continue;
    if (read != RawRegsetRead::Present)
      return false;
    try {
      snapshot->extended.push_back(std::move(optional));
    } catch (...) {
      return false;
    }
  }
  return true;
}

static bool write_raw_regset(int tid, const RawRegisterSet &set) {
  if (tid <= 0 || set.bytes.empty() ||
      set.bytes.size() > kMaxAarch64RegsetBytes)
    return false;
  std::vector<uint8_t> copy;
  try {
    copy = set.bytes;
  } catch (...) {
    return false;
  }
  struct iovec iov = {copy.data(), copy.size()};
  errno = 0;
  const bool ok = ptrace(PTRACE_SETREGSET, tid, set.note, &iov) >= 0 &&
                  iov.iov_len == set.bytes.size();
  if (!ok) {
    fprintf(stderr,
            "[ptrace] SETREGSET note=%u failed errno=%d bytes=%zu/%zu\n",
            set.note, errno, iov.iov_len, set.bytes.size());
  }
  return ok;
}

static bool restored_pstate_matches(uint64_t expected, uint64_t actual) {
  constexpr uint64_t kPtraceSingleStepPstate = uint64_t{1} << 21;
  if (expected == actual)
    return true;
  // Only tolerate the kernel adding its transient single-step stop bit after
  // we restored a snapshot that explicitly had it clear. Masking both sides
  // would also accept failure to restore a genuine set bit.
  return (expected & kPtraceSingleStepPstate) == 0 &&
         (actual & kPtraceSingleStepPstate) != 0 &&
         (expected ^ actual) == kPtraceSingleStepPstate;
}

static bool raw_regset_matches(int tid, const RawRegisterSet &wanted) {
  if (tid <= 0 || wanted.bytes.empty())
    return false;
  std::vector<uint8_t> observed;
  try {
    observed.assign(wanted.bytes.size(), 0);
  } catch (...) {
    return false;
  }
  struct iovec iov = {observed.data(), observed.size()};
  errno = 0;
  if (ptrace(PTRACE_GETREGSET, tid, wanted.note, &iov) < 0 ||
      iov.iov_len != wanted.bytes.size()) {
    fprintf(stderr,
            "[ptrace] GETREGSET verify note=%u failed errno=%d bytes=%zu/%zu\n",
            wanted.note, errno, iov.iov_len, wanted.bytes.size());
    return false;
  }
  if (wanted.note == NT_PRSTATUS &&
      wanted.bytes.size() == sizeof(user_regs_struct_64)) {
    user_regs_struct_64 expected{};
    user_regs_struct_64 actual{};
    memcpy(&expected, wanted.bytes.data(), sizeof(expected));
    memcpy(&actual, observed.data(), sizeof(actual));
    const bool same_core =
        memcmp(expected.regs, actual.regs, sizeof(expected.regs)) == 0 &&
        expected.sp == actual.sp && expected.pc == actual.pc &&
        restored_pstate_matches(expected.pstate, actual.pstate);
    if (same_core)
      return true;
  }
  if (observed == wanted.bytes)
    return true;
  size_t first = 0;
  while (first < observed.size() && observed[first] == wanted.bytes[first])
    first++;
  fprintf(stderr,
          "[ptrace] REGSET verify mismatch note=%u byte=%zu wanted=%02x "
          "got=%02x size=%zu\n",
          wanted.note, first,
          first < wanted.bytes.size() ? wanted.bytes[first] : 0,
          first < observed.size() ? observed[first] : 0, observed.size());
  return false;
}

static bool restore_remote_registers_verified(
    int tid, const RemoteRegisterSnapshot &snapshot) {
  // Extended state first and GPR/PSTATE last. Only report success after a
  // second complete read proves that later SETREGSET operations did not alter
  // an earlier image.
  for (const RawRegisterSet &set : snapshot.extended)
    if (!write_raw_regset(tid, set))
      return false;
  if (!write_raw_regset(tid, snapshot.gpr))
    return false;
  for (const RawRegisterSet &set : snapshot.extended)
    if (!raw_regset_matches(tid, set))
      return false;
  return raw_regset_matches(tid, snapshot.gpr);
}

static constexpr int SYS_MMAP_64 = 222;
static constexpr int SYS_MUNMAP_64 = 215;
static constexpr int SYS_MPROTECT_64 = 226;

static size_t native_page_size() {
  static const size_t page = []() -> size_t {
    long value = sysconf(_SC_PAGESIZE);
    if (value <= 0)
      return 0;
    size_t candidate = static_cast<size_t>(value);
    if ((candidate & (candidate - 1)) != 0)
      return 0;
    return candidate;
  }();
  return page;
}

// Remote calls, syscalls and code patches temporarily replace tracee
// registers/instructions. Serialise the complete transactions: locking only
// individual ptrace calls still lets a second worker save the first worker's
// temporary register state and later "restore" it over the real one.
static std::recursive_mutex g_remote_mutation_mu;
static thread_local AttachDeadline g_remote_operation_deadline =
    AttachDeadline::max();
static bool executable_range_mapped(int pid, uint64_t addr, size_t len);
static ExecutableWriteResult write_generated_executable_checked(
    int pid, uint64_t target, const void *data, size_t size);

class ScopedRemoteOperationDeadline {
public:
  explicit ScopedRemoteOperationDeadline(std::chrono::seconds duration)
      : previous_(g_remote_operation_deadline) {
    const AttachDeadline candidate = std::chrono::steady_clock::now() + duration;
    g_remote_operation_deadline = std::min(previous_, candidate);
  }
  ~ScopedRemoteOperationDeadline() {
    g_remote_operation_deadline = previous_;
  }

  AttachDeadline deadline() const { return g_remote_operation_deadline; }

private:
  AttachDeadline previous_;
};

static pid_t waitpid_until(pid_t pid, int *status,
                           const AttachDeadline &deadline) {
  if (!status) {
    errno = EINVAL;
    return -1;
  }
  while (std::chrono::steady_clock::now() < deadline) {
    errno = 0;
    pid_t waited = waitpid(pid, status, __WALL | WNOHANG);
    if (waited != 0) {
      if (waited < 0 && errno == EINTR)
        continue;
      return waited;
    }
    usleep(1000);
  }
  errno = ETIMEDOUT;
  return -1;
}

// Locate an existing `svc #0` in the target so a syscall can be driven without
// writing to the tracee's text. The previous approach patched the instruction
// at the current PC, which fails whenever the process is stopped in a
// read-only executable mapping -- i.e. essentially always, so every remote
// mmap/munmap silently failed.
static uint64_t find_syscall_insn(int pid) {
  // Shared by every worker thread, so the cache needs a lock. The scan itself
  // stays outside the critical section: it reads megabytes over ptrace and
  // holding the lock through it would serialise all workers on the first miss.
  static std::mutex cache_mu;
  static std::map<int, uint64_t> cache;
  {
    std::lock_guard<std::mutex> lock(cache_mu);
    auto it = cache.find(pid);
    if (it != cache.end()) {
      uint32_t inst = 0;
      if (it->second != 0 &&
          ProcessTracer::read_memory(pid, it->second, &inst, sizeof(inst)) &&
          inst == 0xD4000001u)
        return it->second;
      // PID reuse, exec, or a libc remap invalidated the cached address.
      cache.erase(it);
    }
  }

  const uint32_t want = 0xD4000001u; // svc #0

  uint64_t found = 0;
  for (const auto &m : Memory::read_maps(pid)) {
    if (m.perms.find('x') == std::string::npos || !m.readable())
      continue;
    // libc is guaranteed to contain syscall stubs.
    if (m.name.find("libc.so") == std::string::npos)
      continue;
    size_t len = m.size();
    if (len == 0 || len > 8u * 1024 * 1024)
      continue;
    std::vector<uint8_t> buf(len);
    if (!ProcessTracer::read_memory(pid, m.start, buf.data(), len))
      continue;
    for (size_t off = 0; off + 4 <= len; off += 4) {
      uint32_t inst;
      memcpy(&inst, buf.data() + off, 4);
      if (inst == want) {
        found = m.start + off;
        break;
      }
    }
    if (found)
      break;
  }
  std::lock_guard<std::mutex> lock(cache_mu);
  // A concurrent caller may have filled the entry while we scanned; either
  // result is equally valid, so keep whichever landed first.
  if (found == 0)
    return 0; // libc may not have been mapped yet; allow a later retry
  return cache.emplace(pid, found).first->second;
}

static bool set_regs_verified(int pid, const user_regs_struct_64 &wanted) {
  user_regs_struct_64 copy = wanted;
  struct iovec iov = {&copy, sizeof(copy)};
  if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0)
    return false;

  user_regs_struct_64 observed{};
  iov.iov_base = &observed;
  iov.iov_len = sizeof(observed);
  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0 ||
      iov.iov_len != sizeof(observed))
    return false;
  if (memcmp(observed.regs, wanted.regs, sizeof(observed.regs)) != 0 ||
      observed.sp != wanted.sp || observed.pc != wanted.pc)
    return false;
  // Linux owns PSTATE.SS while a task is in a ptrace single-step stop and can
  // report it set even after a successful SETREGSET that restored every
  // userspace-visible register. The bit is cleared by the next ptrace resume;
  // all architectural condition/interrupt state must still match exactly.
  return restored_pstate_matches(wanted.pstate, observed.pstate);
}

static bool proc_tracee_is_owned_by_self(int pid) {
  if (pid <= 0)
    return false;
  char path[64] = {};
  int path_length = snprintf(path, sizeof(path), "/proc/%d/status", pid);
  if (path_length <= 0 || static_cast<size_t>(path_length) >= sizeof(path))
    return false;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return false;
  char status[4096] = {};
  ssize_t amount = read(fd, status, sizeof(status) - 1);
  close(fd);
  if (amount <= 0)
    return false;

  // Linux records the exact tracer task, not necessarily its thread-group
  // leader, in TracerPid. Runtime module analysis is intentionally performed
  // by worker threads, so comparing this field with getpid() rejected every
  // valid auto-attached fork/vfork child created during --trace-init.
  const int self = tracer_thread_id();
  if (self <= 0)
    return false;
  const char *cursor = status;
  const char *end = status + amount;
  while (cursor < end) {
    const char *line_end = static_cast<const char *>(
        memchr(cursor, '\n', static_cast<size_t>(end - cursor)));
    if (!line_end)
      line_end = end;
    if (line_end - cursor >= 10 && memcmp(cursor, "TracerPid:", 10) == 0) {
      cursor += 10;
      while (cursor < line_end && (*cursor == ' ' || *cursor == '\t'))
        cursor++;
      int tracer = 0;
      while (cursor < line_end && *cursor >= '0' && *cursor <= '9') {
        tracer = tracer * 10 + (*cursor - '0');
        cursor++;
      }
      return tracer == self;
    }
    cursor = line_end < end ? line_end + 1 : end;
  }
  return false;
}

// Normal-context last resort for a ptrace child event whose GETEVENTMSG failed.
// A fork/vfork child is a process leader visible in /proc and carries our
// TracerPid even before userspace runs. Killing every tracee owned by this
// single-command Hayabusa process closes the otherwise unidentifiable child
// hole; same-TGID CLONE children die with the original group.
static void terminate_all_owned_tracees_from_proc() {
  for (int pass = 0; pass < 4; pass++) {
    DIR *proc = opendir("/proc");
    if (!proc)
      return;
    for (;;) {
      errno = 0;
      dirent *entry = readdir(proc);
      if (!entry)
        break;
      if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
        continue;
      char *tail = nullptr;
      long value = strtol(entry->d_name, &tail, 10);
      if (!tail || *tail != '\0' || value <= 0 || value > INT_MAX)
        continue;
      int tracee = static_cast<int>(value);
      if (!proc_tracee_is_owned_by_self(tracee))
        continue;
      int pidfd = static_cast<int>(syscall(SYS_pidfd_open, tracee, 0));
      if (pidfd >= 0) {
        // Opening first binds the kernel object. Recheck ownership afterwards
        // so a numeric PID reuse between /proc scans cannot target a newcomer.
        if (proc_tracee_is_owned_by_self(tracee))
          (void)pidfd_send_signal_retry(pidfd, SIGKILL);
        close(pidfd);
      }
      ptrace(PTRACE_KILL, tracee, nullptr, nullptr);
    }
    closedir(proc);
    usleep(1000);
  }
}

// Deliver a genuine signal which interrupted a temporary single-step without
// leaving the tracee running. Single-step the restored context while injecting
// the signal: the signal is observed by the target and the tracer regains
// control after at most one target instruction. Further signal-delivery stops
// are forwarded in the same way rather than silently swallowed.
static bool deliver_signal_and_restop(int pid, int signal,
                                      const AttachDeadline &deadline) {
  int pending = signal;
  for (int delivered = 0; delivered < 32; delivered++) {
    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr,
               reinterpret_cast<void *>(static_cast<intptr_t>(pending))) < 0)
      return false;

    int status = 0;
    pid_t waited = waitpid_until(pid, &status, deadline);
    if (waited != pid) {
      if (errno == ETIMEDOUT)
        ProcessTracer::cleanup_all_attached();
      return false;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status))
      return true; // delivery legitimately terminated the target
    if (!WIFSTOPPED(status))
      return false;

    const unsigned event =
        (static_cast<unsigned>(status) >> 16) & 0xffffu;
    if (event != 0) {
      // A signal handler is allowed to fork/vfork/clone. With ptrace child
      // options enabled that creates a new automatically attached tracee while
      // the caller may still own temporary code. Merely returning would leave
      // that child outside the signal-safe ownership table; fatal cleanup could
      // then detach it into a copied BRK/hook. Register it first and terminate
      // both sides while they are event-stopped. Other ptrace events (EXEC,
      // EXIT, ...) also invalidate the saved pre-signal context, so the parent
      // is fail-closed in every event case.
      if (event == 1u || event == 2u || event == 3u) {
        int child = 0;
        if (ProcessTracer::event_child(pid, &child) && child > 0) {
          if (!ProcessTracer::track_auto_attached_child(child)) {
            ptrace(PTRACE_KILL, child, nullptr, nullptr);
          }
        }
      }
      ProcessTracer::cleanup_all_attached();
      terminate_all_owned_tracees_from_proc();
      return false;
    }

    const int stopped_signal = WSTOPSIG(status);
    siginfo_t info{};
    errno = 0;
    if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &info) < 0) {
      // EINVAL denotes a group-stop. It is both delivered and safely stopped.
      return errno == EINVAL;
    }
    if (stopped_signal == SIGTRAP &&
        (info.si_code == TRAP_TRACE ||
         (info.si_code == SI_USER && info.si_pid == 0 &&
          info.si_uid == 0)))
      return true;
    pending = stopped_signal;
  }
  return false;
}

static uint64_t execute_syscall(int pid, const std::vector<uint64_t> &args,
                                int syscall_nr) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  const AttachDeadline deadline =
      g_remote_operation_deadline == AttachDeadline::max()
          ? std::chrono::steady_clock::now() + std::chrono::seconds(20)
          : g_remote_operation_deadline;
  if (std::chrono::steady_clock::now() >= deadline)
    return static_cast<uint64_t>(-1);
  ScopedDangerousTransaction dangerous(pid);
  if (!dangerous.active()) {
    fprintf(stderr,
            "[ptrace] remote syscall %d: could not acquire fail-closed "
            "transaction ownership\n",
            syscall_nr);
    return static_cast<uint64_t>(-1);
  }
  RemoteRegisterSnapshot snapshot{};
  user_regs_struct_64 orig_regs{}, regs{};
  if (!save_remote_registers(pid, &snapshot) ||
      snapshot.gpr.bytes.size() != sizeof(orig_regs)) {
    fprintf(stderr,
            "[ptrace] remote syscall %d: complete register snapshot failed\n",
            syscall_nr);
    return static_cast<uint64_t>(-1);
  }
  memcpy(&orig_regs, snapshot.gpr.bytes.data(), sizeof(orig_regs));
  struct iovec iov = {&orig_regs, sizeof(orig_regs)};
  regs = orig_regs;
  for (size_t i = 0; i < args.size() && i < 8; i++)
    regs.regs[i] = args[i];
  regs.regs[8] = syscall_nr;
  const uint64_t svc_addr = find_syscall_insn(pid);
  if (svc_addr == 0) {
    fprintf(stderr, "[ptrace] remote syscall %d: no libc svc instruction\n",
            syscall_nr);
    return static_cast<uint64_t>(-1);
  }
  regs.pc = svc_addr;
  if (!set_regs_verified(pid, regs)) {
    fprintf(stderr,
            "[ptrace] remote syscall %d: temporary register write/readback "
            "failed (errno=%d)\n",
            syscall_nr, errno);
    if (!restore_remote_registers_verified(pid, snapshot))
      ProcessTracer::cleanup_all_attached();
    return static_cast<uint64_t>(-1);
  }

  auto restore = [&]() {
    for (int retry = 0; retry < 3; retry++)
      if (restore_remote_registers_verified(pid, snapshot))
        return true;
    // Resuming syscall-temporary registers is target corruption. Fail closed.
    user_regs_struct_64 observed{};
    struct iovec observed_iov = {&observed, sizeof(observed)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &observed_iov) >= 0) {
      for (size_t reg = 0; reg < 31; reg++) {
        if (observed.regs[reg] == orig_regs.regs[reg])
          continue;
        fprintf(stderr,
                "[ptrace] restore mismatch x%zu wanted=0x%llx got=0x%llx\n",
                reg,
                static_cast<unsigned long long>(orig_regs.regs[reg]),
                static_cast<unsigned long long>(observed.regs[reg]));
      }
      if (observed.sp != orig_regs.sp || observed.pc != orig_regs.pc ||
          observed.pstate != orig_regs.pstate) {
        fprintf(stderr,
                "[ptrace] restore mismatch sp=%llx/%llx pc=%llx/%llx "
                "pstate=%llx/%llx\n",
                static_cast<unsigned long long>(observed.sp),
                static_cast<unsigned long long>(orig_regs.sp),
                static_cast<unsigned long long>(observed.pc),
                static_cast<unsigned long long>(orig_regs.pc),
                static_cast<unsigned long long>(observed.pstate),
                static_cast<unsigned long long>(orig_regs.pstate));
      }
    }
    fprintf(stderr,
            "[ptrace] remote syscall %d: original register restore/readback "
            "failed; killing target\n",
            syscall_nr);
    ProcessTracer::cleanup_all_attached();
    return false;
  };

  if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) < 0) {
    fprintf(stderr, "[ptrace] remote syscall %d: SINGLESTEP failed: %s\n",
            syscall_nr, strerror(errno));
    (void)restore();
    return static_cast<uint64_t>(-1);
  }

  int status = 0;
  pid_t waited = waitpid_until(pid, &status, deadline);
  if (waited < 0 && errno == ETIMEDOUT) {
    fprintf(stderr, "[ptrace] remote syscall %d timed out\n", syscall_nr);
    ProcessTracer::cleanup_all_attached();
    return static_cast<uint64_t>(-1);
  }

  int pending_signal = 0;
  bool expected_stop = false;
  bool single_step_trap = false;
  int trap_info_errno = 0;
  siginfo_t trap_info{};
  SyscallStopInfo first_syscall_stop{};
  SyscallStopInfo final_syscall_stop{};
  bool have_first_syscall_stop = false;
  bool have_final_syscall_stop = false;
  uint64_t result = static_cast<uint64_t>(-1);
  if (waited == pid && WIFSTOPPED(status)) {
    int stopped_signal = WSTOPSIG(status);
    unsigned event =
        (static_cast<unsigned>(status) >> 16) & 0xffffu;
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    const bool got_regs =
        ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) >= 0 &&
        iov.iov_len == sizeof(regs);
    errno = 0;
    int trap_info_result =
        stopped_signal == SIGTRAP
            ? ptrace(PTRACE_GETSIGINFO, pid, nullptr, &trap_info)
            : -1;
    trap_info_errno = errno;
    // Some Android arm64 kernels report a PTRACE_SINGLESTEP completion as a
    // synthetic SIGTRAP either without siginfo (EINVAL) or as an SI_USER record
    // with the impossible userspace sender pid/uid 0. A genuine user SIGTRAP
    // has a nonzero sender, so these exact forms plus event=0 and PC=svc+4 stay
    // distinguishable from signal delivery.
    single_step_trap =
        stopped_signal == SIGTRAP &&
        ((trap_info_result >= 0 &&
          (trap_info.si_code == TRAP_TRACE ||
           (trap_info.si_code == SI_USER && trap_info.si_pid == 0 &&
            trap_info.si_uid == 0))) ||
         (trap_info_result < 0 && trap_info_errno == EINVAL));
    have_first_syscall_stop =
        ProcessTracer::get_syscall_stop(pid, &first_syscall_stop);

    if (got_regs && event == 0 && stopped_signal == SIGTRAP &&
        single_step_trap && regs.pc == svc_addr + 4 &&
        have_first_syscall_stop &&
        first_syscall_stop.kind == SyscallStopKind::Entry &&
        first_syscall_stop.number == static_cast<uint64_t>(syscall_nr)) {
      // arm64 can single-step to the syscall-entry stop, where x0 is the
      // kernel's temporary -ENOSYS sentinel. Resume with PTRACE_SYSCALL and
      // require the matching exit stop before accepting x0 as the result.
      if (ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) >= 0) {
        waited = waitpid_until(pid, &status, deadline);
        if (waited < 0 && errno == ETIMEDOUT) {
          fprintf(stderr,
                  "[ptrace] remote syscall %d exit-stop timed out\n",
                  syscall_nr);
          ProcessTracer::cleanup_all_attached();
          return static_cast<uint64_t>(-1);
        }
        if (waited == pid && WIFSTOPPED(status)) {
          stopped_signal = WSTOPSIG(status);
          event = (static_cast<unsigned>(status) >> 16) & 0xffffu;
          iov.iov_base = &regs;
          iov.iov_len = sizeof(regs);
          const bool got_exit_regs =
              ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) >= 0 &&
              iov.iov_len == sizeof(regs);
          have_final_syscall_stop =
              ProcessTracer::get_syscall_stop(pid, &final_syscall_stop);
          expected_stop =
              got_exit_regs && event == 0 &&
              (stopped_signal == SIGTRAP ||
               stopped_signal == (SIGTRAP | 0x80)) &&
              regs.pc == svc_addr + 4 && have_final_syscall_stop &&
              final_syscall_stop.kind == SyscallStopKind::Exit &&
              static_cast<uint64_t>(final_syscall_stop.return_value) ==
                  regs.regs[0];
          if (expected_stop)
            result = regs.regs[0];
        }
      }
    } else {
      // Kernels which complete the syscall in the single-step itself do not
      // expose an entry stop. In that case the validated trap/PC pair carries
      // the final register result directly.
      expected_stop =
          got_regs && event == 0 && stopped_signal == SIGTRAP &&
          single_step_trap && regs.pc == svc_addr + 4 &&
          (!have_first_syscall_stop ||
           first_syscall_stop.kind != SyscallStopKind::Entry);
      if (expected_stop)
        result = regs.regs[0];
    }

    if (!expected_stop && event == 0) {
      if (stopped_signal != SIGTRAP) {
        pending_signal = stopped_signal;
      } else if (!single_step_trap) {
        pending_signal = SIGTRAP;
      }
    }
  }

  if (!expected_stop) {
    fprintf(stderr,
            "[ptrace] remote syscall %d: unexpected stop "
            "(waited=%d status=0x%x signal=%d event=%u pc=0x%llx "
            "expected=0x%llx siginfo=%d code=%d pid=%d uid=%u "
            "info_errno=%d first_kind=%d first_nr=%llu final_kind=%d "
            "final_ret=%lld)\n",
            syscall_nr, static_cast<int>(waited), status,
            WIFSTOPPED(status) ? WSTOPSIG(status) : 0,
            WIFSTOPPED(status)
                ? ((static_cast<unsigned>(status) >> 16) & 0xffffu)
                : 0,
            static_cast<unsigned long long>(regs.pc),
            static_cast<unsigned long long>(svc_addr + 4),
            single_step_trap ? 1 : 0, trap_info.si_code, trap_info.si_pid,
            static_cast<unsigned>(trap_info.si_uid), trap_info_errno,
            static_cast<int>(first_syscall_stop.kind),
            static_cast<unsigned long long>(first_syscall_stop.number),
            static_cast<int>(final_syscall_stop.kind),
            static_cast<long long>(final_syscall_stop.return_value));
  } else if (result >= static_cast<uint64_t>(-4095)) {
    fprintf(stderr,
            "[ptrace] remote syscall %d completed with %lld "
            "(first_kind=%d first_nr=%llu final_kind=%d final_ret=%lld)\n",
            syscall_nr, static_cast<long long>(result),
            static_cast<int>(first_syscall_stop.kind),
            static_cast<unsigned long long>(first_syscall_stop.number),
            static_cast<int>(final_syscall_stop.kind),
            static_cast<long long>(final_syscall_stop.return_value));
  }

  if (!restore())
    return static_cast<uint64_t>(-1);
  if (pending_signal != 0 &&
      !deliver_signal_and_restop(pid, pending_signal, deadline)) {
    fprintf(stderr,
            "[ptrace] remote syscall %d: could not preserve signal %d\n",
            syscall_nr, pending_signal);
    return static_cast<uint64_t>(-1);
  }
  return expected_stop ? result : static_cast<uint64_t>(-1);
}

static bool syscall_failed(uint64_t result) {
  // Linux reports -errno in x0; valid userspace mappings cannot occupy this
  // top-page range.
  return result >= static_cast<uint64_t>(-4095);
}

namespace InstructionDecoder {

// AArch64 decoding is rizin's job now. What used to live here was a
// hand-written decoder covering a couple of dozen encodings; these are thin
// adapters onto rz_analysis_op so the rest of the file keeps its old shape
// while the actual decode comes from a complete disassembler.

DecodedInstruction decode(uint32_t inst, uint64_t addr) {
  DecodedInstruction d{};
  d.type = InstructionType::Unknown;

  uint8_t bytes[4];
  write_le32(bytes, inst);
  rzb::Insn insn;
  if (!rzb::decode_one(bytes, sizeof(bytes), addr, &insn))
    return d;

  switch (insn.type) {
  case rzb::InsnType::Call:
    d.type = InstructionType::BranchLink;
    break;
  case rzb::InsnType::Return:
    d.type = InstructionType::Return;
    break;
  case rzb::InsnType::Branch:
    d.type = insn.is_indirect ? InstructionType::BranchRegister
                              : InstructionType::Branch;
    break;
  case rzb::InsnType::ConditionalBranch:
    d.type = InstructionType::ConditionalBranch;
    break;
  case rzb::InsnType::Load:
    d.type = InstructionType::Load;
    break;
  case rzb::InsnType::Store:
    d.type = InstructionType::Store;
    break;
  case rzb::InsnType::Adrp:
    d.type = InstructionType::Adrp;
    break;
  case rzb::InsnType::Add:
    d.type = InstructionType::Add;
    break;
  default:
    d.type = InstructionType::Other;
    break;
  }

  d.target_address = insn.target;
  d.is_call = insn.is_call;
  d.is_return = insn.is_return;
  d.is_indirect = insn.is_indirect;
  return d;
}

bool is_function_end(const uint8_t *code, size_t offset, size_t size) {
  if (offset + 4 > size)
    return true;
  rzb::Insn insn;
  if (!rzb::decode_one(code + offset, size - offset, 0, &insn))
    return false;
  return insn.is_return;
}

size_t find_function_end(const uint8_t *code, size_t max_size) {
  for (size_t i = 0; i + 4 <= max_size; i += 4)
    if (is_function_end(code, i, max_size))
      return i + 4;
  return max_size;
}

std::vector<CallInfo> scan_calls(const uint8_t *code, size_t size,
                                 uint64_t base) {
  std::vector<CallInfo> calls;
  for (size_t i = 0; i + 4 <= size; i += 4) {
    rzb::Insn insn;
    if (!rzb::decode_one(code + i, size - i, base + i, &insn))
      continue;
    if (!insn.is_call || insn.is_indirect || !insn.target)
      continue;
    CallInfo ci{};
    ci.call_site_offset = i;
    ci.target_address = insn.target;
    calls.push_back(ci);
  }
  return calls;
}

// Not disassembly: this reads the live process to follow a PLT stub through to
// the GOT entry the loader filled in, which only makes sense against a running
// target and has no rizin equivalent.

uint64_t resolve_plt(int pid, uint64_t plt_addr) {
  uint8_t stub[16];
  if (!ProcessTracer::read_memory(pid, plt_addr, stub, 16))
    return 0;

  for (int skip = 0; skip <= 4; skip += 4) {
    uint32_t inst0 = read_le32(stub + skip);
    uint32_t inst1 = read_le32(stub + skip + 4);

    bool is_adrp = (inst0 & 0x9F000000) == 0x90000000;
    bool is_ldr = (inst1 & 0xFFC00000) == 0xF9400000;

    if (is_adrp && is_ldr) {
      int32_t immhi = ((inst0 >> 5) & 0x7FFFF) << 2;
      int32_t immlo = (inst0 >> 29) & 0x3;
      int32_t imm21 = immhi | immlo;
      if (imm21 & 0x100000)
        imm21 |= 0xFFE00000;
      int64_t page_offset = (int64_t)imm21 << 12;
      uint64_t page_base = ((plt_addr + skip) & ~0xFFFULL) + page_offset;
      uint32_t ldr_imm = ((inst1 >> 10) & 0xFFF) << 3;
      uint64_t got_addr = page_base + ldr_imm;

      uint64_t got_value = 0;
      if (ProcessTracer::read_memory(pid, got_addr, &got_value, 8)) {
        if (got_value > 0x1000)
          return got_value;
      }
    }
  }
  return 0;
}




} // namespace InstructionDecoder




static bool record_attached(int tgid, int tid) {
  uint64_t desired = attached_state(tgid, tid);
  for (auto &slot : g_attached) {
    uint64_t expected = 0;
    if (slot.state.compare_exchange_strong(expected, desired,
                                           std::memory_order_release,
                                           std::memory_order_relaxed))
      return true;
  }
  return false; // table full
}

static void forget_attached(int tgid, int tid) {
  uint64_t expected = attached_state(tgid, tid);
  for (auto &slot : g_attached) {
    if (slot.state.compare_exchange_strong(expected, 0,
                                           std::memory_order_acq_rel,
                                           std::memory_order_relaxed))
      return;
    expected = attached_state(tgid, tid);
  }
}

// Seize one thread and interrupt it without delivering SIGSTOP. `__WALL` is
// required: without it waitpid ignores non-leader threads.
enum class AttachOneResult { Attached, Vanished, GroupStopped, Failed };

static bool release_unpublished_seized_task(int tid,
                                            const AttachDeadline &deadline) {
  errno = 0;
  if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0 && errno != EIO &&
      errno != ESRCH)
    return false;
  while (std::chrono::steady_clock::now() < deadline) {
    int status = 0;
    errno = 0;
    const pid_t waited = waitpid(tid, &status, __WALL | WNOHANG);
    if (waited == 0) {
      usleep(1000);
      continue;
    }
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      return errno == ECHILD || errno == ESRCH;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status))
      return true;
    if (!WIFSTOPPED(status))
      continue;
    const int signal = WSTOPSIG(status);
    const unsigned event =
        (static_cast<unsigned>(status) >> 16) & 0xffffu;
    int detach_signal = 0;
    if (event == 0 && signal != (SIGTRAP | 0x80) &&
        ProcessTracer::classify_signal_stop(tid, signal, event) ==
            SignalStopKind::Delivery)
      detach_signal = signal;
    errno = 0;
    return ptrace(PTRACE_DETACH, tid, nullptr,
                  reinterpret_cast<void *>(
                      static_cast<intptr_t>(detach_signal))) >= 0 ||
           errno == ESRCH;
  }
  return false;
}

static AttachOneResult attach_one_thread(int tgid, int tid,
                                         const AttachDeadline &deadline) {
  if (std::chrono::steady_clock::now() >= deadline)
    return AttachOneResult::Failed;
  // Do not publish this numeric TID as belonging to the requested TGID until
  // PTRACE_SEIZE has pinned the exact task and its stopped /proc status proves
  // that membership. If Hayabusa exits in the short pre-publication window,
  // the kernel releases the tracer relationship; an async cleanup must never
  // misclassify and kill a recycled unrelated task.
  sigset_t blocked{}, previous{};
  sigemptyset(&blocked);
  sigaddset(&blocked, SIGINT);
  sigaddset(&blocked, SIGTERM);
  sigaddset(&blocked, SIGABRT);
  sigprocmask(SIG_BLOCK, &blocked, &previous);

  if (ptrace(PTRACE_SEIZE, tid, nullptr, nullptr) < 0) {
    int saved_errno = errno;
    sigprocmask(SIG_SETMASK, &previous, nullptr);
    return saved_errno == ESRCH && !thread_is_member(tgid, tid)
               ? AttachOneResult::Vanished
               : AttachOneResult::Failed;
  }
  int seized_tgid = 0;
  if (!ProcessTracer::read_thread_group_id(tid, &seized_tgid) ||
      seized_tgid != tgid) {
    const bool released = release_unpublished_seized_task(tid, deadline);
    sigprocmask(SIG_SETMASK, &previous, nullptr);
    return released ? AttachOneResult::Vanished : AttachOneResult::Failed;
  }
  if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) < 0) {
    int saved_errno = errno;
    if (saved_errno == EIO) {
      // The thread may already be in a published signal/group stop. Consume
      // that status once so a pre-existing job-control stop can be reported to
      // remote-call reacquisition instead of being misclassified as failure.
      int pending_status = 0;
      errno = 0;
      pid_t pending = waitpid(tid, &pending_status, __WALL | WNOHANG);
      if (pending == tid && WIFSTOPPED(pending_status)) {
        const int signal = WSTOPSIG(pending_status);
        const unsigned event =
            (static_cast<unsigned>(pending_status) >> 16) & 0xffffu;
        const bool job_control =
            signal == SIGSTOP || signal == SIGTSTP || signal == SIGTTIN ||
            signal == SIGTTOU;
        SignalStopKind kind =
            ProcessTracer::classify_signal_stop(tid, signal, event);
        const bool group_stop =
            (event == kPtraceEventStop && job_control) ||
            kind == SignalStopKind::GroupStop;
        int detach_signal =
            kind == SignalStopKind::Delivery ? signal : 0;
        if (detach_thread_verified(tgid, tid, detach_signal)) {
          forget_attached(tgid, tid);
          sigprocmask(SIG_SETMASK, &previous, nullptr);
          return group_stop ? AttachOneResult::GroupStopped
                            : AttachOneResult::Failed;
        }
      }
    }
    // No target code was changed. Try to consume any already-published stop
    // and detach; if ownership itself is ambiguous, fail terminally rather
    // than return with a hidden tracer relationship.
    StopWaitResult stopped = stop_and_wait_for_detach(tgid, tid);
    if (stopped == StopWaitResult::Stopped &&
        detach_thread_verified(tgid, tid, 0)) {
      forget_attached(tgid, tid);
    } else if (stopped != StopWaitResult::Gone) {
      kill(tgid, SIGKILL);
      ptrace(PTRACE_KILL, tid, nullptr, nullptr);
    } else {
      forget_attached(tgid, tid);
    }
    sigprocmask(SIG_SETMASK, &previous, nullptr);
    return saved_errno == ESRCH && !thread_is_member(tgid, tid)
               ? AttachOneResult::Vanished
               : AttachOneResult::Failed;
  }

  int status = 0;
  pid_t waited = -1;
  bool interrupt_stop = false;
  int delivered = 0;
  bool saw_group_stop = false;
  while (delivered < 1024 &&
         std::chrono::steady_clock::now() < deadline) {
    do {
      waited = waitpid(tid, &status, __WALL | WNOHANG);
    } while (waited < 0 && errno == EINTR);
    if (waited == 0) {
      usleep(1000);
      continue;
    }
    if (waited != tid || !WIFSTOPPED(status))
      break;
    delivered++;
    int signal = WSTOPSIG(status);
    const unsigned event =
        (static_cast<unsigned>(status) >> 16) & 0xffffu;
    if (event == kPtraceEventStop && signal == SIGTRAP) {
      interrupt_stop = true;
      break;
    }
    if (event == kPtraceEventStop) {
      // A seized job-control group-stop is not safe to wake for analysis.
      // Leave it intact and make this attach attempt fail cleanly below.
      const bool job_control = signal == SIGSTOP || signal == SIGTSTP ||
                               signal == SIGTTIN || signal == SIGTTOU;
      saw_group_stop = job_control;
      break;
    }
    // A genuine signal-delivery stop can win the race with INTERRUPT. Preserve
    // it on the exact TID; the pending interrupt then reports event 128.
    if (ptrace(PTRACE_CONT, tid, nullptr,
               reinterpret_cast<void *>(static_cast<intptr_t>(signal))) < 0)
      break;
  }
  if (!interrupt_stop) {
    if (detach_thread_verified(tgid, tid, 0))
      forget_attached(tgid, tid);
    sigprocmask(SIG_SETMASK, &previous, nullptr);
    if (!thread_is_member(tgid, tid))
      return AttachOneResult::Vanished;
    return saw_group_stop ? AttachOneResult::GroupStopped
                          : AttachOneResult::Failed;
  }
  int observed_tgid = 0;
  if (!ProcessTracer::read_thread_group_id(tid, &observed_tgid) ||
      observed_tgid != tgid) {
    // PTRACE_SEIZE pins the exact task, so a direct detach from this consumed
    // interrupt-stop cannot cross into a later PID reuse. Do not use numeric
    // kill/rollback here: this may be an unrelated task that won the lookup
    // race immediately before SEIZE.
    bool released = false;
    for (int retry = 0; retry < 200; ++retry) {
      errno = 0;
      if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) >= 0 ||
          errno == ESRCH) {
        released = true;
        break;
      }
      if (errno != EINTR)
        usleep(1000);
    }
    if (released)
      forget_attached(tgid, tid);
    sigprocmask(SIG_SETMASK, &previous, nullptr);
    return released ? AttachOneResult::Vanished : AttachOneResult::Failed;
  }
  if (!record_attached(tgid, tid)) {
    bool released = false;
    for (int retry = 0; retry < 200; ++retry) {
      errno = 0;
      if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) >= 0 ||
          errno == ESRCH) {
        released = true;
        break;
      }
      if (errno != EINTR)
        usleep(1000);
    }
    if (!released)
      (void)ptrace(PTRACE_KILL, tid, nullptr, nullptr);
    sigprocmask(SIG_SETMASK, &previous, nullptr);
    return AttachOneResult::Failed;
  }
  sigprocmask(SIG_SETMASK, &previous, nullptr);
  return AttachOneResult::Attached;
}

static bool already_attached(int tgid, int tid) {
  uint64_t wanted = attached_state(tgid, tid);
  for (auto &slot : g_attached)
    if (slot.state.load(std::memory_order_acquire) == wanted)
      return true;
  return false;
}

// g_attach_mu must be held. Every successful attach removes one thread creator
// from the running set, so convergence is guaranteed for a finite process.
enum class AttachConvergence { Complete, GroupStopped, Failed };

static AttachConvergence
converge_attached_threads(int pid, size_t *newly_attached,
                          const AttachDeadline &deadline) {
  size_t added = 0;
  for (size_t pass = 0; pass < kMaxAttachedThreads; pass++) {
    if (std::chrono::steady_clock::now() >= deadline) {
      if (newly_attached)
        *newly_attached = added;
      return AttachConvergence::Failed;
    }
    std::vector<int> tids;
    if (!ProcessTracer::list_threads_complete(pid, &tids) ||
        tids.size() > kMaxAttachedThreads) {
      if (newly_attached)
        *newly_attached = added;
      return AttachConvergence::Failed;
    }
    for (int tid : tids) {
      if (std::chrono::steady_clock::now() >= deadline) {
        if (newly_attached)
          *newly_attached = added;
        return AttachConvergence::Failed;
      }
      if (already_attached(pid, tid))
        continue;
      AttachOneResult result = attach_one_thread(pid, tid, deadline);
      if (result == AttachOneResult::Attached) {
        added++;
      } else if (result == AttachOneResult::GroupStopped) {
        if (newly_attached)
          *newly_attached = added;
        return AttachConvergence::GroupStopped;
      } else if (result == AttachOneResult::Failed) {
        if (newly_attached)
          *newly_attached = added;
        return AttachConvergence::Failed;
      }
    }

    std::vector<int> verification;
    if (std::chrono::steady_clock::now() >= deadline ||
        !ProcessTracer::list_threads_complete(pid, &verification) ||
        verification.size() > kMaxAttachedThreads) {
      if (newly_attached)
        *newly_attached = added;
      return AttachConvergence::Failed;
    }
    bool missing = false;
    for (int tid : verification)
      if (!already_attached(pid, tid)) {
        missing = true;
        break;
      }
    if (!missing) {
      if (newly_attached)
        *newly_attached = added;
      return AttachConvergence::Complete;
    }
  }
  if (newly_attached)
    *newly_attached = added;
  return AttachConvergence::Failed;
}

// Attach to *every* thread of the target, not just the group leader.
//
  // PTRACE_SEIZE/INTERRUPT stops only the thread it names. Seizing the leader alone
// leaves the rest of the process running, which is why work a packer does on a
// worker thread used to be invisible. Threads created while we are attaching
// are caught by the second pass; ones created after that need
// PTRACE_O_TRACECLONE on the tracing loop.
bool ProcessTracer::attach(int pid) {
  const int owner_tid = tracer_thread_id();
  if (owner_tid == 0)
    return false;
  std::lock_guard<std::mutex> lock(g_attach_mu);
  const AttachDeadline deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(5);

  TraceeRef *free_ref = nullptr;
  for (auto &t : g_tracees) {
    if (t.pid == pid && t.refs > 0) {
      if (t.owner_tid != owner_tid)
        return false;
      size_t added = 0;
      if (converge_attached_threads(pid, &added, deadline) !=
          AttachConvergence::Complete)
        return false;
      t.refs++;
      return true;
    }
    if (t.pid == 0 && !free_ref)
      free_ref = &t;
  }
  if (!free_ref)
    return false; // tracee table full

  size_t attached = 0;
  bool failed = converge_attached_threads(pid, &attached, deadline) !=
                AttachConvergence::Complete;

  if (attached == 0)
    failed = true;
  if (failed) {
    // This was a new tracee, so every matching slot belongs to this failed
    // transaction. Roll it all back; never report a partially frozen process
    // as safe to patch.
    bool rollback_ok = true;
    for (auto &slot : g_attached) {
      if (std::chrono::steady_clock::now() >= deadline) {
        rollback_ok = false;
        break;
      }
      uint64_t state = slot.state.load(std::memory_order_acquire);
      if (attached_tgid(state) != pid)
        continue;
      int tid = attached_tid(state);
      if (detach_thread_verified(pid, tid, 0))
        slot.state.compare_exchange_strong(state, 0,
                                           std::memory_order_acq_rel,
                                           std::memory_order_relaxed);
      else
        rollback_ok = false;
    }
    if (!rollback_ok) {
      // A failed rollback must not escape with an unowned ptrace-stop: the
      // caller receives false and therefore has no RAII guard to clean it up.
      // SIGKILL cannot be caught or blocked, so terminal cleanup is the only
      // safe resolution once a partial attach cannot be detached.
      kill(pid, SIGKILL);
      for (int retry = 0; retry < 200; retry++) {
        bool any = false;
        for (auto &slot : g_attached) {
          uint64_t state = slot.state.load(std::memory_order_acquire);
          if (attached_tgid(state) != pid)
            continue;
          int tid = attached_tid(state);
          if (detach_thread_verified(pid, tid, 0)) {
            slot.state.compare_exchange_strong(
                state, 0, std::memory_order_acq_rel,
                std::memory_order_relaxed);
          } else {
            any = true;
          }
        }
        if (!any)
          break;
        usleep(1000);
      }
      // The tracee is terminal even if the kernel has not reaped every TID
      // yet; no later caller may inherit bookkeeping for this failed attach.
      for (auto &slot : g_attached) {
        uint64_t state = slot.state.load(std::memory_order_acquire);
        if (attached_tgid(state) == pid)
          slot.state.compare_exchange_strong(state, 0,
                                             std::memory_order_acq_rel,
                                             std::memory_order_relaxed);
      }
    }
    return false;
  }

  free_ref->pid = pid;
  free_ref->refs = 1;
  free_ref->owner_tid = owner_tid;
  return true;
}

bool ProcessTracer::detach(int pid) {
  const int owner_tid = tracer_thread_id();
  if (owner_tid == 0)
    return false;
  std::lock_guard<std::mutex> lock(g_attach_mu);

  TraceeRef *ref = nullptr;
  bool had_ref = false;
  for (auto &t : g_tracees) {
    if (t.pid != pid || t.refs <= 0)
      continue;
    if (t.owner_tid != owner_tid)
      return false;
    if (--t.refs > 0)
      return true; // another caller still needs the tracee stopped
    ref = &t;
    had_ref = true;
    break;
  }

  bool all_ok = true;
  bool found = false;
  for (auto &slot : g_attached) {
    uint64_t state = slot.state.load(std::memory_order_acquire);
    if (attached_tgid(state) != pid)
      continue;
    int tid = attached_tid(state);
    found = true;
    if (detach_thread_verified(pid, tid, 0)) {
      slot.state.compare_exchange_strong(state, 0,
                                         std::memory_order_acq_rel,
                                         std::memory_order_relaxed);
    } else {
      all_ok = false;
    }
  }

  if (ref) {
    if (all_ok)
      *ref = TraceeRef{};
    else
      ref->refs = 1; // preserve ownership and make a retry meaningful
  }

  // Never detach a thread group without a matching lease. A foreign owner may
  // still rely on that group being stopped.
  if (!found)
    return had_ref;
  return all_ok;
}

bool ProcessTracer::read_memory(int pid, uint64_t addr, void *buf, size_t len) {
  uint8_t *out = static_cast<uint8_t *>(buf);
  size_t done = 0;
  while (done < len) {
    struct iovec local = {out + done, len - done};
    struct iovec remote = {
        reinterpret_cast<void *>(static_cast<uintptr_t>(addr + done)),
        len - done};
    ssize_t rd = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (rd <= 0)
      return false;
    done += static_cast<size_t>(rd);
  }
  return true;
}

bool ProcessTracer::write_memory(int pid, uint64_t addr, const void *buf,
                                 size_t len) {
  const uint8_t *in = static_cast<const uint8_t *>(buf);
  size_t done = 0;
  while (done < len) {
    struct iovec local = {const_cast<uint8_t *>(in + done), len - done};
    struct iovec remote = {
        reinterpret_cast<void *>(static_cast<uintptr_t>(addr + done)),
        len - done};
    ssize_t wr = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (wr <= 0)
      return false;
    done += static_cast<size_t>(wr);
  }
  return true;
}


bool ProcessTracer::continue_process(int pid, int signal) {
  return ptrace(PTRACE_CONT, pid, nullptr,
                reinterpret_cast<void *>(static_cast<intptr_t>(signal))) >= 0;
}

bool ProcessTracer::interrupt(int tid) {
  return tid > 0 && ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) >= 0;
}






// Syscall number and arguments at a PTRACE_SYSCALL stop.
bool ProcessTracer::get_syscall(int pid, uint64_t *nr, uint64_t *args,
                                size_t n) {
  {
    user_regs_struct_64 regs{};
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return false;
    if (nr)
      *nr = regs.regs[8];
    for (size_t i = 0; i < n && i < 8; i++)
      args[i] = regs.regs[i];
    return true;
  }
  return false;
}

bool ProcessTracer::get_syscall_stop(int pid, SyscallStopInfo *info) {
  if (!info)
    return false;
  *info = {};
  HayabusaPtraceSyscallInfo raw{};
  long n = ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(raw), &raw);
  if (n < 0)
    return false;
  if (raw.op == kSyscallInfoEntry) {
    info->kind = SyscallStopKind::Entry;
    info->number = raw.payload.entry.nr;
    memcpy(info->args, raw.payload.entry.args, sizeof(info->args));
  } else if (raw.op == kSyscallInfoExit) {
    info->kind = SyscallStopKind::Exit;
    info->return_value = raw.payload.exit.rval;
    info->is_error = raw.payload.exit.is_error != 0;
  }
  return info->kind != SyscallStopKind::Unknown;
}

bool ProcessTracer::syscall_step(int pid, int signal) {
  return ptrace(PTRACE_SYSCALL, pid, nullptr,
                (void *)(intptr_t)signal) >= 0;
}

#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS 0x4200
#endif

// Follow every thread and child the target creates. Without this a packer that
// unpacks on a worker thread is invisible: only the initial thread is traced.
bool ProcessTracer::follow_children(int pid) {
  long opts = 0x00000001 | // TRACESYSGOOD: syscall stops are SIGTRAP|0x80
              0x00000002 | // TRACEFORK
              0x00000004 | // TRACEVFORK
              0x00000008 | // TRACECLONE
              0x00000010;  // TRACEEXEC
  return ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)opts) >= 0;
}

bool ProcessTracer::follow_thread_clones(int tid) {
  long opts = 0x00000002 | // PTRACE_O_TRACEFORK
              0x00000004 | // PTRACE_O_TRACEVFORK
              0x00000008 | // PTRACE_O_TRACECLONE
              0x00100000;  // PTRACE_O_EXITKILL
  return ptrace(PTRACE_SETOPTIONS, tid, 0, (void *)opts) >= 0;
}

bool ProcessTracer::clear_trace_options(int tid) {
  return tid > 0 && ptrace(PTRACE_SETOPTIONS, tid, nullptr, nullptr) >= 0;
}

SignalStopKind ProcessTracer::classify_signal_stop(int tid, int signal,
                                                   unsigned event) {
  if (tid <= 0 || signal <= 0)
    return SignalStopKind::Unknown;
  const bool job_control = signal == SIGSTOP || signal == SIGTSTP ||
                           signal == SIGTTIN || signal == SIGTTOU;
  if (event == kPtraceEventStop)
    return job_control ? SignalStopKind::GroupStop
                       : SignalStopKind::Unknown;
  if (event != 0)
    return SignalStopKind::Unknown;
  siginfo_t info{};
  errno = 0;
  if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) >= 0)
    return info.si_signo == signal ? SignalStopKind::Delivery
                                  : SignalStopKind::Unknown;
  return errno == EINVAL ? SignalStopKind::GroupStop
                         : SignalStopKind::Unknown;
}

bool ProcessTracer::adopt_attached_thread(int tgid, int tid) {
  if (tgid <= 0 || tid <= 0 || !thread_is_member(tgid, tid))
    return false;
  std::lock_guard<std::mutex> lock(g_attach_mu);
  const int owner_tid = tracer_thread_id();
  if (owner_tid == 0)
    return false;

  bool owns_group = false;
  for (const auto &tracee : g_tracees)
    if (tracee.pid == tgid && tracee.refs > 0 &&
        tracee.owner_tid == owner_tid) {
      owns_group = true;
      break;
    }
  if (!owns_group)
    return false;

  uint64_t wanted = attached_state(tgid, tid);
  AttachedThread *free_slot = nullptr;
  for (auto &slot : g_attached) {
    uint64_t state = slot.state.load(std::memory_order_acquire);
    if (state == wanted)
      return true;
    if (state == 0 && !free_slot)
      free_slot = &slot;
  }
  if (!free_slot)
    return false;
  uint64_t empty = 0;
  return free_slot->state.compare_exchange_strong(
      empty, wanted, std::memory_order_acq_rel, std::memory_order_relaxed);
}

bool ProcessTracer::track_auto_attached_child(int child) {
  if (child <= 0)
    return false;
  errno = 0;
  int pidfd = static_cast<int>(syscall(SYS_pidfd_open, child, 0));
  if (pidfd < 0 || pidfd == INT_MAX) {
    if (pidfd >= 0)
      close(pidfd);
    return false;
  }
  if (pidfd_send_signal_retry(pidfd, 0) < 0) {
    close(pidfd);
    return false;
  }
  // pidfd_open without PIDFD_THREAD is defined for a thread-group leader.
  // Bind that exact kernel object first, then prove the still-stopped numeric
  // PID is both its leader and our ptrace child before publishing it to fatal
  // cleanup. A descendant worker TID must instead be claimed through its
  // already-pinned leader below.
  int observed_tgid = 0;
  if (!ProcessTracer::read_thread_group_id(child, &observed_tgid) ||
      observed_tgid != child || !proc_tracee_is_owned_by_self(child)) {
    close(pidfd);
    return false;
  }
  const uint64_t desired = patch_child_state(child, pidfd);
  std::lock_guard<std::mutex> token_lock(g_patch_child_mu);
  std::atomic<uint64_t> *free_slot = nullptr;
  for (;;) {
    free_slot = nullptr;
    bool removed_stale = false;
    for (auto &slot : g_patch_children) {
      uint64_t state = slot.load(std::memory_order_acquire);
      if (patch_child_pid(state) == child) {
        const int existing_pidfd = patch_child_pidfd(state);
        if (existing_pidfd >= 0 &&
            pidfd_send_signal_retry(existing_pidfd, 0) >= 0 &&
            slot.load(std::memory_order_acquire) == state) {
          close(pidfd);
          g_patch_child_tokens[child] = state;
          return true;
        }
        if (slot.compare_exchange_strong(state, 0, std::memory_order_acq_rel,
                                         std::memory_order_relaxed)) {
          if (existing_pidfd >= 0)
            close(existing_pidfd);
          g_patch_child_tokens.erase(child);
          removed_stale = true;
        }
        free_slot = nullptr;
        break;
      }
      if (state == 0 && !free_slot)
        free_slot = &slot;
    }
    if (!free_slot) {
      if (removed_stale)
        continue;
      close(pidfd);
      return false;
    }

    uint64_t empty = 0;
    if (free_slot->compare_exchange_strong(
            empty, desired, std::memory_order_acq_rel,
            std::memory_order_relaxed))
      break;
    // Another producer won this slot between the scan and CAS. Rescan in a
    // bounded stack frame: a recursive retry could overflow under a clone
    // storm precisely while fatal cleanup needs this registry most.
  }

  // Close the race with cleanup_all_attached(): either its scan observes this
  // slot, or this recheck observes the permanent fatal sentinel and kills the
  // child itself.
  if (g_active_patch_tgid.load(std::memory_order_acquire) ==
      kFatalCleanupStarted) {
    uint64_t wanted = desired;
    if (free_slot->compare_exchange_strong(
            wanted, 0, std::memory_order_acq_rel,
            std::memory_order_relaxed)) {
      (void)pidfd_send_signal_retry(pidfd, SIGKILL);
      close(pidfd);
    }
    return false;
  }
  g_patch_child_tokens[child] = desired;
  return true;
}

static uint64_t tracked_patch_child_token(int child) {
  std::lock_guard<std::mutex> token_lock(g_patch_child_mu);
  const auto token = g_patch_child_tokens.find(child);
  return token == g_patch_child_tokens.end() ? 0 : token->second;
}

static bool tracked_patch_child_alive(uint64_t token) {
  const int leader = patch_child_pid(token);
  const int pidfd = patch_child_pidfd(token);
  if (leader <= 0 || pidfd < 0)
    return false;
  for (auto &slot : g_patch_children) {
    if (slot.load(std::memory_order_acquire) != token)
      continue;
    if (pidfd_send_signal_retry(pidfd, 0) < 0)
      return false;
    return slot.load(std::memory_order_acquire) == token;
  }
  return false;
}

bool ProcessTracer::claim_auto_attached_tracee(int original_tgid, int tid,
                                               int *tracee_tgid,
                                               bool *original_group) {
  if (tracee_tgid)
    *tracee_tgid = 0;
  if (original_group)
    *original_group = false;
  if (original_tgid <= 0 || tid <= 0 || !tracee_tgid || !original_group ||
      !proc_tracee_is_owned_by_self(tid))
    return false;

  int observed_tgid = 0;
  if (!ProcessTracer::read_thread_group_id(tid, &observed_tgid) ||
      observed_tgid <= 0)
    return false;

  if (observed_tgid == original_tgid) {
    if (!ProcessTracer::adopt_attached_thread(original_tgid, tid))
      return false;
    *tracee_tgid = observed_tgid;
    *original_group = true;
    return true;
  }

  if (observed_tgid == tid) {
    if (!ProcessTracer::track_auto_attached_child(tid))
      return false;
    *tracee_tgid = observed_tgid;
    return true;
  }

  // A non-leader TID has no process pidfd on the Android kernels Hayabusa
  // supports. Its exact fatal-cleanup identity is the live leader pidfd plus
  // stopped /proc membership and TracerPid proof. Never publish a bare worker
  // TID unless that chain is complete.
  const uint64_t leader_token = tracked_patch_child_token(observed_tgid);
  if (!tracked_patch_child_alive(leader_token) ||
      !thread_is_member(observed_tgid, tid))
    return false;

  const uint64_t wanted = attached_state(observed_tgid, tid);
  AttachedThread *free_slot = nullptr;
  for (auto &slot : g_attached) {
    const uint64_t state = slot.state.load(std::memory_order_acquire);
    if (state == wanted) {
      *tracee_tgid = observed_tgid;
      return true;
    }
    if (state == 0 && !free_slot)
      free_slot = &slot;
  }
  if (!free_slot)
    return false;
  uint64_t empty = 0;
  if (!free_slot->state.compare_exchange_strong(
          empty, wanted, std::memory_order_acq_rel,
          std::memory_order_relaxed))
    return false;

  // Fatal cleanup either observes this verified slot, or wins first and makes
  // this publication terminal. In the latter case remove the late slot and
  // bind SIGKILL to the descendant group's exact leader pidfd.
  if (g_active_patch_tgid.load(std::memory_order_acquire) ==
          kFatalCleanupStarted ||
      !tracked_patch_child_alive(leader_token)) {
    uint64_t published = wanted;
    free_slot->state.compare_exchange_strong(
        published, 0, std::memory_order_acq_rel,
        std::memory_order_relaxed);
    const int leader_pidfd = patch_child_pidfd(leader_token);
    if (leader_pidfd >= 0)
      (void)pidfd_send_signal_retry(leader_pidfd, SIGKILL);
    return false;
  }

  *tracee_tgid = observed_tgid;
  return true;
}

static void untrack_patch_child_token(int child, uint64_t wanted) {
  if (child <= 0 || wanted == 0)
    return;
  {
    std::lock_guard<std::mutex> token_lock(g_patch_child_mu);
    auto token = g_patch_child_tokens.find(child);
    if (token != g_patch_child_tokens.end() && token->second == wanted)
      g_patch_child_tokens.erase(token);
  }
  for (auto &slot : g_patch_children) {
    uint64_t state = wanted;
    if (slot.compare_exchange_strong(state, 0, std::memory_order_acq_rel,
                                     std::memory_order_relaxed)) {
      const int pidfd = patch_child_pidfd(wanted);
      if (pidfd >= 0)
        close(pidfd);
      return;
    }
  }
}

void ProcessTracer::untrack_auto_attached_child(int child) {
  untrack_patch_child_token(child, tracked_patch_child_token(child));
}

void ProcessTracer::forget_auto_attached_tracee(int tgid, int tid) {
  if (tgid > 0 && tid > 0)
    forget_attached(tgid, tid);
}

bool ProcessTracer::release_auto_attached_child(int child, int signal,
                                                int tgid,
                                                bool release_group) {
  if (child <= 0)
    return false;
  const int owner_tgid = tgid > 0 ? tgid : child;

  auto forget_released = [&]() {
    forget_attached(owner_tgid, child);
    if (release_group)
      untrack_auto_attached_child(owner_tgid);
  };

  // Callers consume the kernel-generated initial child stop before restoring
  // its copied code. At that point a direct verified detach cannot run it
  // between restoration and ownership release.
  if (detach_thread_verified(owner_tgid, child, signal)) {
    forget_released();
    return true;
  }
  for (int retry = 0; retry < 200; retry++) {
    int status = 0;
    errno = 0;
    pid_t waited = waitpid(child, &status, __WALL | WNOHANG);
    if (waited == child) {
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        forget_released();
        return true;
      }
      if (WIFSTOPPED(status)) {
        bool detached = detach_thread_verified(owner_tgid, child, signal);
        if (detached)
          forget_released();
        return detached;
      }
      continue;
    }
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      if ((errno == ECHILD || errno == ESRCH) &&
          !thread_is_member(owner_tgid, child)) {
        forget_released();
        return true;
      }
      return false;
    }
    usleep(1000);
  }
  bool gone = !thread_is_member(owner_tgid, child);
  if (gone)
    forget_released();
  return gone;
}

// pid of the thread/process just created, at a clone/fork event stop.
bool ProcessTracer::event_child(int pid, int *child) {
  unsigned long msg = 0;
  if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg) < 0)
    return false;
  *child = (int)msg;
  return true;
}

static std::vector<int> owned_group_tids(int tgid) {
  std::vector<int> tids;
  for (auto &slot : g_attached) {
    const uint64_t state = slot.state.load(std::memory_order_acquire);
    if (attached_tgid(state) == tgid && attached_tid(state) > 0)
      tids.push_back(attached_tid(state));
  }
  std::sort(tids.begin(), tids.end());
  tids.erase(std::unique(tids.begin(), tids.end()), tids.end());
  return tids;
}

enum class PatchChildResult { SameGroup, SeparateContained, Failed };

static PatchChildResult contain_patch_child_event(
    int parent_tgid, int event_tid, bool resume_same_group,
    const AttachDeadline &deadline, int *same_group_child = nullptr) {
  if (same_group_child)
    *same_group_child = 0;
  unsigned long message = 0;
  if (ptrace(PTRACE_GETEVENTMSG, event_tid, nullptr, &message) < 0 ||
      message == 0 || message > static_cast<unsigned long>(INT_MAX))
    return PatchChildResult::Failed;
  const int child = static_cast<int>(message);

  bool child_stopped = false;
  while (std::chrono::steady_clock::now() < deadline) {
    int status = 0;
    errno = 0;
    const pid_t waited = waitpid(child, &status, __WALL | WNOHANG);
    if (waited == 0) {
      usleep(1000);
      continue;
    }
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      return PatchChildResult::Failed;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      return PatchChildResult::SeparateContained;
    }
    if (WIFSTOPPED(status)) {
      child_stopped = true;
      break;
    }
  }
  if (!child_stopped)
    return PatchChildResult::Failed;

  int child_tgid = 0;
  bool original_group = false;
  while (std::chrono::steady_clock::now() < deadline && child_tgid == 0) {
    if (ProcessTracer::claim_auto_attached_tracee(
            parent_tgid, child, &child_tgid, &original_group))
      break;
    usleep(1000);
  }
  if (child_tgid <= 0)
    return PatchChildResult::Failed;
  if (original_group) {
    if (!ProcessTracer::follow_thread_clones(child))
      return PatchChildResult::Failed;
    if (resume_same_group &&
        ptrace(PTRACE_CONT, child, nullptr, nullptr) < 0)
      return PatchChildResult::Failed;
    if (same_group_child)
      *same_group_child = child;
    return PatchChildResult::SameGroup;
  }

  const uint64_t child_token = tracked_patch_child_token(child_tgid);
  if (child_token == 0 || !tracked_patch_child_alive(child_token))
    return PatchChildResult::Failed;

  // Any non-thread child can carry a private copy of the temporary stub or
  // patched text. It never leaves exact ptrace ownership: kill from its
  // kernel-generated initial stop and retain the pidfd registry entry until
  // that fatal signal has been bound to the exact child.
  bool kill_injected = false;
  bool registry_released = false;
  while (std::chrono::steady_clock::now() < deadline) {
    if (!kill_injected) {
      errno = 0;
      if (ptrace(PTRACE_CONT, child, nullptr,
                 reinterpret_cast<void *>(static_cast<intptr_t>(SIGKILL))) >=
              0 ||
          errno == ESRCH) {
        kill_injected = true;
      } else {
        // Older kernels can reject signal injection from the synthetic initial
        // child stop. PTRACE_KILL is still bound to this traced task.
        errno = 0;
        if (ptrace(PTRACE_KILL, child, nullptr, nullptr) < 0 && errno != ESRCH)
          return PatchChildResult::Failed;
        kill_injected = true;
      }
      if (kill_injected && !registry_released) {
        // The fatal signal is now bound to the exact ptrace child. Drop and
        // close the registry token before waitpid reaps it, eliminating the
        // numeric-PID reuse interval between reap and untrack.
        ProcessTracer::forget_auto_attached_tracee(child_tgid, child);
        untrack_patch_child_token(child_tgid, child_token);
        registry_released = true;
      }
    }
    int status = 0;
    errno = 0;
    const pid_t waited = waitpid(child, &status, __WALL | WNOHANG);
    if (waited == child && (WIFEXITED(status) || WIFSIGNALED(status))) {
      return PatchChildResult::SeparateContained;
    }
    if (waited == child && WIFSTOPPED(status))
      kill_injected = false;
    if (waited < 0 && (errno == ECHILD || errno == ESRCH)) {
      int observed_tgid = 0;
      if (!ProcessTracer::read_thread_group_id(child, &observed_tgid)) {
        return PatchChildResult::SeparateContained;
      }
    } else if (waited < 0 && errno != EINTR) {
      return PatchChildResult::Failed;
    }
    usleep(1000);
  }
  return PatchChildResult::Failed;
}

enum class PatchQuiesceResult { Stopped, GroupStopped, Gone, Failed };

static PatchQuiesceResult quiesce_owned_patch_group(
    int tgid, std::set<int> stopped, const AttachDeadline &deadline) {
  std::set<int> interrupted;
  bool group_stopped = false;
  while (std::chrono::steady_clock::now() < deadline) {
    std::vector<int> tids = owned_group_tids(tgid);
    if (tids.empty())
      return thread_is_member(tgid, tgid) ? PatchQuiesceResult::Failed
                                          : PatchQuiesceResult::Gone;

    for (int tid : tids) {
      if (stopped.count(tid) != 0 || interrupted.count(tid) != 0)
        continue;
      errno = 0;
      if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) >= 0 ||
          errno == EIO) {
        interrupted.insert(tid);
      } else if (errno == ESRCH && !thread_is_member(tgid, tid)) {
        forget_attached(tgid, tid);
      } else {
        return PatchQuiesceResult::Failed;
      }
    }

    bool observed = false;
    tids = owned_group_tids(tgid);
    for (int tid : tids) {
      if (stopped.count(tid) != 0)
        continue;
      int status = 0;
      errno = 0;
      const pid_t waited = waitpid(tid, &status, __WALL | WNOHANG);
      if (waited == 0)
        continue;
      if (waited < 0) {
        if (errno == EINTR)
          continue;
        if ((errno == ECHILD || errno == ESRCH) &&
            !thread_is_member(tgid, tid)) {
          forget_attached(tgid, tid);
          observed = true;
          continue;
        }
        return PatchQuiesceResult::Failed;
      }
      observed = true;
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        forget_attached(tgid, tid);
        if (tid == tgid)
          return PatchQuiesceResult::Gone;
        continue;
      }
      if (!WIFSTOPPED(status))
        continue;

      const int signal = WSTOPSIG(status);
      const unsigned event =
          (static_cast<unsigned>(status) >> 16) & 0xffffu;
      if (event == kPtraceEventFork || event == kPtraceEventVfork ||
          event == kPtraceEventClone) {
        int same_group_child = 0;
        if (contain_patch_child_event(tgid, tid, false, deadline,
                                      &same_group_child) ==
            PatchChildResult::Failed)
          return PatchQuiesceResult::Failed;
        stopped.insert(tid);
        if (same_group_child > 0)
          stopped.insert(same_group_child);
        continue;
      }
      const bool job_control = signal == SIGSTOP || signal == SIGTSTP ||
                               signal == SIGTTIN || signal == SIGTTOU;
      if (event == kPtraceEventStop) {
        stopped.insert(tid);
        if (job_control)
          group_stopped = true;
        continue;
      }
      if (event != 0)
        return PatchQuiesceResult::Failed;

      const SignalStopKind kind =
          ProcessTracer::classify_signal_stop(tid, signal, event);
      if (kind == SignalStopKind::GroupStop) {
        stopped.insert(tid);
        group_stopped = true;
        continue;
      }
      if (kind != SignalStopKind::Delivery)
        return PatchQuiesceResult::Failed;
      // Deliver a genuine signal exactly once, then let the already-requested
      // PTRACE_INTERRUPT regain a signal-free event stop.
      if (ptrace(PTRACE_CONT, tid, nullptr,
                 reinterpret_cast<void *>(static_cast<intptr_t>(signal))) < 0)
        return PatchQuiesceResult::Failed;
    }

    tids = owned_group_tids(tgid);
    bool all_stopped = !tids.empty();
    for (int tid : tids)
      all_stopped = all_stopped && stopped.count(tid) != 0;
    std::vector<int> visible;
    if (all_stopped && ProcessTracer::list_threads_complete(tgid, &visible)) {
      for (int tid : visible)
        if (!already_attached(tgid, tid) || stopped.count(tid) == 0) {
          all_stopped = false;
          break;
        }
    } else {
      all_stopped = false;
    }
    if (all_stopped) {
      for (int tid : tids) {
        int observed_tgid = 0;
        if (!ProcessTracer::read_thread_group_id(tid, &observed_tgid) ||
            observed_tgid != tgid ||
            !ProcessTracer::clear_trace_options(tid))
          return PatchQuiesceResult::Failed;
      }
      return group_stopped ? PatchQuiesceResult::GroupStopped
                           : PatchQuiesceResult::Stopped;
    }
    if (!observed)
      usleep(1000);
  }
  return PatchQuiesceResult::Failed;
}

PatchSupervisionResult ProcessTracer::supervise_patch_target(
    int pid, const std::function<bool()> &keep_running,
    const std::function<void()> &on_tick) {
  if (pid <= 0 || !keep_running || !current_thread_holds_tracee_lease(pid))
    return PatchSupervisionResult::Failed;
  const uint64_t generation =
      g_active_patch_generation.load(std::memory_order_acquire);
  if (generation == 0 || !active_patch_identity_alive(pid, generation))
    return PatchSupervisionResult::TargetGone;

  std::vector<int> tids = owned_group_tids(pid);
  if (tids.empty())
    return PatchSupervisionResult::Failed;
  std::vector<int> resumed;
  for (int tid : tids) {
    if (!follow_thread_clones(tid))
      break;
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) < 0)
      break;
    resumed.push_back(tid);
  }
  if (resumed.size() != tids.size()) {
    std::set<int> stayed_stopped;
    for (int tid : tids)
      if (std::find(resumed.begin(), resumed.end(), tid) == resumed.end())
        stayed_stopped.insert(tid);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    PatchQuiesceResult quiesced =
        quiesce_owned_patch_group(pid, std::move(stayed_stopped), deadline);
    return quiesced == PatchQuiesceResult::Gone
               ? PatchSupervisionResult::TargetGone
               : PatchSupervisionResult::Failed;
  }

  bool terminal_failure = false;
  bool target_gone = false;
  bool saw_group_stop = false;
  std::set<int> stopped;
  auto next_tick = std::chrono::steady_clock::now();
  while (keep_running()) {
    if (!active_patch_identity_alive(pid, generation)) {
      target_gone = true;
      break;
    }
    const auto now = std::chrono::steady_clock::now();
    if (on_tick && now >= next_tick) {
      try {
        on_tick();
      } catch (...) {
        terminal_failure = true;
        break;
      }
      next_tick = now + std::chrono::milliseconds(100);
    }

    bool observed = false;
    for (int tid : owned_group_tids(pid)) {
      int status = 0;
      errno = 0;
      const pid_t waited = waitpid(tid, &status, __WALL | WNOHANG);
      if (waited == 0)
        continue;
      if (waited < 0) {
        if (errno == EINTR)
          continue;
        if ((errno == ECHILD || errno == ESRCH) &&
            !thread_is_member(pid, tid)) {
          forget_attached(pid, tid);
          if (tid == pid)
            target_gone = true;
          observed = true;
          continue;
        }
        terminal_failure = true;
        break;
      }
      observed = true;
      if (WIFEXITED(status) || WIFSIGNALED(status)) {
        forget_attached(pid, tid);
        if (tid == pid)
          target_gone = true;
        continue;
      }
      if (!WIFSTOPPED(status))
        continue;

      const int signal = WSTOPSIG(status);
      const unsigned event =
          (static_cast<unsigned>(status) >> 16) & 0xffffu;
      if (event == kPtraceEventFork || event == kPtraceEventVfork ||
          event == kPtraceEventClone) {
        if (contain_patch_child_event(
                pid, tid, true,
                std::chrono::steady_clock::now() + std::chrono::seconds(2)) ==
            PatchChildResult::Failed ||
            ptrace(PTRACE_CONT, tid, nullptr, nullptr) < 0) {
          terminal_failure = true;
          break;
        }
        continue;
      }
      const bool job_control = signal == SIGSTOP || signal == SIGTSTP ||
                               signal == SIGTTIN || signal == SIGTTOU;
      if (event == kPtraceEventStop && job_control) {
        stopped.insert(tid);
        saw_group_stop = true;
        break;
      }
      if (event != 0) {
        terminal_failure = true;
        break;
      }
      const SignalStopKind kind = classify_signal_stop(tid, signal, event);
      if (kind == SignalStopKind::GroupStop) {
        stopped.insert(tid);
        saw_group_stop = true;
        break;
      }
      if (kind != SignalStopKind::Delivery ||
          ptrace(PTRACE_CONT, tid, nullptr,
                 reinterpret_cast<void *>(static_cast<intptr_t>(signal))) < 0) {
        terminal_failure = true;
        break;
      }
    }
    if (terminal_failure || target_gone || saw_group_stop)
      break;
    if (!observed)
      usleep(1000);
  }

  if (target_gone) {
    cleanup_all_attached();
    reset_attach_bookkeeping();
    return PatchSupervisionResult::TargetGone;
  }
  if (terminal_failure) {
    cleanup_all_attached();
    reset_attach_bookkeeping();
    return PatchSupervisionResult::Failed;
  }

  const PatchQuiesceResult quiesced = quiesce_owned_patch_group(
      pid, std::move(stopped),
      std::chrono::steady_clock::now() + std::chrono::seconds(5));
  if (quiesced == PatchQuiesceResult::Stopped &&
      active_patch_identity_alive(pid, generation))
    return PatchSupervisionResult::Stopped;
  if (quiesced == PatchQuiesceResult::GroupStopped &&
      active_patch_identity_alive(pid, generation))
    return PatchSupervisionResult::GroupStopped;
  cleanup_all_attached();
  reset_attach_bookkeeping();
  return quiesced == PatchQuiesceResult::Gone
             ? PatchSupervisionResult::TargetGone
             : PatchSupervisionResult::Failed;
}


bool ProcessTracer::get_pc(int pid, uint64_t *pc) {
  if (!pc)
    return false;
  user_regs_struct_64 regs{};
  struct iovec iov = {&regs, sizeof(regs)};
  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
    return false;
  *pc = regs.pc;
  return true;
}

bool ProcessTracer::set_pc(int pid, uint64_t pc) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  user_regs_struct_64 regs{};
  struct iovec iov = {&regs, sizeof(regs)};
  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
    return false;
  regs.pc = pc;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);
  if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0)
    return false;
  user_regs_struct_64 verify{};
  iov.iov_base = &verify;
  iov.iov_len = sizeof(verify);
  return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) >= 0 &&
         verify.pc == pc;
}


// Executable/readable file-backed views of read_maps(), plus a synthetic name
// for anonymous regions so JIT/unpacked code is still addressable by name.
std::vector<MapEntry> ProcessTracer::get_library_ranges(int pid) {
  std::vector<MapEntry> ranges;
  for (auto &e : Memory::read_maps(pid)) {
    if (e.perms.rfind("r-xp", 0) != 0 && e.perms.rfind("r--p", 0) != 0)
      continue;
    if (e.name.empty()) {
      std::ostringstream ss;
      ss << "anon_" << e.start;
      e.name = ss.str();
    }
    ranges.push_back(std::move(e));
  }
  return ranges;
}

std::string
ProcessTracer::find_library_for_address(const std::vector<MapEntry> &ranges,
                                       uint64_t addr) {
  for (const auto &r : ranges) {
    if (addr >= r.start && addr < r.end)
      return r.name;
  }
  return "";
}

uint64_t FunctionHooker::allocate_remote(int pid, size_t size) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  int syscall_nr = SYS_MMAP_64;
  uint64_t result = execute_syscall(
      pid,
      {0, (uint64_t)size, (uint64_t)(PROT_READ | PROT_WRITE),
       (uint64_t)(MAP_PRIVATE | MAP_ANONYMOUS), (uint64_t)-1, 0},
      syscall_nr);
  if (syscall_failed(result)) {
    fprintf(stderr,
            "[ptrace] remote mmap(%zu) failed: return=%lld errno=%lld\n",
            size, static_cast<long long>(result),
            static_cast<long long>(-static_cast<int64_t>(result)));
    return 0;
  }
  return result;
}

bool FunctionHooker::free_remote(int pid, uint64_t addr, size_t size) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  int syscall_nr = SYS_MUNMAP_64;
  uint64_t ret = execute_syscall(pid, {addr, (uint64_t)size}, syscall_nr);
  return ret == 0;
}

static bool checked_u64_add(uint64_t lhs, uint64_t rhs, uint64_t *out) {
  if (!out || rhs > std::numeric_limits<uint64_t>::max() - lhs)
    return false;
  *out = lhs + rhs;
  return true;
}

static bool checked_u64_mul(uint64_t lhs, uint64_t rhs, uint64_t *out) {
  if (!out || (lhs != 0 && rhs > std::numeric_limits<uint64_t>::max() / lhs))
    return false;
  *out = lhs * rhs;
  return true;
}

template <typename T>
static bool read_remote_object(int pid, uint64_t address, T *out) {
  if (!out)
    return false;
  std::array<uint8_t, sizeof(T)> bytes{};
  if (!ProcessTracer::read_memory(pid, address, bytes.data(), bytes.size()))
    return false;
  memcpy(out, bytes.data(), sizeof(*out));
  return true;
}

static bool remote_object_address(uint64_t base, uint64_t index,
                                  uint64_t object_size, uint64_t *out) {
  uint64_t offset = 0;
  return checked_u64_mul(index, object_size, &offset) &&
         checked_u64_add(base, offset, out);
}

static bool remote_range_in_loads(const std::vector<Elf64_Phdr> &phdrs,
                                  uint64_t load_bias, uint64_t address,
                                  uint64_t size,
                                  uint64_t *containing_load_end = nullptr) {
  if (size == 0)
    return false;
  uint64_t range_end = 0;
  if (!checked_u64_add(address, size, &range_end))
    return false;
  for (const Elf64_Phdr &ph : phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_memsz == 0)
      continue;
    uint64_t load_start = 0;
    uint64_t load_end = 0;
    if (!checked_u64_add(load_bias, ph.p_vaddr, &load_start) ||
        !checked_u64_add(load_start, ph.p_memsz, &load_end)) {
      return false;
    }
    if (address >= load_start && range_end <= load_end) {
      if (containing_load_end)
        *containing_load_end = load_end;
      return true;
    }
  }
  return false;
}

static bool
remote_range_in_executable_loads(const std::vector<Elf64_Phdr> &phdrs,
                                 uint64_t load_bias, uint64_t address,
                                 uint64_t size) {
  if (size == 0)
    return false;
  uint64_t range_end = 0;
  if (!checked_u64_add(address, size, &range_end))
    return false;
  for (const Elf64_Phdr &ph : phdrs) {
    if (ph.p_type != PT_LOAD || (ph.p_flags & PF_X) == 0 || ph.p_memsz == 0)
      continue;
    uint64_t load_start = 0;
    uint64_t load_end = 0;
    if (!checked_u64_add(load_bias, ph.p_vaddr, &load_start) ||
        !checked_u64_add(load_start, ph.p_memsz, &load_end))
      return false;
    if (address >= load_start && range_end <= load_end)
      return true;
  }
  return false;
}

static bool current_executable_object_range(int pid, uint64_t address,
                                            uint64_t size,
                                            const std::string &object_path) {
  uint64_t end = 0;
  if (pid <= 0 || size == 0 || object_path.empty() ||
      !checked_u64_add(address, size, &end))
    return false;
  for (const MapEntry &mapping : Memory::read_maps(pid)) {
    if (mapping.name != object_path ||
        mapping.perms.find('x') == std::string::npos)
      continue;
    if (address >= mapping.start && end <= mapping.end)
      return true;
  }
  return false;
}

// Dynamic pointers in an in-memory ELF normally retain their link-time virtual
// address. A few Android packers rewrite them to runtime addresses. Accept
// either representation only when the complete requested object lies in a
// declared PT_LOAD; comparing the raw value numerically with the mapping base is
// not sufficient for non-zero-p_vaddr images.
static bool resolve_remote_dynamic_pointer(
    const std::vector<Elf64_Phdr> &phdrs, uint64_t load_bias, uint64_t value,
    uint64_t size, uint64_t *out, uint64_t *containing_load_end = nullptr) {
  if (!out || value == 0 || size == 0)
    return false;
  uint64_t raw_load_end = 0;
  const bool raw_valid = remote_range_in_loads(
      phdrs, load_bias, value, size,
      containing_load_end ? &raw_load_end : nullptr);
  uint64_t relocated = 0;
  uint64_t relocated_load_end = 0;
  const bool relocated_valid =
      checked_u64_add(load_bias, value, &relocated) &&
      remote_range_in_loads(phdrs, load_bias, relocated, size,
                            containing_load_end ? &relocated_load_end
                                                : nullptr);
  // A value that independently denotes two different PT_LOAD objects is not a
  // representation choice; it is ambiguous attacker-controlled metadata.
  if (raw_valid && relocated_valid && value != relocated)
    return false;
  if (!raw_valid && !relocated_valid)
    return false;
  if (raw_valid) {
    *out = value;
    if (containing_load_end)
      *containing_load_end = raw_load_end;
  } else {
    *out = relocated;
    if (containing_load_end)
      *containing_load_end = relocated_load_end;
  }
  return true;
}

static bool read_remote_cstr(int pid, uint64_t address, size_t max_len,
                             std::string *out) {
  if (!out || max_len == 0)
    return false;
  out->clear();
  out->reserve(std::min<size_t>(max_len, 256));
  size_t offset = 0;
  while (offset < max_len) {
    std::array<char, 64> chunk{};
    const size_t to_read = std::min(chunk.size(), max_len - offset);
    uint64_t chunk_address = 0;
    if (!checked_u64_add(address, static_cast<uint64_t>(offset),
                         &chunk_address) ||
        !ProcessTracer::read_memory(pid, chunk_address, chunk.data(),
                                    to_read)) {
      out->clear();
      return false;
    }
    for (size_t i = 0; i < to_read; ++i) {
      if (chunk[i] == '\0')
        return true;
      out->push_back(chunk[i]);
    }
    offset += to_read;
  }
  out->clear();
  return false;
}

static uint64_t parse_remote_symbol_impl(int pid, uint64_t header_address,
                                         const std::string &sym) {
  constexpr uint16_t kMaxProgramHeaders = 4096;
  constexpr uint64_t kMaxHeaderBytes = 1ULL << 20;
  constexpr uint64_t kMaxDynamicBytes = 1ULL << 20;
  constexpr uint32_t kMaxHashEntries = 1U << 20;
  constexpr uint64_t kMaxStringTableBytes = 256ULL << 20;
  constexpr size_t kMaxSymbolNameBytes = 4096;

  if (pid <= 0 || header_address == 0 || sym.empty())
    return 0;

  Elf64_Ehdr ehdr{};
  if (!read_remote_object(pid, header_address, &ehdr) ||
      memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
      ehdr.e_ident[EI_VERSION] != EV_CURRENT || ehdr.e_version != EV_CURRENT ||
      (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC) ||
      ehdr.e_machine != EM_AARCH64 ||
      ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
      ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0 ||
      ehdr.e_phnum > kMaxProgramHeaders || ehdr.e_phoff == 0 ||
      ehdr.e_phoff > kMaxHeaderBytes) {
    return 0;
  }

  uint64_t phdr_table = 0;
  uint64_t phdr_span = 0;
  uint64_t phdr_end = 0;
  uint64_t phdr_file_end = 0;
  if (!checked_u64_add(header_address, ehdr.e_phoff, &phdr_table) ||
      !checked_u64_mul(ehdr.e_phnum, sizeof(Elf64_Phdr), &phdr_span) ||
      !checked_u64_add(phdr_table, phdr_span, &phdr_end) ||
      !checked_u64_add(ehdr.e_phoff, phdr_span, &phdr_file_end) ||
      phdr_file_end > kMaxHeaderBytes) {
    return 0;
  }
  (void)phdr_end;

  std::vector<Elf64_Phdr> phdrs;
  try {
    phdrs.resize(ehdr.e_phnum);
  } catch (...) {
    return 0;
  }
  for (size_t i = 0; i < phdrs.size(); ++i) {
    uint64_t address = 0;
    if (!remote_object_address(phdr_table, i, sizeof(Elf64_Phdr), &address) ||
        !read_remote_object(pid, address, &phdrs[i])) {
      return 0;
    }
    const Elf64_Phdr &ph = phdrs[i];
    uint64_t ignored = 0;
    if (ph.p_type != PT_LOAD)
      continue;
    if (ph.p_filesz > ph.p_memsz || ph.p_memsz == 0 ||
        !checked_u64_add(ph.p_vaddr, ph.p_memsz, &ignored) ||
        !checked_u64_add(ph.p_offset, ph.p_filesz, &ignored) ||
        (ph.p_align > 1 &&
         ((ph.p_align & (ph.p_align - 1)) != 0 ||
          (ph.p_vaddr & (ph.p_align - 1)) !=
              (ph.p_offset & (ph.p_align - 1))))) {
      return 0;
    }
  }

  // The address taken from /proc/<pid>/maps is the runtime address of file
  // offset zero, not necessarily the ELF load bias. Locate the unique PT_LOAD
  // which maps the ELF and program headers, then subtract its non-zero p_vaddr.
  const Elf64_Phdr *header_load = nullptr;
  for (const Elf64_Phdr &ph : phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_offset != 0 ||
        ph.p_filesz < sizeof(Elf64_Ehdr) || ph.p_filesz < phdr_file_end)
      continue;
    if (header_load)
      return 0;
    header_load = &ph;
  }
  if (!header_load || header_address < header_load->p_vaddr)
    return 0;
  const uint64_t load_bias = header_address - header_load->p_vaddr;
  uint64_t verified_header = 0;
  if (!checked_u64_add(load_bias, header_load->p_vaddr, &verified_header) ||
      verified_header != header_address ||
      !remote_range_in_loads(phdrs, load_bias, header_address,
                             phdr_file_end, nullptr)) {
    return 0;
  }

  uint64_t dyn_vaddr = 0;
  uint64_t dyn_size = 0;
  bool found_dynamic = false;
  for (const Elf64_Phdr &ph : phdrs) {
    if (ph.p_type != PT_DYNAMIC)
      continue;
    if (found_dynamic || ph.p_filesz > ph.p_memsz ||
        ph.p_memsz < sizeof(Elf64_Dyn) ||
        ph.p_memsz > kMaxDynamicBytes ||
        ph.p_memsz % sizeof(Elf64_Dyn) != 0) {
      return 0;
    }
    uint64_t dyn_end = 0;
    if (!checked_u64_add(ph.p_vaddr, ph.p_memsz, &dyn_end))
      return 0;
    bool contained_in_load = false;
    for (const Elf64_Phdr &load : phdrs) {
      if (load.p_type != PT_LOAD || ph.p_vaddr < load.p_vaddr)
        continue;
      uint64_t load_end = 0;
      if (checked_u64_add(load.p_vaddr, load.p_memsz, &load_end) &&
          dyn_end <= load_end) {
        contained_in_load = true;
        break;
      }
    }
    if (!contained_in_load)
      return 0;
    dyn_vaddr = ph.p_vaddr;
    dyn_size = ph.p_memsz;
    found_dynamic = true;
  }
  if (!found_dynamic)
    return 0;

  uint64_t dyn_address = 0;
  if (!checked_u64_add(load_bias, dyn_vaddr, &dyn_address) ||
      !remote_range_in_loads(phdrs, load_bias, dyn_address, dyn_size))
    return 0;

  uint64_t symtab_value = 0;
  uint64_t strtab_value = 0;
  uint64_t hash_value = 0;
  uint64_t gnu_hash_value = 0;
  uint64_t strtab_size = 0;
  uint64_t syment_size = 0;
  bool saw_null = false;
  bool saw_hash_tag = false;
  bool saw_gnu_hash_tag = false;
  const uint64_t dynamic_count = dyn_size / sizeof(Elf64_Dyn);
  for (uint64_t i = 0; i < dynamic_count; ++i) {
    uint64_t address = 0;
    Elf64_Dyn dyn{};
    if (!remote_object_address(dyn_address, i, sizeof(Elf64_Dyn), &address) ||
        !read_remote_object(pid, address, &dyn)) {
      return 0;
    }
    if (dyn.d_tag == DT_NULL) {
      saw_null = true;
      break;
    }
    switch (dyn.d_tag) {
    case DT_SYMTAB:
      symtab_value = dyn.d_un.d_ptr;
      break;
    case DT_STRTAB:
      strtab_value = dyn.d_un.d_ptr;
      break;
    case DT_STRSZ:
      strtab_size = dyn.d_un.d_val;
      break;
    case DT_SYMENT:
      syment_size = dyn.d_un.d_val;
      break;
    case DT_HASH:
      if (saw_hash_tag)
        return 0;
      saw_hash_tag = true;
      hash_value = dyn.d_un.d_ptr;
      break;
    case DT_GNU_HASH:
      if (saw_gnu_hash_tag)
        return 0;
      saw_gnu_hash_tag = true;
      gnu_hash_value = dyn.d_un.d_ptr;
      break;
    }
  }
  if (!saw_null || symtab_value == 0 || strtab_value == 0 ||
      strtab_size == 0 || strtab_size > kMaxStringTableBytes ||
      syment_size != sizeof(Elf64_Sym) ||
      (!saw_hash_tag && !saw_gnu_hash_tag) ||
      (saw_hash_tag && hash_value == 0) ||
      (saw_gnu_hash_tag && gnu_hash_value == 0)) {
    return 0;
  }

  // DT_* pointers normally remain link-time virtual addresses in memory;
  // relocated absolute pointers used by some packers are accepted too.
  uint64_t symtab = 0;
  uint64_t strtab = 0;
  uint64_t hash = 0;
  uint64_t gnu_hash = 0;
  uint64_t gnu_hash_load_end = 0;
  if (!resolve_remote_dynamic_pointer(phdrs, load_bias, symtab_value,
                                      sizeof(Elf64_Sym), &symtab) ||
      !resolve_remote_dynamic_pointer(phdrs, load_bias, strtab_value,
                                      strtab_size, &strtab) ||
      (hash_value != 0 &&
       !resolve_remote_dynamic_pointer(phdrs, load_bias, hash_value,
                                       2 * sizeof(uint32_t), &hash)) ||
      (gnu_hash_value != 0 &&
       !resolve_remote_dynamic_pointer(
           phdrs, load_bias, gnu_hash_value, 4 * sizeof(uint32_t), &gnu_hash,
           &gnu_hash_load_end))) {
    return 0;
  }

  size_t sysv_symbol_count = 0;
  if (hash != 0) {
    std::array<uint32_t, 2> header{};
    if (!ProcessTracer::read_memory(pid, hash, header.data(), sizeof(header)))
      return 0;
    const uint32_t nbuckets = header[0];
    const uint32_t nchain = header[1];
    uint64_t table_entries = 0;
    uint64_t table_bytes = 0;
    if (nbuckets == 0 || nbuckets > kMaxHashEntries || nchain == 0 ||
        nchain > kMaxHashEntries ||
        !checked_u64_add(2, nbuckets, &table_entries) ||
        !checked_u64_add(table_entries, nchain, &table_entries) ||
        !checked_u64_mul(table_entries, sizeof(uint32_t), &table_bytes) ||
        !remote_range_in_loads(phdrs, load_bias, hash, table_bytes)) {
      return 0;
    }
    sysv_symbol_count = nchain;
  }

  size_t gnu_symbol_count = 0;
  if (gnu_hash != 0) {
    std::array<uint32_t, 4> header{};
    if (!ProcessTracer::read_memory(pid, gnu_hash, header.data(),
                                    sizeof(header))) {
      return 0;
    }
    const uint32_t nbuckets = header[0];
    const uint32_t symoffset = header[1];
    const uint32_t bloom_size = header[2];
    if (nbuckets == 0 || nbuckets > kMaxHashEntries || bloom_size == 0 ||
        bloom_size > kMaxHashEntries || symoffset >= kMaxHashEntries) {
      return 0;
    }

    uint64_t bloom_bytes = 0;
    uint64_t buckets_addr = 0;
    uint64_t bucket_bytes = 0;
    uint64_t chain_addr = 0;
    if (!checked_u64_mul(bloom_size, sizeof(Elf64_Xword), &bloom_bytes) ||
        !checked_u64_add(gnu_hash, sizeof(header), &buckets_addr) ||
        !checked_u64_add(buckets_addr, bloom_bytes, &buckets_addr) ||
        !checked_u64_mul(nbuckets, sizeof(uint32_t), &bucket_bytes) ||
        !checked_u64_add(buckets_addr, bucket_bytes, &chain_addr) ||
        chain_addr > gnu_hash_load_end) {
      return 0;
    }

    uint32_t max_bucket = 0;
    for (uint32_t i = 0; i < nbuckets; ++i) {
      uint64_t bucket_addr = 0;
      uint32_t bucket = 0;
      if (!remote_object_address(buckets_addr, i, sizeof(uint32_t),
                                 &bucket_addr) ||
          !read_remote_object(pid, bucket_addr, &bucket)) {
        return 0;
      }
      if (bucket >= kMaxHashEntries ||
          (bucket != 0 && bucket < symoffset))
        return 0;
      max_bucket = std::max(max_bucket, bucket);
    }

    if (max_bucket != 0) {
      const uint64_t available_chain_entries =
          (gnu_hash_load_end - chain_addr) / sizeof(uint32_t);
      const uint64_t first_chain_index = max_bucket - symoffset;
      if (first_chain_index >= available_chain_entries)
        return 0;
      uint32_t symbol_index = max_bucket;
      const uint64_t maximum_steps = std::min<uint64_t>(
          available_chain_entries - first_chain_index,
          static_cast<uint64_t>(kMaxHashEntries) - symbol_index);
      for (uint64_t guard = 0; guard < maximum_steps; ++guard) {
        const uint64_t chain_index = symbol_index - symoffset;
        uint64_t entry_addr = 0;
        uint32_t chain_value = 0;
        if (!remote_object_address(chain_addr, chain_index, sizeof(uint32_t),
                                   &entry_addr) ||
            !read_remote_object(pid, entry_addr, &chain_value)) {
          return 0;
        }
        if ((chain_value & 1U) != 0) {
          gnu_symbol_count = static_cast<size_t>(symbol_index) + 1;
          break;
        }
        if (symbol_index + 1 >= kMaxHashEntries)
          return 0;
        ++symbol_index;
      }
      if (gnu_symbol_count == 0 || gnu_symbol_count > kMaxHashEntries)
        return 0;
    } else {
      gnu_symbol_count = symoffset;
    }
  }

  if (sysv_symbol_count != 0 && gnu_symbol_count != 0 &&
      gnu_symbol_count != sysv_symbol_count) {
    return 0;
  }
  const size_t symbol_count =
      sysv_symbol_count != 0 ? sysv_symbol_count : gnu_symbol_count;
  uint64_t symbol_table_bytes = 0;
  if (symbol_count == 0 || symbol_count > kMaxHashEntries ||
      !checked_u64_mul(symbol_count, sizeof(Elf64_Sym),
                       &symbol_table_bytes) ||
      !remote_range_in_loads(phdrs, load_bias, symtab,
                             symbol_table_bytes)) {
    return 0;
  }

  for (size_t i = 0; i < symbol_count; ++i) {
    uint64_t address = 0;
    Elf64_Sym symbol{};
    if (!remote_object_address(symtab, i, sizeof(Elf64_Sym), &address) ||
        !read_remote_object(pid, address, &symbol)) {
      break;
    }
    if (symbol.st_name == 0 || symbol.st_value == 0 ||
        symbol.st_name >= strtab_size) {
      continue;
    }
    uint64_t name_address = 0;
    if (!checked_u64_add(strtab, symbol.st_name, &name_address))
      return 0;
    const uint64_t remaining = strtab_size - symbol.st_name;
    const size_t name_limit = static_cast<size_t>(std::min<uint64_t>(
        remaining, static_cast<uint64_t>(kMaxSymbolNameBytes)));
    std::string name;
    if (!read_remote_cstr(pid, name_address, name_limit, &name))
      continue;
    if (name != sym)
      continue;
    constexpr uint8_t kGnuIndirectFunction = 10;
    const uint8_t symbol_type = ELF64_ST_TYPE(symbol.st_info);
    if (symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= SHN_LORESERVE ||
        (symbol_type != STT_FUNC && symbol_type != kGnuIndirectFunction)) {
      continue;
    }
    uint64_t resolved = 0;
    const uint64_t symbol_span = symbol.st_size == 0 ? 1 : symbol.st_size;
    if (!checked_u64_add(load_bias, symbol.st_value, &resolved) ||
        !remote_range_in_executable_loads(phdrs, load_bias, resolved,
                                          symbol_span)) {
      return 0;
    }
    return resolved;
  }
  return 0;
}

uint64_t FunctionHooker::find_remote_symbol(int pid, const std::string &lib,
                                            const std::string &sym) {
  struct CandidateObject {
    uint64_t base = 0;
    std::string path;
  };
  std::vector<CandidateObject> candidates;
  for (const MapEntry &mapping : Memory::read_maps(pid)) {
    if (!mapping.readable() || mapping.offset != 0 || mapping.name.empty() ||
        mapping.name[0] != '/')
      continue;
    std::string path = mapping.name;
    while (!path.empty() && (path.back() == ' ' || path.back() == '\n'))
      path.pop_back();
    size_t slash = path.rfind('/');
    std::string base_name =
        (slash != std::string::npos) ? path.substr(slash + 1) : path;
    if (base_name != lib && path.find("/" + lib) == std::string::npos)
      continue;
    bool duplicate = false;
    for (const CandidateObject &candidate : candidates) {
      if (candidate.base == mapping.start && candidate.path == path) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate)
      candidates.push_back({mapping.start, std::move(path)});
  }
  for (const CandidateObject &candidate : candidates) {
    const uint64_t resolved =
        parse_remote_symbol_impl(pid, candidate.base, sym);
    if (resolved != 0 &&
        current_executable_object_range(pid, resolved, 1, candidate.path))
      return resolved;
  }
  return 0;
}


RemoteCallResult FunctionHooker::inject_library(
    int pid, const std::string &lib_path) {
  if (lib_path.empty()) {
    RemoteCallResult result{};
    result.error_message = "library path is empty";
    return result;
  }
  return MemoryInjector::remote_dlopen(pid, lib_path, RTLD_NOW);
}

std::vector<RelinkEntry>
StaticRelinker::find_external_calls(const std::vector<uint8_t> &data,
                                    uint64_t base) {
  (void)base;
  std::vector<RelinkEntry> entries;
  constexpr uint64_t kMaxDynamicBytes = 1ULL << 20;

  Elf64ProgramHeaders elf;
  if (!parse_elf64_program_headers(data, &elf))
    return entries;

  size_t dyn_off = 0;
  size_t dyn_size = 0;
  bool found_dynamic = false;
  for (const Elf64_Phdr &ph : elf.entries) {
    if (ph.p_type != PT_DYNAMIC)
      continue;
    if (ph.p_filesz < sizeof(Elf64_Dyn) ||
        ph.p_filesz > kMaxDynamicBytes || ph.p_offset > data.size() ||
        ph.p_filesz > data.size() - static_cast<size_t>(ph.p_offset)) {
      return entries;
    }
    dyn_off = static_cast<size_t>(ph.p_offset);
    dyn_size = static_cast<size_t>(ph.p_filesz);
    found_dynamic = true;
    break;
  }
  if (!found_dynamic)
    return entries;

  uint64_t jmprel = 0;
  uint64_t pltrelsz = 0;
  uint64_t symtab = 0;
  uint64_t strtab = 0;
  uint64_t strtab_size = 0;
  uint64_t syment_size = 0;
  uint64_t relaent_size = 0;
  uint64_t pltrel_kind = 0;
  bool saw_null = false;
  for (size_t offset = 0; offset <= dyn_size - sizeof(Elf64_Dyn);
       offset += sizeof(Elf64_Dyn)) {
    Elf64_Dyn dyn{};
    memcpy(&dyn, data.data() + dyn_off + offset, sizeof(dyn));
    if (dyn.d_tag == DT_NULL) {
      saw_null = true;
      break;
    }
    switch (dyn.d_tag) {
    case DT_JMPREL:
      jmprel = dyn.d_un.d_ptr;
      break;
    case DT_PLTRELSZ:
      pltrelsz = dyn.d_un.d_val;
      break;
    case DT_PLTREL:
      pltrel_kind = dyn.d_un.d_val;
      break;
    case DT_RELAENT:
      relaent_size = dyn.d_un.d_val;
      break;
    case DT_SYMTAB:
      symtab = dyn.d_un.d_ptr;
      break;
    case DT_SYMENT:
      syment_size = dyn.d_un.d_val;
      break;
    case DT_STRTAB:
      strtab = dyn.d_un.d_ptr;
      break;
    case DT_STRSZ:
      strtab_size = dyn.d_un.d_val;
      break;
    }
  }
  if (!saw_null || jmprel == 0 || pltrelsz == 0 || symtab == 0 ||
      strtab == 0 || strtab_size == 0 || pltrel_kind != DT_RELA ||
      (relaent_size != 0 && relaent_size != sizeof(Elf64_Rela)) ||
      (syment_size != 0 && syment_size != sizeof(Elf64_Sym))) {
    return entries;
  }

  auto vaddr_to_off = [&](uint64_t vaddr, uint64_t &out) -> bool {
    for (const Elf64_Phdr &ph : elf.entries) {
      if (ph.p_type != PT_LOAD || vaddr < ph.p_vaddr)
        continue;
      const uint64_t delta = vaddr - ph.p_vaddr;
      if (delta >= ph.p_filesz)
        continue;
      uint64_t offset = 0;
      if (!checked_u64_add(ph.p_offset, delta, &offset) ||
          offset >= data.size()) {
        return false;
      }
      out = offset;
      return true;
    }
    // Some callers may provide an already flattened in-memory image rather
    // than file layout. Retain the old direct-offset fallback, but only after
    // a valid PT_LOAD mapping has had the first chance to resolve the vaddr.
    if (vaddr < data.size()) {
      out = vaddr;
      return true;
    }
    return false;
  };

  uint64_t jmprel_off = 0, symtab_off = 0, strtab_off = 0;
  if (!vaddr_to_off(jmprel, jmprel_off) || !vaddr_to_off(symtab, symtab_off) ||
      !vaddr_to_off(strtab, strtab_off))
    return entries;

  if (jmprel_off > data.size() ||
      pltrelsz > data.size() - static_cast<size_t>(jmprel_off) ||
      pltrelsz % sizeof(Elf64_Rela) != 0 || strtab_off > data.size() ||
      strtab_size > data.size() - static_cast<size_t>(strtab_off) ||
      symtab_off >= data.size()) {
    return entries;
  }

  const size_t count = static_cast<size_t>(pltrelsz / sizeof(Elf64_Rela));
  for (size_t i = 0; i < count; i++) {
    const size_t rel_off = static_cast<size_t>(jmprel_off) +
                           i * sizeof(Elf64_Rela);
    Elf64_Rela rela{};
    memcpy(&rela, data.data() + rel_off, sizeof(rela));
    const uint32_t sym_idx = ELF64_R_SYM(rela.r_info);
    const size_t available_symbols =
        (data.size() - static_cast<size_t>(symtab_off)) / sizeof(Elf64_Sym);
    if (sym_idx >= available_symbols)
      continue;
    const size_t sym_off = static_cast<size_t>(symtab_off) +
                           static_cast<size_t>(sym_idx) * sizeof(Elf64_Sym);
    Elf64_Sym symbol{};
    memcpy(&symbol, data.data() + sym_off, sizeof(symbol));
    if (symbol.st_name == 0 || symbol.st_name >= strtab_size)
      continue;

    const size_t name_off = static_cast<size_t>(strtab_off) + symbol.st_name;
    const size_t name_limit = static_cast<size_t>(
        std::min<uint64_t>(strtab_size - symbol.st_name,
                           data.size() - name_off));
    const void *name_end = memchr(data.data() + name_off, '\0', name_limit);
    if (!name_end)
      continue;
    const auto *name_begin =
        reinterpret_cast<const char *>(data.data() + name_off);
    const auto *name_finish = static_cast<const char *>(name_end);
    if (name_begin == name_finish)
      continue;

    RelinkEntry entry;
    entry.call_site = rela.r_offset;
    entry.target_addr = 0;
    entry.symbol_name.assign(name_begin, name_finish);
    entries.push_back(entry);
  }
  return entries;
}

bool StaticRelinker::resolve_symbol(int pid, const std::string &name,
                                    uint64_t *addr) {
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  std::set<std::string> checked;
  while (std::getline(maps, line)) {
    if (line.find(".so") == std::string::npos)
      continue;
    if (line.find("r-xp") == std::string::npos &&
        line.find("r--p") == std::string::npos)
      continue;
    size_t path_pos = line.find('/');
    if (path_pos == std::string::npos)
      continue;
    size_t space_pos = line.find(' ', path_pos);
    std::string path = line.substr(path_pos, space_pos - path_pos);
    size_t slash = path.rfind('/');
    std::string lib =
        (slash != std::string::npos) ? path.substr(slash + 1) : path;
    if (checked.count(lib))
      continue;
    checked.insert(lib);
    uint64_t a = FunctionHooker::find_remote_symbol(pid, lib, name);
    if (a != 0) {
      *addr = a;
      return true;
    }
  }
  return false;
}

std::vector<uint8_t> StaticRelinker::embed_function(int pid, uint64_t addr,
                                                    size_t max_size) {
  static constexpr size_t DEFAULT_MAX_FUNC_SIZE = 64 * 1024;
  size_t read_size = (max_size == 0) ? DEFAULT_MAX_FUNC_SIZE : max_size;

  // Never read past the end of the mapping the function lives in.
  //
  // read_memory is all-or-nothing, and a 64 KB window from a function near the
  // end of its segment runs into unmapped padding -- which on a library built
  // for 16 KB pages is guaranteed, since each segment gets its own mapping with
  // PROT_NONE in between. The read failed, embed_function returned nothing, and
  // every extraction of such a function reported "Extraction failed".
  for (const auto &m : Memory::read_maps(pid)) {
    if (addr >= m.start && addr < m.end) {
      size_t avail = static_cast<size_t>(m.end - addr);
      if (avail < read_size)
        read_size = avail;
      break;
    }
  }
  if (read_size < 4)
    return {};

  std::vector<uint8_t> func_data(read_size);
  if (!ProcessTracer::read_memory(pid, addr, func_data.data(), read_size))
    return {};

  size_t actual_size =
      InstructionDecoder::find_function_end(func_data.data(), read_size);

  if (actual_size < 4)
    actual_size = 4;

  func_data.resize(actual_size);
  return func_data;
}

// A user-space function such as dlopen may need a mutex held by another target
// thread. ProcessTracer::attach() intentionally stops every thread, so running
// only the call thread can deadlock forever. Temporarily detach/resume the
// peers, then converge back to a fully stopped thread set before returning to
// the caller. Physical detach is legal only for the sole group owner: a
// refcount greater than one means another snapshot/patch transaction relies on
// the peers remaining frozen.
enum class RemotePeerRelease { Complete, SharedOwner, Failed };

static RemotePeerRelease
release_remote_call_peers(int tgid, int call_tid,
                          const AttachDeadline &deadline) {
  {
    std::lock_guard<std::mutex> lock(g_attach_mu);
    TraceeRef *owner = nullptr;
    const int owner_tid = tracer_thread_id();
    if (owner_tid == 0)
      return RemotePeerRelease::Failed;
    for (auto &ref : g_tracees) {
      if (ref.pid == tgid && ref.refs > 0 && ref.owner_tid == owner_tid) {
        owner = &ref;
        break;
      }
    }
    if (!owner)
      return RemotePeerRelease::Failed;
    if (owner->refs != 1)
      return RemotePeerRelease::SharedOwner;
  }

  const std::vector<int> tids = owned_group_tids(tgid);
  if (tids.empty() || std::find(tids.begin(), tids.end(), call_tid) == tids.end())
    return RemotePeerRelease::Failed;
  for (int tid : tids) {
    if (std::chrono::steady_clock::now() >= deadline ||
        !ProcessTracer::follow_thread_clones(tid)) {
      for (int configured : tids) {
        if (configured == tid)
          break;
        (void)ProcessTracer::clear_trace_options(configured);
      }
      return RemotePeerRelease::Failed;
    }
  }
  std::set<int> resumed;
  for (int tid : tids) {
    if (tid == call_tid)
      continue;
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) >= 0) {
      resumed.insert(tid);
      continue;
    }
    std::set<int> stayed_stopped;
    for (int owned : tids)
      if (resumed.count(owned) == 0)
        stayed_stopped.insert(owned);
    PatchQuiesceResult quiesced =
        quiesce_owned_patch_group(tgid, std::move(stayed_stopped), deadline);
    (void)quiesced;
    return RemotePeerRelease::Failed;
  }
  return RemotePeerRelease::Complete;
}

static pid_t poll_owned_group_wait(int tgid, int *status) {
  if (!status) {
    errno = EINVAL;
    return -1;
  }
  const std::vector<int> tids = owned_group_tids(tgid);
  if (tids.empty()) {
    errno = ECHILD;
    return -1;
  }
  for (int tid : tids) {
    errno = 0;
    const pid_t waited = waitpid(tid, status, __WALL | WNOHANG);
    if (waited > 0)
      return waited;
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      if ((errno == ECHILD || errno == ESRCH) &&
          !thread_is_member(tgid, tid)) {
        forget_attached(tgid, tid);
        continue;
      }
      return -1;
    }
  }
  return 0;
}

static void forget_exited_tracee(int tgid) {
  std::lock_guard<std::mutex> lock(g_attach_mu);
  for (auto &slot : g_attached) {
    uint64_t state = slot.state.load(std::memory_order_acquire);
    if (attached_tgid(state) == tgid)
      slot.state.compare_exchange_strong(state, 0,
                                         std::memory_order_acq_rel,
                                         std::memory_order_relaxed);
  }
  for (auto &ref : g_tracees)
    if (ref.pid == tgid)
      ref = TraceeRef{};
}

static void terminate_remote_call_state(int tgid) {
  // cleanup_all_attached uses the transaction's pidfd before releasing any
  // ownership slot, so SIGKILL is bound to the original task rather than a
  // reusable numeric PID.
  ProcessTracer::cleanup_all_attached();
  terminate_all_owned_tracees_from_proc();

  // Drain every ptrace death notification before allowing the numeric PID to
  // escape as reusable. SIGKILL is terminal, but without this bounded reap a
  // caller could immediately mistake a zombie (or later PID reuse) for a live
  // target and issue free/dlerror against it.
  const auto drain_deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(2);
  while (std::chrono::steady_clock::now() < drain_deadline) {
    bool consumed = false;
    for (;;) {
      int status = 0;
      errno = 0;
      pid_t waited = waitpid(-1, &status, __WALL | WNOHANG);
      if (waited > 0) {
        consumed = true;
        continue;
      }
      if (waited < 0 && errno == EINTR)
        continue;
      break;
    }
    if (!thread_is_member(tgid, tgid)) {
      errno = 0;
      if (kill(tgid, 0) < 0 && errno == ESRCH)
        break;
    }
    if (!consumed)
      usleep(1000);
  }
  ProcessTracer::reset_attach_bookkeeping();
}

enum class RemotePeerReacquire { Complete, GroupStopped, Failed };

static RemotePeerReacquire
reacquire_remote_call_peers(int tgid, int call_tid,
                            const AttachDeadline &deadline) {
  const PatchQuiesceResult result =
      quiesce_owned_patch_group(tgid, {call_tid}, deadline);
  if (result == PatchQuiesceResult::Stopped)
    return RemotePeerReacquire::Complete;
  if (result == PatchQuiesceResult::GroupStopped)
    return RemotePeerReacquire::GroupStopped;
  // Partial reacquisition means the ProcessTracer group contract is no longer
  // true. Do not return a live process with unknown peer ownership.
  terminate_remote_call_state(tgid);
  return RemotePeerReacquire::Failed;
}

enum class RemoteQuiesceResult { Stopped, Gone, Failed };

static bool verify_remote_return_marker(int tid, int status,
                                        uint64_t stub_addr,
                                        uint64_t expected_sp,
                                        uint64_t expected_nonce,
                                        user_regs_struct_64 *out) {
  if (tid <= 0 || stub_addr == 0 || !WIFSTOPPED(status) ||
      WSTOPSIG(status) != SIGTRAP)
    return false;
  const unsigned event =
      (static_cast<unsigned>(status) >> 16) & 0xffffu;
  if (event != 0)
    return false;

  RawRegisterSet raw;
  if (!read_exact_fixed_regset(tid, NT_PRSTATUS,
                               sizeof(user_regs_struct_64), &raw))
    return false;
  user_regs_struct_64 regs{};
  memcpy(&regs, raw.bytes.data(), sizeof(regs));
  const uint64_t return_pc = stub_addr + 8;
  if (regs.pc != return_pc || regs.sp != expected_sp ||
      regs.regs[19] != expected_nonce)
    return false;

  siginfo_t info{};
  if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) < 0 ||
      info.si_signo != SIGTRAP || info.si_code != TRAP_BRKPT ||
      reinterpret_cast<uintptr_t>(info.si_addr) != return_pc)
    return false;

  uint32_t marker = 0;
  if (!ProcessTracer::read_memory(tid, return_pc, &marker, sizeof(marker)) ||
      marker != 0xD4200000u)
    return false;
  if (out)
    *out = regs;
  return true;
}

// Stop a running remote-call register owner without adding a target signal.
// Signal-delivery stops which beat PTRACE_INTERRUPT are suppressed only long
// enough to consume the event-stop, then replayed after the original register
// image has been restored. A group-stop is already a safe boundary and must
// never be resumed merely to manufacture an interrupt event.
static RemoteQuiesceResult
quiesce_remote_call_thread(int tgid, int tid, uint64_t stub_addr,
                           int *pending_signal, bool *group_stopped,
                           bool *returned_to_stub, uint64_t expected_sp,
                           uint64_t expected_nonce,
                           const AttachDeadline &deadline) {
  if (!pending_signal || !group_stopped || !returned_to_stub)
    return RemoteQuiesceResult::Failed;

  bool interrupt_pending = false;
  errno = 0;
  if (ptrace(PTRACE_INTERRUPT, tid, nullptr, nullptr) >= 0) {
    interrupt_pending = true;
  } else if (errno == ESRCH && !thread_is_member(tgid, tid)) {
    return RemoteQuiesceResult::Gone;
  } else if (errno != EIO) {
    return RemoteQuiesceResult::Failed;
  }

  while (std::chrono::steady_clock::now() < deadline) {
    int status = 0;
    errno = 0;
    pid_t waited = waitpid(tid, &status, __WALL | WNOHANG);
    if (waited == 0) {
      usleep(1000);
      continue;
    }
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      return (errno == ECHILD || errno == ESRCH) &&
                     !thread_is_member(tgid, tid)
                 ? RemoteQuiesceResult::Gone
                 : RemoteQuiesceResult::Failed;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status))
      return RemoteQuiesceResult::Gone;
    if (!WIFSTOPPED(status))
      continue;

    const int stop_signal = WSTOPSIG(status);
    const unsigned event =
        (static_cast<unsigned>(status) >> 16) & 0xffffu;

    if (verify_remote_return_marker(tid, status, stub_addr, expected_sp,
                                    expected_nonce, nullptr)) {
      *returned_to_stub = true;
      return RemoteQuiesceResult::Stopped;
    }
    if (event == kPtraceEventStop && stop_signal == SIGTRAP)
      return RemoteQuiesceResult::Stopped;

    const bool job_control =
        stop_signal == SIGSTOP || stop_signal == SIGTSTP ||
        stop_signal == SIGTTIN || stop_signal == SIGTTOU;
    if (event == kPtraceEventStop && job_control) {
      // A second target signal cannot be represented alongside a previously
      // suppressed delivery without guessing their order.
      if (*pending_signal != 0)
        return RemoteQuiesceResult::Failed;
      *group_stopped = true;
      return RemoteQuiesceResult::Stopped;
    }
    if (event == kPtraceEventFork || event == kPtraceEventVfork ||
        event == kPtraceEventClone) {
      if (contain_patch_child_event(tgid, tid, false, deadline) ==
          PatchChildResult::Failed)
        return RemoteQuiesceResult::Failed;
      return RemoteQuiesceResult::Stopped;
    }
    if (event != 0)
      return RemoteQuiesceResult::Failed;

    if (stop_signal == (SIGTRAP | 0x80)) {
      if (!interrupt_pending)
        return RemoteQuiesceResult::Stopped;
      if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) >= 0)
        continue;
      return errno == ESRCH && !thread_is_member(tgid, tid)
                 ? RemoteQuiesceResult::Gone
                 : RemoteQuiesceResult::Failed;
    }

    SignalStopKind kind =
        ProcessTracer::classify_signal_stop(tid, stop_signal, event);
    if (kind == SignalStopKind::GroupStop) {
      if (*pending_signal != 0)
        return RemoteQuiesceResult::Failed;
      *group_stopped = true;
      return RemoteQuiesceResult::Stopped;
    }
    if (kind != SignalStopKind::Delivery || *pending_signal != 0)
      return RemoteQuiesceResult::Failed;

    siginfo_t info{};
    if (ptrace(PTRACE_GETSIGINFO, tid, nullptr, &info) < 0 ||
        info.si_signo != stop_signal)
      return RemoteQuiesceResult::Failed;
    if (stop_signal == SIGTRAP &&
        (info.si_code == TRAP_TRACE ||
         (info.si_code == SI_USER && info.si_pid == 0 && info.si_uid == 0)))
      return RemoteQuiesceResult::Stopped;

    if (!interrupt_pending)
      *pending_signal = stop_signal;
    if (!interrupt_pending)
      return RemoteQuiesceResult::Stopped;
    if (ptrace(PTRACE_CONT, tid, nullptr, nullptr) < 0)
      return errno == ESRCH && !thread_is_member(tgid, tid)
                 ? RemoteQuiesceResult::Gone
                 : RemoteQuiesceResult::Failed;
    // The delivery stop was explicitly suppressed. Record it only after the
    // successful resume so the restore path replays it exactly once; a failed
    // PTRACE_CONT leaves the original delivery stop pending in the kernel.
    *pending_signal = stop_signal;
  }
  return RemoteQuiesceResult::Failed;
}


static RemoteCallResult
call_remote_attached_impl(int pid, uint64_t func_addr,
                          const std::vector<uint64_t> &args,
                          bool acquire_attach) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  ScopedRemoteOperationDeadline operation_window(std::chrono::seconds(20));
  RemoteCallResult result{};

  if (args.size() > 8) {
    result.error_message =
        "remote calls support at most eight AArch64 register arguments";
    return result;
  }

  if (acquire_attach && !ProcessTracer::attach(pid)) {
    result.error_message = "Failed to attach";
    result.target_gone = !thread_is_member(pid, pid);
    return result;
  }
  if (!executable_range_mapped(pid, func_addr, 4)) {
    result.error_message =
        "remote call target is not in a current executable mapping";
    if (acquire_attach)
      (void)ProcessTracer::detach(pid);
    return result;
  }

  {
    ScopedDangerousTransaction dangerous(pid);
    if (!dangerous.active()) {
      result.error_message =
          "could not acquire fail-closed remote-call ownership";
      if (acquire_attach)
        ProcessTracer::detach(pid);
      return result;
    }
    RemoteRegisterSnapshot snapshot{};
    user_regs_struct_64 orig_regs{}, regs{};
    uint64_t stub_addr = 0;
    uint64_t return_nonce = 0;
    bool have_snapshot = false;
    bool call_thread_stopped = true;
    bool peers_released = false;
    bool registers_restored = false;
    bool group_stopped = false;
    bool terminal_failure = false;
    bool target_gone = false;
    bool call_started = false;
    bool returned_to_stub = false;
    int pending_signal = 0;
    const AttachDeadline operation_deadline = operation_window.deadline();
    const AttachDeadline call_deadline =
        std::min(operation_deadline,
                 std::chrono::steady_clock::now() +
                     std::chrono::seconds(15));

    do {
      stub_addr = FunctionHooker::allocate_remote(pid, 32);
      if (stub_addr == 0) {
        result.error_message = "could not allocate the call stub";
        break;
      }

      // ldr x9, #16   -- the target address, stored at stub_addr + 16
      // blr x9
      // brk #0        -- where x30 points, so the call returns into a trap
      //
      // The literal offset used to be #8, which loaded the `brk` and the
      // padding word as an address and branched there. Every remote call
      // crashed the target with SIGSEGV before reaching the function, which is
      // why library injection never once succeeded.
      uint32_t stub_code[] = {
          0x58000089,
          0xD63F0120,
          0xD4200000,
          0x00000000,
      };
      uint8_t call_stub[sizeof(stub_code) + sizeof(func_addr)] = {};
      memcpy(call_stub, stub_code, sizeof(stub_code));
      memcpy(call_stub + sizeof(stub_code), &func_addr, sizeof(func_addr));
      if (write_generated_executable_checked(
              pid, stub_addr, call_stub, sizeof(call_stub)) !=
          ExecutableWriteResult::WrittenVerified) {
        result.error_message = "could not write the call stub";
        break;
      }

      // Setup uses remote syscalls which independently preserve their state.
      // Snapshot only after setup so a real signal delivered during mmap or
      // mprotect is not later overwritten with a stale pre-signal image.
      if (!save_remote_registers(pid, &snapshot) ||
          snapshot.gpr.bytes.size() != sizeof(orig_regs)) {
        result.error_message =
            "failed to snapshot complete AArch64 register state";
        break;
      }
      have_snapshot = true;
      memcpy(&orig_regs, snapshot.gpr.bytes.data(), sizeof(orig_regs));
      regs = orig_regs;
      for (size_t i = 0; i < args.size(); i++)
        regs.regs[i] = args[i];

      const RemotePeerRelease peer_release =
          release_remote_call_peers(pid, pid, operation_deadline);
      if (peer_release == RemotePeerRelease::SharedOwner) {
        result.error_message =
            "remote call requires exclusive ownership of the thread group";
        break;
      }
      if (peer_release != RemotePeerRelease::Complete) {
        result.error_message =
            "could not safely resume all peer threads for the remote call";
        terminal_failure = true;
        break;
      }
      peers_released = true;

      return_nonce =
          0x4841594142555341ULL ^ stub_addr ^ static_cast<uint64_t>(pid);
      regs.regs[19] = return_nonce;
      regs.regs[30] = stub_addr + 8;
      regs.pc = stub_addr;

      RawRegisterSet temporary_gpr = snapshot.gpr;
      memcpy(temporary_gpr.bytes.data(), &regs, sizeof(regs));
      if (!write_raw_regset(pid, temporary_gpr) ||
          !raw_regset_matches(pid, temporary_gpr)) {
        result.error_message = std::string("PTRACE_SETREGSET: ") +
                               strerror(errno);
        break;
      }
      if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        result.error_message = std::string("PTRACE_CONT: ") + strerror(errno);
        break;
      }
      call_started = true;
      call_thread_stopped = false;

      int status = 0;
      while (std::chrono::steady_clock::now() < call_deadline) {
        errno = 0;
        pid_t w = poll_owned_group_wait(pid, &status);
        if (w == 0) {
          usleep(1000);
          continue;
        }
        if (w < 0) {
          if (errno == EINTR)
            continue;
          if ((errno == ECHILD || errno == ESRCH) &&
              !thread_is_member(pid, pid)) {
            result.error_message =
                "target exited while executing the remote call";
            target_gone = true;
            break;
          }
          result.error_message = std::string("waitpid: ") + strerror(errno);
          break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
          forget_attached(pid, static_cast<int>(w));
          if (w == pid) {
            result.error_message =
                "target exited while executing the remote call";
            target_gone = true;
            call_thread_stopped = false;
            break;
          }
          continue;
        }
        if (!WIFSTOPPED(status))
          continue;

        if (w == pid)
          call_thread_stopped = true;
        const int sig = WSTOPSIG(status);
        const unsigned event =
            (static_cast<unsigned>(status) >> 16) & 0xffffu;
        user_regs_struct_64 stopped_regs{};
        if (w == pid &&
            verify_remote_return_marker(pid, status, stub_addr, regs.sp,
                                        return_nonce, &stopped_regs)) {
          regs = stopped_regs;
          returned_to_stub = true;
          break;
        }

        if (event == kPtraceEventFork || event == kPtraceEventVfork ||
            event == kPtraceEventClone) {
          const PatchChildResult child_result = contain_patch_child_event(
              pid, static_cast<int>(w), true, operation_deadline);
          if (child_result == PatchChildResult::Failed ||
              ptrace(PTRACE_CONT, w, nullptr, nullptr) < 0) {
            result.error_message =
                "could not contain a child created during the remote call";
            terminal_failure = true;
            break;
          }
          if (w == pid)
            call_thread_stopped = false;
          continue;
        }

        const bool job_control = sig == SIGSTOP || sig == SIGTSTP ||
                                 sig == SIGTTIN || sig == SIGTTOU;
        if (event == kPtraceEventStop && job_control) {
          group_stopped = true;
          result.error_message =
              "remote call interrupted by target group-stop";
          break;
        }
        if (event != 0) {
          result.error_message =
              "ptrace event made remote-call ownership ambiguous";
          terminal_failure = true;
          break;
        }

        SignalStopKind kind =
            ProcessTracer::classify_signal_stop(static_cast<int>(w), sig);
        if (kind == SignalStopKind::GroupStop) {
          group_stopped = true;
          result.error_message =
              "remote call interrupted by target group-stop";
          break;
        }
        if (kind != SignalStopKind::Delivery) {
          result.error_message =
              "could not classify remote-call signal stop";
          terminal_failure = true;
          break;
        }

        // This is a real target signal (including an internal SIGTRAP), not
        // our return BRK. Let the target observe it and keep waiting.
        if (ptrace(PTRACE_CONT, w, nullptr,
                   (void *)(intptr_t)sig) < 0) {
          result.error_message =
              std::string("PTRACE_CONT after signal: ") + strerror(errno);
          break;
        }
        if (w == pid)
          call_thread_stopped = false;
      }

      if (!returned_to_stub) {
        if (result.error_message.empty())
          result.error_message = "remote call timed out after 15 seconds";
        break;
      }
      result.return_value = regs.regs[0];
      result.success = true;
    } while (false);

    if (call_started && !returned_to_stub && !call_thread_stopped &&
        !terminal_failure) {
      RemoteQuiesceResult quiesced = quiesce_remote_call_thread(
          pid, pid, stub_addr, &pending_signal, &group_stopped,
          &returned_to_stub, regs.sp, return_nonce, operation_deadline);
      if (quiesced == RemoteQuiesceResult::Stopped) {
        call_thread_stopped = true;
        // A timeout can race the return BRK by one scheduler tick. Only that
        // verified PC makes the remote function complete enough to salvage.
        if (returned_to_stub) {
          RawRegisterSet returned;
          if (read_exact_fixed_regset(pid, NT_PRSTATUS, sizeof(regs),
                                      &returned)) {
            memcpy(&regs, returned.bytes.data(), sizeof(regs));
            result.return_value = regs.regs[0];
            result.success = true;
            result.error_message.clear();
          } else {
            terminal_failure = true;
          }
        }
      } else if (quiesced == RemoteQuiesceResult::Gone) {
        target_gone = true;
      } else {
        terminal_failure = true;
      }
    }

    if (target_gone && !result.target_gone) {
      result.success = false;
      // waitpid already proved that this exact tracee exited. Discard local
      // ownership only; sending SIGKILL through the now-reusable numeric PID
      // could hit an unrelated replacement process.
      forget_exited_tracee(pid);
      result.target_gone = true;
      call_thread_stopped = false;
    }

    // Once target code began, any stop other than the verified return BRK can
    // leave loader locks, constructor state, or the target stack half-mutated.
    // Restoring registers alone would merely hide that corruption.
    if (call_started && !returned_to_stub && !target_gone)
      terminal_failure = true;

    if (terminal_failure) {
      result.success = false;
      if (result.error_message.empty())
        result.error_message = "remote-call recovery state was ambiguous";
      terminate_remote_call_state(pid);
      target_gone = true;
      result.target_gone = true;
      call_thread_stopped = false;
    }

    if (have_snapshot && !target_gone) {
      if (!call_thread_stopped) {
        result.success = false;
        result.error_message =
            "remote call thread could not be stopped for register recovery";
        terminate_remote_call_state(pid);
        target_gone = true;
        result.target_gone = true;
      } else {
        registers_restored = restore_remote_registers_verified(pid, snapshot);
        if (!registers_restored) {
          result.success = false;
          result.error_message =
              std::string("failed to restore registers: ") + strerror(errno);
          terminate_remote_call_state(pid);
          target_gone = true;
          result.target_gone = true;
        }
      }
    }

    // This path is normally empty because signal stops are forwarded while the
    // remote call runs. If a verified-complete return retains one delivery,
    // replay it only after restoring the caller's original register image.
    if (!target_gone && registers_restored && pending_signal != 0 &&
        !group_stopped) {
      if (!deliver_signal_and_restop(pid, pending_signal,
                                     operation_deadline)) {
        result.success = false;
        result.error_message =
            "could not safely replay remote-call signal delivery";
        terminate_remote_call_state(pid);
        target_gone = true;
        result.target_gone = true;
      }
      pending_signal = 0;
    }

    if (peers_released && !target_gone) {
      RemotePeerReacquire reacquired =
          reacquire_remote_call_peers(pid, pid, operation_deadline);
      if (reacquired == RemotePeerReacquire::GroupStopped) {
        group_stopped = true;
        result.target_group_stopped = true;
      } else if (reacquired != RemotePeerReacquire::Complete) {
        result.success = false;
        result.error_message =
            "could not reattach every peer after the remote call";
        target_gone = true; // reacquire helper performed terminal cleanup
        result.target_gone = true;
      }
    }
    // Never unmap code while an unverified register restore may still leave PC
    // or LR pointing into it. A leak is recoverable; a dangling branch is not.
    if (stub_addr != 0 && !target_gone && !group_stopped &&
        (!have_snapshot || registers_restored))
      FunctionHooker::free_remote(pid, stub_addr, 32);

    if (target_gone)
      result.target_gone = true;
  }

  if (acquire_attach && !result.target_gone && !ProcessTracer::detach(pid)) {
    result.success = false;
    result.error_message = "remote-call detach verification failed";
    terminate_remote_call_state(pid);
    result.target_gone = true;
  }
  return result;
}

RemoteCallResult
MemoryInjector::call_remote(int pid, uint64_t func_addr,
                            const std::vector<uint64_t> &args) {
  return call_remote_attached_impl(
      pid, func_addr, args, !current_thread_holds_tracee_lease(pid));
}


// An address inside a mapping that belongs to the target's own linker
// namespace, to be handed to __loader_dlopen as the calling address.
static uint64_t namespace_caller_addr(int pid) {
  uint64_t exe_text = 0;
  for (const auto &m : Memory::read_maps(pid)) {
    if (m.name.empty() || m.name[0] != '/')
      continue;
    if (m.perms.find('x') == std::string::npos)
      continue;
    if (m.name.find("/apex/") != std::string::npos ||
        m.name.find("/system/") != std::string::npos)
      continue;
    exe_text = m.start;
    break;
  }
  return exe_text;
}

RemoteCallResult MemoryInjector::remote_dlopen(int pid,
                                               const std::string &path,
                                               int flags) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  ScopedRemoteOperationDeadline operation_window(std::chrono::seconds(20));
  RemoteCallResult outcome{};
  bool acquired_attach = false;
  if (!current_thread_holds_tracee_lease(pid)) {
    if (!ProcessTracer::attach(pid)) {
      fprintf(stderr, "[inject] could not attach to %d\n", pid);
      outcome.error_message = "could not attach for remote dlopen";
      outcome.target_gone = !thread_is_member(pid, pid);
      return outcome;
    }
    acquired_attach = true;
  }
  // __loader_dlopen first, and with all three arguments.
  //
  // On Android 8 and later `dlopen` is a shim that forwards to
  // __loader_dlopen(path, flags, __builtin_return_address(0)), and the linker
  // resolves the caller address to a namespace. Called through ptrace the
  // return address is the trap stub, which belongs to no namespace, so the
  // linker refuses the load and every injection came back with a null handle.
  // Passing an address inside the target's own executable names the namespace
  // the target itself loads from.
  bool needs_caller = true;
  uint64_t dlopen_addr =
      FunctionHooker::find_remote_symbol(pid, "libc.so", "__loader_dlopen");
  if (dlopen_addr == 0)
    dlopen_addr = find_linker_function(pid, "__loader_dlopen");
  if (dlopen_addr == 0) {
    dlopen_addr = FunctionHooker::find_remote_symbol(pid, "libdl.so", "dlopen");
    needs_caller = false;
  }
  if (dlopen_addr == 0) {
    fprintf(stderr, "[inject] no dlopen entry point found in the target\n");
    outcome.error_message = "no dlopen entry point found in the target";
    if (acquired_attach && !ProcessTracer::detach(pid)) {
      terminate_remote_call_state(pid);
      outcome.target_gone = true;
    }
    return outcome;
  }

  size_t path_len = path.size() + 1;
  uint64_t path_addr = FunctionHooker::allocate_remote(pid, path_len);
  if (path_addr == 0) {
    fprintf(stderr, "[inject] remote allocation of %zu bytes failed\n",
            path_len);
    outcome.error_message = "remote library-path allocation failed";
    if (acquired_attach && !ProcessTracer::detach(pid)) {
      terminate_remote_call_state(pid);
      outcome.target_gone = true;
    }
    return outcome;
  }

  if (!ProcessTracer::write_memory(pid, path_addr, path.c_str(), path_len)) {
    FunctionHooker::free_remote(pid, path_addr, path_len);
    outcome.error_message = "could not write the remote library path";
    if (acquired_attach && !ProcessTracer::detach(pid)) {
      terminate_remote_call_state(pid);
      outcome.target_gone = true;
    }
    return outcome;
  }

  std::vector<uint64_t> args = {path_addr, (uint64_t)flags};
  if (needs_caller)
    args.push_back(namespace_caller_addr(pid));
  // This function already owns the sole ProcessTracer reference used for the
  // path allocation. Reusing it avoids a nested refcount whose peers would be
  // physically detached behind the outer owner's back.
  outcome = call_remote_attached_impl(pid, dlopen_addr, args, false);

  // A terminal timeout/ambiguity path deliberately killed the target. Never
  // run munmap or another attach against that numeric PID: it may be recycled.
  // A completed call that raced a job-control stop is also left untouched so
  // the final detach(0) preserves the owner's stop.
  if (!outcome.target_gone && !outcome.target_group_stopped)
    FunctionHooker::free_remote(pid, path_addr, path_len);
  if (acquired_attach && !outcome.target_gone &&
      !ProcessTracer::detach(pid)) {
    outcome.success = false;
    outcome.error_message = "remote-dlopen detach verification failed";
    terminate_remote_call_state(pid);
    outcome.target_gone = true;
  }

  if (!outcome.success)
    fprintf(stderr, "[inject] remote call to 0x%llx failed: %s\n",
            (unsigned long long)dlopen_addr,
            outcome.error_message.empty() ? "no detail"
                                          : outcome.error_message.c_str());
  else if (outcome.return_value == 0)
    fprintf(stderr, "[inject] the linker refused %s (null handle)\n",
            path.c_str());
  return outcome;
}


RemoteStringResult MemoryInjector::remote_dlerror(int pid) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  ScopedRemoteOperationDeadline operation_window(std::chrono::seconds(20));
  RemoteStringResult outcome{};
  bool acquired_attach = false;
  if (!current_thread_holds_tracee_lease(pid)) {
    if (!ProcessTracer::attach(pid)) {
      outcome.error_message = "could not attach for remote dlerror";
      outcome.target_gone = !thread_is_member(pid, pid);
      return outcome;
    }
    acquired_attach = true;
  }
  uint64_t dlerror_addr =
      FunctionHooker::find_remote_symbol(pid, "libdl.so", "dlerror");
  if (dlerror_addr == 0) {
    outcome.error_message = "no dlerror entry point found in the target";
    if (acquired_attach && !ProcessTracer::detach(pid)) {
      terminate_remote_call_state(pid);
      outcome.target_gone = true;
    }
    return outcome;
  }

  std::vector<uint64_t> args;
  auto result = call_remote_attached_impl(pid, dlerror_addr, args, false);
  outcome.success = result.success;
  outcome.target_gone = result.target_gone;
  outcome.target_group_stopped = result.target_group_stopped;
  outcome.error_message = result.error_message;

  if (result.success && result.return_value != 0) {
    // Keep the same stopped-process lease used for symbol resolution and the
    // call until the loader-owned error buffer has been copied locally.
    outcome.value = read_string_remote(pid, result.return_value, 256);
    if (outcome.value.empty()) {
      outcome.success = false;
      outcome.error_message = "could not read remote dlerror string";
    }
  }
  if (acquired_attach && !outcome.target_gone &&
      !ProcessTracer::detach(pid)) {
    outcome.success = false;
    outcome.error_message = "remote-dlerror detach verification failed";
    terminate_remote_call_state(pid);
    outcome.target_gone = true;
  }
  return outcome;
}



// Patching a function means writing to an r-xp mapping, which
// process_vm_writev refuses. Flip the affected pages writable via a remote
// mprotect, write, then restore. Without this every inline hook and stub
// failed with "cannot write patch".
static bool remote_mprotect_pages(int pid, uint64_t addr, size_t len,
                                  int prot) {
  uint64_t page = native_page_size();
  if (page == 0 || len == 0 ||
      addr > std::numeric_limits<uint64_t>::max() - len)
    return false;
  uint64_t start = addr & ~(page - 1);
  uint64_t unaligned_end = addr + len;
  if (unaligned_end > std::numeric_limits<uint64_t>::max() - (page - 1))
    return false;
  uint64_t end = (unaligned_end + page - 1) & ~(page - 1);
  if (end <= start)
    return false;
  int nr = SYS_MPROTECT_64;
  uint64_t ret = execute_syscall(
      pid, {start, end - start, (uint64_t)prot}, nr);
  return ret == 0;
}

// Write into executable memory, restoring the original protection afterwards.
// Write into the tracee's *text* via PTRACE_POKEDATA, one machine word at a
// time, read-modify-writing the partial words at each end.
//
// This exists instead of process_vm_writev because of instruction-cache
// coherency. On AArch64 the D-cache and I-cache are not unified: a plain write
// to an executable page leaves the old instructions sitting in the I-cache and
// the CPU may keep executing them. arm64's ptrace path calls
// flush_ptrace_access() and so maintains the caches for us; process_vm_writev
// takes a different path and does not. Data writes still use the faster
// process_vm_writev -- only code goes through here.
static bool poke_words(int pid, uint64_t addr, const void *data, size_t len) {
  const uint8_t *src = static_cast<const uint8_t *>(data);
  const size_t W = sizeof(long);
  uint64_t start = addr & ~(uint64_t)(W - 1);
  uint64_t end = (addr + len + W - 1) & ~(uint64_t)(W - 1);

  for (uint64_t p = start; p < end; p += W) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)p, nullptr);
    if (word == -1 && errno != 0)
      return false;
    uint8_t buf[sizeof(long)];
    memcpy(buf, &word, W);
    // Splice in whatever part of this word the caller's range covers.
    for (size_t i = 0; i < W; i++) {
      uint64_t byte_addr = p + i;
      if (byte_addr >= addr && byte_addr < addr + len)
        buf[i] = src[byte_addr - addr];
    }
    memcpy(&word, buf, W);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)p, (void *)word) < 0)
      return false;
  }
  return true;
}

static bool write_code(int pid, uint64_t addr, const void *data, size_t len) {
  if (poke_words(pid, addr, data, len))
    return true;
  // Preserve W^X even on kernels where PTRACE_POKEDATA cannot write an RX
  // mapping. Every target thread is stopped while this helper is used.
  if (!remote_mprotect_pages(pid, addr, len, PROT_READ | PROT_WRITE))
    return false;
  bool ok = poke_words(pid, addr, data, len);
  bool protections_restored =
      remote_mprotect_pages(pid, addr, len, PROT_READ | PROT_EXEC);
  return ok && protections_restored;
}

static bool executable_range_mapped(int pid, uint64_t addr, size_t len) {
  if (len == 0 || addr > std::numeric_limits<uint64_t>::max() - len)
    return false;
  const uint64_t end = addr + len;
  for (const auto &mapping : Memory::read_maps(pid)) {
    if (addr >= mapping.start && end <= mapping.end)
      return mapping.perms.find('x') != std::string::npos;
  }
  return false;
}

// ---- PC-relative relocation for relocated prologues -------------------------
//
// An inline hook copies the first N bytes of the target into a trampoline that
// lives somewhere else in the address space. Any PC-relative instruction among
// those bytes computes a different result once moved. The original code copied
// the bytes verbatim, so hooking any function starting with the ubiquitous
// `adrp`/`b`/`ldr literal` prologue silently corrupted it.
//
// Each instruction is re-encoded for its new address. If an instruction cannot
// be represented at the new distance, relocation fails and the caller must
// refuse to install the hook rather than emit broken code.

static bool fits_signed(int64_t v, int bits) {
  int64_t lim = int64_t(1) << (bits - 1);
  return v >= -lim && v < lim;
}

static bool relocate_arm64(uint32_t inst, uint64_t from, uint64_t to,
                           uint32_t *out) {
  *out = inst;

  // ADRP xD, #imm  -- page-relative, +/-4GB
  if ((inst & 0x9F000000) == 0x90000000) {
    int32_t immlo = (inst >> 29) & 0x3;
    int32_t immhi = (inst >> 5) & 0x7FFFF;
    int32_t imm = (immhi << 2) | immlo;
    if (imm & 0x100000)
      imm |= ~0x1FFFFF;
    uint64_t target = (from & ~0xFFFULL) + (int64_t(imm) << 12);
    int64_t delta = int64_t(target - (to & ~0xFFFULL)) >> 12;
    if (!fits_signed(delta, 21))
      return false;
    uint32_t v = uint32_t(delta) & 0x1FFFFF;
    *out = (inst & ~0x60FFFFE0u) | ((v & 0x3) << 29) | (((v >> 2) & 0x7FFFF) << 5);
    return true;
  }

  // ADR xD, #imm -- +/-1MB from the instruction itself
  if ((inst & 0x9F000000) == 0x10000000) {
    int32_t immlo = (inst >> 29) & 0x3;
    int32_t immhi = (inst >> 5) & 0x7FFFF;
    int32_t imm = (immhi << 2) | immlo;
    if (imm & 0x100000)
      imm |= ~0x1FFFFF;
    int64_t delta = int64_t(from + imm - to);
    if (!fits_signed(delta, 21))
      return false;
    uint32_t v = uint32_t(delta) & 0x1FFFFF;
    *out = (inst & ~0x60FFFFE0u) | ((v & 0x3) << 29) | (((v >> 2) & 0x7FFFF) << 5);
    return true;
  }

  // B / BL -- imm26, +/-128MB
  if ((inst & 0x7C000000) == 0x14000000) {
    int32_t imm = inst & 0x3FFFFFF;
    if (imm & 0x2000000)
      imm |= ~0x3FFFFFF;
    int64_t delta = int64_t(from + (int64_t(imm) << 2) - to) >> 2;
    if (!fits_signed(delta, 26))
      return false;
    *out = (inst & 0xFC000000u) | (uint32_t(delta) & 0x3FFFFFF);
    return true;
  }

  // B.cond / CBZ / CBNZ -- imm19, +/-1MB
  if ((inst & 0xFF000010) == 0x54000000 || (inst & 0x7E000000) == 0x34000000) {
    int32_t imm = (inst >> 5) & 0x7FFFF;
    if (imm & 0x40000)
      imm |= ~0x7FFFF;
    int64_t delta = int64_t(from + (int64_t(imm) << 2) - to) >> 2;
    if (!fits_signed(delta, 19))
      return false;
    *out = (inst & ~0x00FFFFE0u) | ((uint32_t(delta) & 0x7FFFF) << 5);
    return true;
  }

  // TBZ / TBNZ -- imm14, +/-32KB. Never survives a move to a fresh mapping.
  if ((inst & 0x7E000000) == 0x36000000)
    return false;

  // LDR/LDRSW literal, PRFM literal -- imm19
  if ((inst & 0x3B000000) == 0x18000000) {
    int32_t imm = (inst >> 5) & 0x7FFFF;
    if (imm & 0x40000)
      imm |= ~0x7FFFF;
    int64_t delta = int64_t(from + (int64_t(imm) << 2) - to) >> 2;
    if (!fits_signed(delta, 19))
      return false;
    *out = (inst & ~0x00FFFFE0u) | ((uint32_t(delta) & 0x7FFFF) << 5);
    return true;
  }

  return true; // PC-independent
}


// Copy `size` bytes of code from `from` to `to`, re-encoding PC-relative forms.
static bool relocate_block(const std::vector<uint8_t> &code, uint64_t from,
                           uint64_t to, std::vector<uint8_t> *out,
                           std::string *error) {
  out->assign(code.begin(), code.end());
  for (size_t off = 0; off + 4 <= code.size(); off += 4) {
    uint32_t inst;
    memcpy(&inst, code.data() + off, 4);
    uint32_t fixed = inst;
    bool ok = relocate_arm64(inst, from + off, to + off, &fixed);
    if (!ok) {
      if (error) {
        char buf[128];
        snprintf(buf, sizeof(buf),
                 "instruction 0x%08x at +%zu is PC-relative and cannot be "
                 "relocated to the trampoline",
                 inst, off);
        *error = buf;
      }
      return false;
    }
    memcpy(out->data() + off, &fixed, 4);
  }
  return true;
}

bool MemoryInjector::install_inline_hook(int pid, uint64_t target,
                                        uint64_t hook, HookInfo *info) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  if (!info)
    return false;

  info->target_addr = target;
  info->active = false;
  info->error.clear();

  // AArch64 instructions are 4-byte aligned. A misaligned target is either a
  // bad symbol or a 32-bit-ARM address that does not belong here; either way
  // patching it would corrupt the function.
  if (target & 3) {
    info->error = "target is not 4-byte aligned; not an AArch64 entry point";
    return false;
  }

  const size_t patch_size = 16;
  const size_t tramp_size = patch_size + 16;

  if (!executable_range_mapped(pid, target, patch_size)) {
    info->error = "target does not lie in a current executable mapping";
    return false;
  }
  if (!executable_range_mapped(pid, hook, 4)) {
    info->error = "hook destination does not lie in an executable mapping";
    return false;
  }

  info->patch_size = patch_size;
  info->original_bytes.resize(patch_size);
  if (!ProcessTracer::read_memory(pid, target, info->original_bytes.data(),
                                  patch_size)) {
    info->error = "cannot read target prologue";
    return false;
  }

  info->trampoline_addr = FunctionHooker::allocate_remote(pid, tramp_size);
  if (info->trampoline_addr == 0) {
    info->error = "remote allocation failed";
    return false;
  }

  // Re-encode the displaced prologue for its new address before writing it.
  std::vector<uint8_t> relocated;
  if (!relocate_block(info->original_bytes, target, info->trampoline_addr,
                      &relocated, &info->error)) {
    FunctionHooker::free_remote(pid, info->trampoline_addr, tramp_size);
    info->trampoline_addr = 0;
    return false;
  }

  std::vector<uint8_t> tramp(tramp_size, 0);
  memcpy(tramp.data(), relocated.data(), patch_size);

  if (true) {
    uint64_t ret_addr = target + patch_size;
    uint32_t jmp_back[] = {0x58000050, 0xD61F0200}; // ldr x16,#8 ; br x16
    memcpy(tramp.data() + patch_size, jmp_back, 8);
    memcpy(tramp.data() + patch_size + 8, &ret_addr, 8);
  } else {
    uint32_t ret_addr = (uint32_t)(target + patch_size);
    uint32_t jmp_back[] = {0xE51FF004, ret_addr}; // ldr pc,[pc,#-4]
    memcpy(tramp.data() + patch_size, jmp_back, 8);
  }

  if (write_generated_executable_checked(pid, info->trampoline_addr,
                                         tramp.data(), tramp_size) !=
      ExecutableWriteResult::WrittenVerified) {
    FunctionHooker::free_remote(pid, info->trampoline_addr, tramp_size);
    info->trampoline_addr = 0;
    info->error = "cannot write/verify trampoline";
    return false;
  }

  std::vector<uint8_t> patch(patch_size);
  if (true) {
    uint32_t hook_jmp[] = {0x58000050, 0xD61F0200};
    memcpy(patch.data(), hook_jmp, 8);
    memcpy(patch.data() + 8, &hook, 8);
  } else {
    uint32_t hook32 = (uint32_t)hook;
    uint32_t hook_jmp[] = {0xE51FF004, hook32};
    memcpy(patch.data(), hook_jmp, 8);
  }

  ExecutableWriteResult patch_result = write_executable_checked(
      pid, target, patch.data(), patch_size);
  if (patch_result != ExecutableWriteResult::WrittenVerified) {
    if (patch_result == ExecutableWriteResult::StateUnknown) {
      // A partial multiword branch may already target the trampoline. Mark it
      // owned before attempting rollback; if rollback is not verified the
      // destination must remain mapped.
      info->active = true;
      if (remove_inline_hook(pid, *info)) {
        info->active = false;
        info->trampoline_addr = 0;
        info->error = "patch state became unknown; original was restored";
      } else {
        info->error =
            "patch state unknown and original restore was not verified";
      }
    } else {
      FunctionHooker::free_remote(pid, info->trampoline_addr, tramp_size);
      info->trampoline_addr = 0;
      info->error = "target patch was not written";
    }
    return false;
  }

  info->active = true;
  return true;
}

bool MemoryInjector::remove_inline_hook(int pid, const HookInfo &info) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  if (!info.active)
    return false;

  ExecutableWriteResult restore_result = write_executable_checked(
      pid, info.target_addr, info.original_bytes.data(),
      info.original_bytes.size());
  if (restore_result != ExecutableWriteResult::WrittenVerified) {
    std::vector<uint8_t> verify(info.original_bytes.size());
    if (!ProcessTracer::read_memory(pid, info.target_addr, verify.data(),
                                    verify.size()) ||
        verify != info.original_bytes)
      return false;
  }

  std::vector<uint8_t> verify(info.original_bytes.size());
  if (!ProcessTracer::read_memory(pid, info.target_addr, verify.data(),
                                  verify.size()) ||
      verify != info.original_bytes)
    return false;

  size_t tramp_size = info.patch_size + 16;
  // The dangerous state is gone once the original prologue is verified back
  // in place. A failed munmap leaks a small scratch page but must not turn a
  // successful restore into a retry that could later free reused memory.
  (void)FunctionHooker::free_remote(pid, info.trampoline_addr, tramp_size);
  return true;
}
// ---- logging hook -----------------------------------------------------------
//
// Stub bodies are assembled from source (see the .S listings used to generate
// them) rather than hand-encoded. Record area layout:
//   [0]      uint64 call count
//   [8 + n*32] four uint64 argument slots, n in [0, SLOTS)

// ldr x16,area; atomic { old=ldaxr; stlxr(old+1); retry }; old&=7;
// lsl old,#5; add x16,x16,old; add x16,#8; store x0-x3;
// ldr x16,tramp; br x16; nop. The exclusive loop gives every simultaneous
// caller a distinct count/slot before it touches the record area.
static const uint32_t kStubArm64[] = {
    0x580001d0, 0xc85ffe11, 0x9100062f, 0xc80efe0f, 0x35ffffae,
    0x92400a31, 0xd37bea31, 0x8b110210, 0x91002210, 0xa9000600,
    0xa9010e02, 0x580000b0, 0xd61f0200, 0xd503201f};
static constexpr size_t kStubArm64AreaOff = 0x38;
static constexpr size_t kStubArm64TrampOff = 0x40;
static constexpr size_t kStubArm64Size = 0x48;


bool MemoryInjector::install_logging_hook(int pid, uint64_t target,
                                          LoggingHook *out) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  if (!out)
    return false;
  *out = LoggingHook{};


  const size_t slot_bytes = 32;
  const size_t record_size = (8) + LoggingHook::SLOTS * slot_bytes;
  const size_t stub_size = kStubArm64Size;
  // Android SELinux commonly rejects anonymous RWX mappings. Keep generated
  // code and mutable call records on distinct pages: write the first page as
  // RW, transition it to RX, and leave only the second page writable.
  const size_t remote_page = native_page_size();
  if (remote_page == 0) {
    out->info.error = "cannot determine native page size";
    return false;
  }
  const size_t total = remote_page * 2;
  if (stub_size > remote_page || record_size > remote_page) {
    out->info.error = "hook code/record layout exceeds its W^X page";
    return false;
  }

  uint64_t block = FunctionHooker::allocate_remote(pid, total);
  if (block == 0) {
    out->info.error = "remote allocation failed";
    return false;
  }
  uint64_t stub_addr = block;
  uint64_t record_addr = block + remote_page;

  std::vector<uint8_t> stub(stub_size, 0);
  memcpy(stub.data(), kStubArm64, sizeof(kStubArm64));

  memcpy(stub.data() + kStubArm64AreaOff, &record_addr, 8);

  if (write_generated_executable_checked(pid, stub_addr, stub.data(),
                                         stub.size()) !=
      ExecutableWriteResult::WrittenVerified) {
    FunctionHooker::free_remote(pid, block, total);
    out->info.error = "cannot write/verify hook stub";
    return false;
  }

  // The counter and argument slots must start at zero -- freshly mapped pages
  // read as zero in practice, but nothing guarantees it, and a garbage counter
  // is indistinguishable from a real call count.
  std::vector<uint8_t> zero(record_size, 0);
  if (!ProcessTracer::write_memory(pid, record_addr, zero.data(),
                                   zero.size())) {
    FunctionHooker::free_remote(pid, block, total);
    out->info.error = "cannot clear hook record area";
    return false;
  }
  std::vector<uint8_t> zero_verify(record_size, 0xff);
  if (!ProcessTracer::read_memory(pid, record_addr, zero_verify.data(),
                                  zero_verify.size()) ||
      zero_verify != zero) {
    FunctionHooker::free_remote(pid, block, total);
    out->info.error = "cannot verify cleared hook record area";
    return false;
  }

  // Publish ownership before the target branch is attempted. A state-unknown
  // branch install must retain this destination until restoration is verified.
  out->stub_addr = block;
  out->stub_size = total;
  out->record_addr = record_addr;

  if (!install_inline_hook(pid, target, stub_addr, &out->info)) {
    if (!out->info.active) {
      FunctionHooker::free_remote(pid, block, total);
      out->stub_addr = 0;
      out->stub_size = 0;
      out->record_addr = 0;
    }
    return false;
  }

  // The stub tail-jumps to the trampoline, whose address is only known after
  // the inline hook is installed.
  size_t tramp_off = kStubArm64TrampOff;
  ExecutableWriteResult literal_result = write_executable_checked(
      pid, stub_addr + tramp_off, &out->info.trampoline_addr, 8);
  if (literal_result != ExecutableWriteResult::WrittenVerified) {
    if (remove_inline_hook(pid, out->info)) {
      out->info.active = false;
      out->info.trampoline_addr = 0;
      FunctionHooker::free_remote(pid, block, total);
      out->stub_addr = 0;
      out->stub_size = 0;
      out->record_addr = 0;
      out->info.error =
          "trampoline literal was not verified; original was restored";
    } else {
      out->info.error =
          "trampoline literal state unknown and restore was not verified";
    }
    return false;
  }
  return true;
}

uint64_t MemoryInjector::read_logging_hook(int pid, const LoggingHook &hook,
                                           std::vector<CallRecord> *out) {
  if (hook.record_addr == 0)
    return 0;


  uint64_t count = 0;
  if (true) {
    if (!ProcessTracer::read_memory(pid, hook.record_addr, &count, 8))
      return 0;
  } else {
    uint32_t c32 = 0;
    if (!ProcessTracer::read_memory(pid, hook.record_addr, &c32, 4))
      return 0;
    count = c32;
  }
  if (!out)
    return count;

  size_t n = std::min<uint64_t>(count, LoggingHook::SLOTS);
  uint64_t base = hook.record_addr + (8);
  for (size_t i = 0; i < n; i++) {
    CallRecord rec{};
    if (true) {
      ProcessTracer::read_memory(pid, base + i * 32, rec.args, 32);
    } else {
      uint32_t a[4] = {0, 0, 0, 0};
      ProcessTracer::read_memory(pid, base + i * 16, a, 16);
      for (int k = 0; k < 4; k++)
        rec.args[k] = a[k];
    }
    out->push_back(rec);
  }
  return count;
}

bool MemoryInjector::remove_logging_hook(int pid, const LoggingHook &hook) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  if (!remove_inline_hook(pid, hook.info))
    return false;
  // Never unmap the branch destination while the target prologue may still
  // point at it. Failure here is only a remote-memory leak, not target
  // corruption, so the restore itself remains successful.
  if (hook.stub_addr)
    (void)FunctionHooker::free_remote(pid, hook.stub_addr, hook.stub_size);
  return true;
}

ExecutableWriteResult
MemoryInjector::stub_out_function(int pid, uint64_t target,
                                  std::vector<uint8_t> *original) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  if (target & 3)
    return ExecutableWriteResult::NotWritten;
  if (!executable_range_mapped(pid, target, 8))
    return ExecutableWriteResult::NotWritten;

  // Read enough for the two-instruction form below before deciding.
  uint8_t head[8] = {};
  if (!ProcessTracer::read_memory(pid, target, head, sizeof(head)))
    return ExecutableWriteResult::NotWritten;

  const uint32_t RET = 0xD65F03C0;
  const uint32_t BTI_C = 0xD503245F;

  // If the first instruction is a branch-target landing pad, it cannot simply
  // be replaced by `ret`. On a BTI-enabled image every indirect call must land
  // on one; a bare `ret` there raises a Branch Target exception and kills the
  // process. PACIASP/PACIBSP are landing pads too, but keeping one would sign
  // LR with no matching AUT before the `ret`, so those are replaced rather than
  // preserved -- `bti c` supplies the landing pad instead. `bti c` sits in the
  // HINT encoding space, so on a CPU without BTI it is just a NOP.
  uint32_t first = read_le32(head);
  // Mask off bits 7:6, the only ones that differ between bti / c / j / jc.
  bool is_landing_pad = (first & 0xFFFFFF3Fu) == 0xD503241Fu || // bti {,c,j,jc}
                        first == 0xD503233Fu ||                 // paciasp
                        first == 0xD503237Fu;                   // pacibsp

  size_t len = is_landing_pad ? 8 : 4;
  uint32_t patch[2] = {RET, 0};
  if (is_landing_pad) {
    patch[0] = BTI_C;
    patch[1] = RET;
  }

  std::vector<uint8_t> saved(head, head + len);
  ExecutableWriteResult result =
      write_executable_checked(pid, target, patch, len);
  if (result != ExecutableWriteResult::WrittenVerified)
    return result;
  if (original)
    *original = saved;
  return ExecutableWriteResult::WrittenVerified;
}

bool MemoryInjector::restore_function(int pid, uint64_t target,
                                      const std::vector<uint8_t> &original) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  if (original.empty())
    return false;
  if (target & 3)
    return false;
  if (!executable_range_mapped(pid, target, original.size()))
    return false;
  ExecutableWriteResult result = write_executable_checked(
      pid, target, original.data(), original.size());
  if (result == ExecutableWriteResult::WrittenVerified)
    return true;
  std::vector<uint8_t> verify(original.size());
  return ProcessTracer::read_memory(pid, target, verify.data(), verify.size()) &&
         verify == original;
}

static ExecutableWriteResult write_executable_checked_impl(
    int pid, uint64_t target, const void *data, size_t size,
    bool allow_generated_transition) {
  std::lock_guard<std::recursive_mutex> remote_lock(g_remote_mutation_mu);
  if (!data || size == 0 || (target & 3) != 0)
    return ExecutableWriteResult::NotWritten;

  try {
    bool was_executable = executable_range_mapped(pid, target, size);
    if (!was_executable && !allow_generated_transition)
      return ExecutableWriteResult::NotWritten;
    std::vector<uint8_t> before(size);
    if (!ProcessTracer::read_memory(pid, target, before.data(), before.size()))
      return ExecutableWriteResult::StateUnknown;

    bool write_ok = write_code(pid, target, data, size);
    bool executable_ok = was_executable;
    if (write_ok && !was_executable) {
      executable_ok = remote_mprotect_pages(
                          pid, target, size, PROT_READ | PROT_EXEC) &&
                      executable_range_mapped(pid, target, size);
    }
    std::vector<uint8_t> after(size);
    if (!ProcessTracer::read_memory(pid, target, after.data(), after.size()))
      return ExecutableWriteResult::StateUnknown;

    if (write_ok && executable_ok && memcmp(after.data(), data, size) == 0)
      return ExecutableWriteResult::WrittenVerified;
    if (write_ok && !executable_ok)
      return ExecutableWriteResult::StateUnknown;
    if (after == before)
      return ExecutableWriteResult::NotWritten;
    return ExecutableWriteResult::StateUnknown;
  } catch (...) {
    return ExecutableWriteResult::StateUnknown;
  }
}

ExecutableWriteResult MemoryInjector::write_executable_checked(
    int pid, uint64_t target, const void *data, size_t size) {
  return write_executable_checked_impl(pid, target, data, size, false);
}

static ExecutableWriteResult write_generated_executable_checked(
    int pid, uint64_t target, const void *data, size_t size) {
  return write_executable_checked_impl(pid, target, data, size, true);
}

bool MemoryInjector::write_executable(int pid, uint64_t target,
                                      const void *data, size_t size) {
  return write_executable_checked(pid, target, data, size) ==
         ExecutableWriteResult::WrittenVerified;
}





uint64_t MemoryInjector::find_linker_function(int pid,
                                              const std::string &func_name) {
  uint64_t addr =
      FunctionHooker::find_remote_symbol(pid, "linker64", func_name);
  if (addr == 0)
    addr = FunctionHooker::find_remote_symbol(pid, "linker", func_name);
  return addr;
}


std::string MemoryInjector::read_string_remote(int pid, uint64_t addr,
                                               size_t max_len) {
  std::vector<char> buf(max_len + 1, 0);
  if (!ProcessTracer::read_memory(pid, addr, buf.data(), max_len))
    return "";

  buf[max_len] = 0;
  return std::string(buf.data());
}


std::vector<uint8_t>
StaticRelinkerEx::relink_full(const std::vector<uint8_t> &elf_data, int pid,
                              uint64_t base_addr, const RelinkConfig &config) {
  std::vector<uint8_t> result = elf_data;

  EmbedContext ctx;
  ctx.pid = pid;
  ctx.base_addr = base_addr;
  ctx.total_embedded_size = 0;
  ctx.current_depth = 0;

  auto lib_ranges = ProcessTracer::get_library_ranges(pid);
  Elf64ProgramHeaders self_program_headers;
  if (parse_elf64_program_headers(elf_data, &self_program_headers)) {
    for (const auto &ph : self_program_headers.entries) {
      if (ph.p_type != PT_LOAD || ph.p_memsz == 0)
        continue;
      uint64_t load_start = 0, load_end = 0;
      if (!checked_u64_add(base_addr, ph.p_vaddr, &load_start) ||
          !checked_u64_add(load_start, ph.p_memsz, &load_end))
        continue;
      for (const auto &range : lib_ranges) {
        if (range.start < load_end && range.end > load_start) {
          ctx.self_library = range.name;
          break;
        }
      }
      if (!ctx.self_library.empty())
        break;
    }
  }

  auto calls = StaticRelinker::find_external_calls(elf_data, base_addr);

  const size_t max_size =
      config.max_total_size > 0 ? config.max_total_size : (64 * 1024 * 1024);

  size_t align = 16;
  uint64_t embed_offset = result.size();
  while (embed_offset % align)
    embed_offset++;
  result.resize(embed_offset);

  std::map<uint64_t, uint64_t> embedded_addrs;
  std::function<void(uint64_t, int)> embed_recursive;

  embed_recursive = [&](uint64_t addr, int depth) {
    if (depth >= config.max_depth)
      return;
    if (result.size() >= max_size)
      return;
    if (embedded_addrs.count(addr))
      return;

    std::string lib = ProcessTracer::find_library_for_address(lib_ranges, addr);
    if (lib == ctx.self_library)
      return;
    std::string lib_base = lib;
    size_t lib_slash = lib_base.rfind('/');
    if (lib_slash != std::string::npos)
      lib_base = lib_base.substr(lib_slash + 1);

    if (!config.exclude_libs.empty() &&
        (config.exclude_libs.count(lib) || config.exclude_libs.count(lib_base)))
      return;
    if (!config.include_only_libs.empty() &&
        !config.include_only_libs.count(lib) &&
        !config.include_only_libs.count(lib_base))
      return;

    auto code = StaticRelinker::embed_function(pid, addr, 0);
    if (code.empty() || code.size() < 8)
      return;

    uint64_t local_offset = result.size();
    embedded_addrs[addr] = local_offset;
    result.insert(result.end(), code.begin(), code.end());
    while (result.size() % align)
      result.push_back(0);

    auto sub_calls =
        InstructionDecoder::scan_calls(code.data(), code.size(), addr);
    for (const auto &c : sub_calls) {
      if (c.target_address == 0 || c.target_address == addr)
        continue;
      uint64_t target = c.target_address;
      if (config.inline_plt_calls) {
        uint64_t resolved =
            InstructionDecoder::resolve_plt(pid, c.target_address);
        if (resolved != 0)
          target = resolved;
      }
      embed_recursive(target, depth + 1);
    }
  };

  for (const auto &entry : calls) {
    uint64_t target = 0;
    if (StaticRelinker::resolve_symbol(pid, entry.symbol_name, &target)) {
      embed_recursive(target, 0);
    }
  }

  if (config.fix_relocations) {
    patch_relocations(result, embedded_addrs, base_addr);
  }

  return result;
}

struct EmbeddedFunctionInfo {
  uint64_t remote_addr;
  uint64_t local_offset;
  size_t size;
  int depth;
};

static bool patch_call_site(std::vector<uint8_t> &blob, size_t call_site,
                            uint64_t target_local) {
  if (call_site + 4 > blob.size())
    return false;

  // AArch64 BL (immediate): 100101 imm26, target = pc + imm26<<2.
  int64_t rel =
      static_cast<int64_t>(target_local) - static_cast<int64_t>(call_site);
  if ((rel & 0x3) != 0)
    return false;
  int64_t imm = rel / 4;
  if (imm < -0x2000000LL || imm >= 0x2000000LL)
    return false;
  uint32_t inst = 0x94000000 | (static_cast<uint32_t>(imm) & 0x03FFFFFF);
  memcpy(blob.data() + call_site, &inst, sizeof(inst));
  return true;
}

static void patch_embedded_calls(std::vector<uint8_t> &blob, int pid,
                                 const std::vector<EmbeddedFunctionInfo> &funcs,
                                 const std::map<uint64_t, uint64_t> &addr_map) {
  for (const auto &fn : funcs) {
    if (fn.local_offset + fn.size > blob.size())
      continue;
    const uint8_t *code = blob.data() + fn.local_offset;
    auto calls =
        InstructionDecoder::scan_calls(code, fn.size, fn.remote_addr);
    for (const auto &call : calls) {
      if (call.call_site_offset + 4 > fn.size)
        continue;
      uint64_t target_addr = call.target_address;
      auto it = addr_map.find(target_addr);
      if (it == addr_map.end()) {
        uint64_t resolved = InstructionDecoder::resolve_plt(pid, target_addr);
        if (resolved != 0 && resolved != target_addr)
          it = addr_map.find(resolved);
      }
      if (it == addr_map.end())
        continue;
      size_t call_site = static_cast<size_t>(fn.local_offset + call.call_site_offset);
      patch_call_site(blob, call_site, it->second);
    }
  }
}

std::vector<uint8_t>
StaticRelinkerEx::extract_function_with_deps(int pid, uint64_t addr,
                                             int max_depth) {
  if (max_depth < 0)
    max_depth = 0;

  const size_t align = 16;
  const size_t max_total_size = 64 * 1024 * 1024;

  auto ranges = ProcessTracer::get_library_ranges(pid);
  std::string root_lib = ProcessTracer::find_library_for_address(ranges, addr);
  if (root_lib.empty())
    return {};

  std::vector<uint8_t> result;
  result.reserve(256 * 1024);

  std::map<uint64_t, uint64_t> embedded_by_remote;
  std::vector<EmbeddedFunctionInfo> embedded_funcs;
  std::vector<std::pair<uint64_t, int>> pending;
  std::set<uint64_t> queued;

  pending.push_back({addr, 0});
  queued.insert(addr);

  while (!pending.empty()) {
    auto current = pending.back();
    pending.pop_back();
    uint64_t current_addr = current.first;
    int depth = current.second;

    if (embedded_by_remote.count(current_addr))
      continue;
    if (depth > max_depth)
      continue;

    auto code = StaticRelinker::embed_function(pid, current_addr, 0);
    if (code.empty() || code.size() < 4) {
      if (current_addr == addr)
        return {};
      continue;
    }

    while (result.size() % align)
      result.push_back(0);

    if (result.size() + code.size() > max_total_size) {
      if (current_addr == addr)
        return {};
      continue;
    }

    uint64_t local_offset = result.size();
    result.insert(result.end(), code.begin(), code.end());
    embedded_by_remote[current_addr] = local_offset;
    embedded_funcs.push_back({current_addr, local_offset, code.size(), depth});

    if (depth >= max_depth)
      continue;

    auto calls = InstructionDecoder::scan_calls(code.data(), code.size(),
                                                current_addr);
    for (const auto &c : calls) {
      uint64_t target = c.target_address;
      if (target == 0 || target == current_addr)
        continue;
      std::string target_lib =
          ProcessTracer::find_library_for_address(ranges, target);
      if (target_lib.empty())
        continue;

      uint64_t resolved_target = target;
      if (target_lib == root_lib) {
        uint64_t plt_resolved = InstructionDecoder::resolve_plt(pid, target);
        if (plt_resolved != 0) {
          std::string resolved_lib =
              ProcessTracer::find_library_for_address(ranges, plt_resolved);
          if (!resolved_lib.empty())
            resolved_target = plt_resolved;
        }
      }

      if (!embedded_by_remote.count(resolved_target) &&
          queued.insert(resolved_target).second) {
        pending.push_back({resolved_target, depth + 1});
      }
    }
  }

  auto root_it = embedded_by_remote.find(addr);
  if (root_it == embedded_by_remote.end())
    return {};

  patch_embedded_calls(result, pid, embedded_funcs, embedded_by_remote);
  return result;
}

static bool file_offset_to_vaddr_impl(const std::vector<uint8_t> &data,
                                      size_t file_off, uint64_t &vaddr_out) {
  Elf64ProgramHeaders elf;
  if (!parse_elf64_program_headers(data, &elf))
    return false;
  const uint64_t offset = static_cast<uint64_t>(file_off);
  for (const Elf64_Phdr &ph : elf.entries) {
    if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
      continue;
    if (offset < ph.p_offset)
      continue;
    const uint64_t delta = offset - ph.p_offset;
    if (delta >= ph.p_filesz ||
        !checked_u64_add(ph.p_vaddr, delta, &vaddr_out)) {
      continue;
    }
    return true;
  }
  return false;
}

static bool file_offset_to_vaddr(const std::vector<uint8_t> &data, size_t file_off,
                                 uint64_t &vaddr_out) {
  if (data.size() < EI_NIDENT || data[0] != 0x7f || data[1] != 'E' ||
      data[2] != 'L' || data[3] != 'F')
    return false;
  if (data[EI_CLASS] != ELFCLASS64)
    return false;
  return file_offset_to_vaddr_impl(data, file_off, vaddr_out);
}

static bool der_length(const std::vector<uint8_t> &data, size_t *pos,
                       size_t limit, size_t *length) {
  if (!pos || !length || limit > data.size() || *pos >= limit)
    return false;
  const uint8_t first = data[(*pos)++];
  if ((first & 0x80u) == 0) {
    *length = first;
    return true;
  }
  const size_t bytes = first & 0x7fu;
  if (bytes == 0 || bytes > 4 || bytes > limit - *pos ||
      data[*pos] == 0)
    return false;
  size_t value = 0;
  for (size_t i = 0; i < bytes; ++i)
    value = (value << 8) | data[(*pos)++];
  // DER requires short form for lengths below 128.
  if (value < 128)
    return false;
  *length = value;
  return true;
}

static bool der_tlv(const std::vector<uint8_t> &data, size_t pos, uint8_t tag,
                    size_t limit, size_t *content, size_t *length,
                    size_t *next) {
  if (!content || !length || !next || limit > data.size() || pos >= limit ||
      data[pos++] != tag || !der_length(data, &pos, limit, length) ||
      pos > limit || *length > limit - pos)
    return false;
  *content = pos;
  *next = pos + *length;
  return true;
}

struct DerInteger {
  size_t content = 0;
  size_t length = 0;
  size_t next = 0;
};

static bool read_der_integer(const std::vector<uint8_t> &data, size_t pos,
                             size_t limit, DerInteger *integer,
                             bool allow_zero = false) {
  if (!integer ||
      !der_tlv(data, pos, 0x02, limit, &integer->content, &integer->length,
               &integer->next) ||
      integer->length == 0)
    return false;
  const uint8_t first = data[integer->content];
  if ((first & 0x80u) != 0)
    return false; // negative INTEGER
  if (integer->length > 1 && first == 0 &&
      (data[integer->content + 1] & 0x80u) == 0)
    return false; // non-minimal positive INTEGER
  bool nonzero = false;
  for (size_t i = 0; i < integer->length; ++i)
    nonzero = nonzero || data[integer->content + i] != 0;
  return allow_zero || nonzero;
}

static size_t der_integer_effective_length(const std::vector<uint8_t> &data,
                                           const DerInteger &integer) {
  return integer.length -
         ((integer.length > 1 && data[integer.content] == 0) ? 1 : 0);
}

static bool rsa_exponent(const std::vector<uint8_t> &data,
                         const DerInteger &integer) {
  size_t pos = integer.content;
  size_t length = integer.length;
  if (length > 1 && data[pos] == 0) {
    ++pos;
    --length;
  }
  if (length == 0 || length > sizeof(uint64_t))
    return false;
  uint64_t value = 0;
  for (size_t i = 0; i < length; ++i)
    value = (value << 8) | data[pos + i];
  return value >= 3 && (value & 1u) != 0;
}

static bool parse_pkcs1_private(const std::vector<uint8_t> &data, size_t off,
                                size_t limit, size_t *container_end) {
  size_t body = 0, body_len = 0, end = 0;
  if (!der_tlv(data, off, 0x30, limit, &body, &body_len, &end) ||
      body_len < 32 || end - off > 64 * 1024)
    return false;
  DerInteger integers[9];
  size_t pos = body;
  for (size_t i = 0; i < 9; ++i) {
    if (!read_der_integer(data, pos, end, &integers[i], i == 0))
      return false;
    pos = integers[i].next;
  }
  if (pos != end || integers[0].length != 1 ||
      data[integers[0].content] != 0 ||
      der_integer_effective_length(data, integers[1]) < 64 ||
      !rsa_exponent(data, integers[2]))
    return false;
  if (container_end)
    *container_end = end;
  return true;
}

static bool parse_pkcs1_public(const std::vector<uint8_t> &data, size_t off,
                               size_t limit, size_t *container_end) {
  size_t body = 0, body_len = 0, end = 0;
  if (!der_tlv(data, off, 0x30, limit, &body, &body_len, &end) ||
      body_len < 8 || end - off > 64 * 1024)
    return false;
  DerInteger modulus, exponent;
  if (!read_der_integer(data, body, end, &modulus) ||
      !read_der_integer(data, modulus.next, end, &exponent) ||
      exponent.next != end ||
      der_integer_effective_length(data, modulus) < 64 ||
      !rsa_exponent(data, exponent))
    return false;
  if (container_end)
    *container_end = end;
  return true;
}

static bool parse_rsa_algorithm_identifier(const std::vector<uint8_t> &data,
                                           size_t off, size_t limit,
                                           size_t *next) {
  static constexpr uint8_t kRsaOid[] = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                        0x0d, 0x01, 0x01, 0x01};
  size_t body = 0, body_len = 0, end = 0;
  if (!der_tlv(data, off, 0x30, limit, &body, &body_len, &end))
    return false;
  size_t oid = 0, oid_len = 0, pos = 0;
  if (!der_tlv(data, body, 0x06, end, &oid, &oid_len, &pos) ||
      oid_len != sizeof(kRsaOid) ||
      memcmp(data.data() + oid, kRsaOid, sizeof(kRsaOid)) != 0)
    return false;
  if (pos < end) {
    size_t null_content = 0, null_len = 0, null_end = 0;
    if (!der_tlv(data, pos, 0x05, end, &null_content, &null_len, &null_end) ||
        null_len != 0)
      return false;
    pos = null_end;
  }
  if (pos != end)
    return false;
  if (next)
    *next = end;
  return true;
}

static bool parse_pkcs8_private(const std::vector<uint8_t> &data, size_t off,
                                size_t limit, size_t *container_end) {
  size_t body = 0, body_len = 0, end = 0;
  if (!der_tlv(data, off, 0x30, limit, &body, &body_len, &end) ||
      end - off > 64 * 1024)
    return false;
  DerInteger version;
  if (!read_der_integer(data, body, end, &version, true) ||
      version.length != 1 || data[version.content] != 0)
    return false;
  size_t pos = 0;
  if (!parse_rsa_algorithm_identifier(data, version.next, end, &pos))
    return false;
  size_t private_body = 0, private_len = 0, private_end = 0;
  if (!der_tlv(data, pos, 0x04, end, &private_body, &private_len,
               &private_end) ||
      private_end != end)
    return false;
  size_t inner_end = 0;
  if (!parse_pkcs1_private(data, private_body, private_end, &inner_end) ||
      inner_end != private_end)
    return false;
  if (container_end)
    *container_end = end;
  return true;
}

static bool parse_spki_public(const std::vector<uint8_t> &data, size_t off,
                              size_t limit, size_t *container_end) {
  size_t body = 0, body_len = 0, end = 0;
  if (!der_tlv(data, off, 0x30, limit, &body, &body_len, &end) ||
      end - off > 64 * 1024)
    return false;
  size_t pos = 0;
  if (!parse_rsa_algorithm_identifier(data, body, end, &pos))
    return false;
  size_t bits = 0, bits_len = 0, bits_end = 0;
  if (!der_tlv(data, pos, 0x03, end, &bits, &bits_len, &bits_end) ||
      bits_end != end || bits_len < 2 || data[bits] != 0)
    return false;
  size_t inner_end = 0;
  if (!parse_pkcs1_public(data, bits + 1, bits_end, &inner_end) ||
      inner_end != bits_end)
    return false;
  if (container_end)
    *container_end = end;
  return true;
}

enum class RsaDerKind { Pkcs1Private, Pkcs1Public, Pkcs8Private, SpkiPublic };

static bool classify_rsa_der(const std::vector<uint8_t> &data, size_t off,
                             size_t limit, RsaDerKind *kind,
                             size_t *container_end) {
  size_t end = 0;
  if (parse_pkcs1_private(data, off, limit, &end)) {
    *kind = RsaDerKind::Pkcs1Private;
  } else if (parse_pkcs1_public(data, off, limit, &end)) {
    *kind = RsaDerKind::Pkcs1Public;
  } else if (parse_pkcs8_private(data, off, limit, &end)) {
    *kind = RsaDerKind::Pkcs8Private;
  } else if (parse_spki_public(data, off, limit, &end)) {
    *kind = RsaDerKind::SpkiPublic;
  } else {
    return false;
  }
  if (container_end)
    *container_end = end;
  return true;
}

static int base64_value(uint8_t byte) {
  if (byte >= 'A' && byte <= 'Z')
    return byte - 'A';
  if (byte >= 'a' && byte <= 'z')
    return byte - 'a' + 26;
  if (byte >= '0' && byte <= '9')
    return byte - '0' + 52;
  if (byte == '+')
    return 62;
  if (byte == '/')
    return 63;
  return -1;
}

static bool decode_pem_base64(const std::vector<uint8_t> &data, size_t begin,
                              size_t end, std::vector<uint8_t> *decoded) {
  if (!decoded || begin > end || end > data.size())
    return false;
  std::vector<uint8_t> encoded;
  encoded.reserve(end - begin);
  for (size_t i = begin; i < end; ++i) {
    const uint8_t byte = data[i];
    if (byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n')
      continue;
    if (byte != '=' && base64_value(byte) < 0)
      return false;
    encoded.push_back(byte);
  }
  if (encoded.empty() || encoded.size() % 4 != 0 ||
      encoded.size() > 4 * 64 * 1024 / 3 + 4)
    return false;
  decoded->clear();
  decoded->reserve(encoded.size() / 4 * 3);
  for (size_t i = 0; i < encoded.size(); i += 4) {
    const bool last = i + 4 == encoded.size();
    const int a = base64_value(encoded[i]);
    const int b = base64_value(encoded[i + 1]);
    if (a < 0 || b < 0)
      return false;
    const bool pad2 = encoded[i + 2] == '=';
    const bool pad3 = encoded[i + 3] == '=';
    if ((pad2 && !pad3) || ((pad2 || pad3) && !last))
      return false;
    const int c = pad2 ? 0 : base64_value(encoded[i + 2]);
    const int d = pad3 ? 0 : base64_value(encoded[i + 3]);
    if (c < 0 || d < 0 || (pad2 && (b & 0x0f) != 0) ||
        (pad3 && !pad2 && (c & 0x03) != 0))
      return false;
    const uint32_t value = (static_cast<uint32_t>(a) << 18) |
                           (static_cast<uint32_t>(b) << 12) |
                           (static_cast<uint32_t>(c) << 6) |
                           static_cast<uint32_t>(d);
    decoded->push_back(static_cast<uint8_t>(value >> 16));
    if (!pad2)
      decoded->push_back(static_cast<uint8_t>(value >> 8));
    if (!pad3)
      decoded->push_back(static_cast<uint8_t>(value));
  }
  return !decoded->empty() && decoded->size() <= 64 * 1024;
}

static bool crypto_candidate_address(const std::vector<uint8_t> &data,
                                     uint64_t base_addr, size_t file_offset,
                                     uint64_t *address) {
  if (!address)
    return false;
  uint64_t relative = static_cast<uint64_t>(file_offset);
  const bool elf_image = data.size() >= SELFMAG &&
                         memcmp(data.data(), ELFMAG, SELFMAG) == 0;
  uint64_t vaddr = 0;
  if (elf_image) {
    // An ELF file offset is not a runtime address. If malformed headers or a
    // hole prevent an exact PT_LOAD translation, discard the candidate rather
    // than reporting base+file_offset from unrelated file-layout bytes.
    if (!file_offset_to_vaddr(data, file_offset, vaddr))
      return false;
    relative = vaddr;
  }
  return checked_u64_add(base_addr, relative, address);
}

static const char *rsa_algorithm(RsaDerKind kind) {
  return kind == RsaDerKind::Pkcs1Private ||
                 kind == RsaDerKind::Pkcs8Private
             ? "RSA-PRIVATE"
             : "RSA-PUBLIC";
}

static const char *rsa_der_source(RsaDerKind kind) {
  switch (kind) {
  case RsaDerKind::Pkcs1Private:
    return "DER-PKCS1";
  case RsaDerKind::Pkcs1Public:
    return "DER-PKCS1-PUBLIC";
  case RsaDerKind::Pkcs8Private:
    return "DER-PKCS8";
  case RsaDerKind::SpkiPublic:
    return "DER-SPKI";
  }
  return "DER";
}

static void append_rsa_candidates(const std::vector<uint8_t> &data,
                                  uint64_t base_addr,
                                  std::vector<CryptoKeyInfo> *keys) {
  if (!keys)
    return;
  struct PemMarker {
    const char *begin;
    const char *end;
    RsaDerKind expected;
    const char *source;
  };
  static constexpr PemMarker pem_markers[] = {
      {"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----",
       RsaDerKind::Pkcs1Private, "PEM-PKCS1"},
      {"-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----",
       RsaDerKind::Pkcs8Private, "PEM-PKCS8"},
      {"-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----",
       RsaDerKind::Pkcs1Public, "PEM-PKCS1-PUBLIC"},
      {"-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----",
       RsaDerKind::SpkiPublic, "PEM-SPKI"},
  };

  static constexpr size_t kMaxPemSpan = 128 * 1024;
  static constexpr size_t kMaxPemCandidates = 4096;
  size_t pem_candidates = 0;
  for (const auto &marker : pem_markers) {
    const size_t begin_len = strlen(marker.begin);
    const size_t end_len = strlen(marker.end);
    size_t at = std::numeric_limits<size_t>::max();
    size_t body_begin = 0;
    for (size_t cursor = 0; cursor < data.size();) {
      if (begin_len <= data.size() - cursor &&
          memcmp(data.data() + cursor, marker.begin, begin_len) == 0) {
        // A nested BEGIN invalidates the earlier unterminated candidate. The
        // cursor never moves backwards, so adversarial repeated markers remain
        // O(N) instead of rescanning the entire suffix for every BEGIN.
        at = cursor;
        body_begin = cursor + begin_len;
        cursor = body_begin;
        continue;
      }
      if (at == std::numeric_limits<size_t>::max()) {
        ++cursor;
        continue;
      }
      if (cursor - body_begin > kMaxPemSpan) {
        at = std::numeric_limits<size_t>::max();
        ++cursor;
        continue;
      }
      if (end_len > data.size() - cursor ||
          memcmp(data.data() + cursor, marker.end, end_len) != 0) {
        ++cursor;
        continue;
      }

      const size_t end_at = cursor;
      const size_t pem_end = end_at + end_len;
      cursor = pem_end;
      const size_t candidate_at = at;
      at = std::numeric_limits<size_t>::max();
      if (++pem_candidates > kMaxPemCandidates)
        return;

      std::vector<uint8_t> decoded;
      RsaDerKind actual{};
      size_t der_end = 0;
      uint64_t address = 0;
      if (!decode_pem_base64(data, body_begin, end_at, &decoded) ||
          !classify_rsa_der(decoded, 0, decoded.size(), &actual, &der_end) ||
          actual != marker.expected || der_end != decoded.size() ||
          !crypto_candidate_address(data, base_addr, candidate_at, &address))
        continue;

      CryptoKeyInfo info;
      info.key_addr = address;
      info.key_data.assign(data.begin() + static_cast<ptrdiff_t>(candidate_at),
                           data.begin() + static_cast<ptrdiff_t>(pem_end));
      info.algorithm = rsa_algorithm(actual);
      info.source = marker.source;
      info.confidence = 1.0;
      keys->push_back(std::move(info));
    }
  }

  for (size_t off = 0; off + 16 <= data.size(); ++off) {
    if (data[off] != 0x30)
      continue;
    RsaDerKind kind{};
    size_t end = 0;
    uint64_t address = 0;
    if (!classify_rsa_der(data, off, data.size(), &kind, &end) || end <= off ||
        end - off > 64 * 1024 ||
        !crypto_candidate_address(data, base_addr, off, &address))
      continue;

    CryptoKeyInfo info;
    info.key_addr = address;
    info.key_data.assign(data.begin() + static_cast<ptrdiff_t>(off),
                         data.begin() + static_cast<ptrdiff_t>(end));
    info.algorithm = rsa_algorithm(kind);
    info.source = rsa_der_source(kind);
    info.confidence = 0.99;
    keys->push_back(std::move(info));
    off = end - 1;
  }
}

bool StaticRelinkerEx::patch_relocations(
    std::vector<uint8_t> &data, const std::map<uint64_t, uint64_t> &addr_map,
    uint64_t base_addr) {

  for (size_t i = 0; i + 4 <= data.size(); i += 4) {
    uint32_t inst = read_le32(data.data() + i);
    uint64_t call_vaddr = 0;
    if (!file_offset_to_vaddr(data, i, call_vaddr))
      continue;

    {
      if ((inst & 0xFC000000) == 0x94000000) {
        int32_t offset = inst & 0x03FFFFFF;
        if (offset & 0x02000000)
          offset |= 0xFC000000;
        uint64_t target_remote =
            base_addr + call_vaddr + static_cast<int64_t>(offset) * 4;
        auto it = addr_map.find(target_remote);
        if (it != addr_map.end())
          patch_call_site(data, i, it->second);
      }
    }
  }

  return true;
}

std::vector<CryptoKeyInfo>
CryptoAnalyzer::scan_for_keys(const std::vector<uint8_t> &data,
                              uint64_t base_addr) {
  std::vector<CryptoKeyInfo> keys;

  auto aes_keys = ElfParser::detect_aes_keys(data);

  for (const auto &k : aes_keys) {
    CryptoKeyInfo info;
    if (!crypto_candidate_address(data, base_addr,
                                  static_cast<size_t>(k.offset),
                                  &info.key_addr))
      continue;
    if (k.key_size > 0)
      info.key_data.assign(k.key, k.key + k.key_size);
    if (k.key_size == 16)
      info.algorithm = "AES-128";
    else if (k.key_size == 24)
      info.algorithm = "AES-192";
    else if (k.key_size == 32)
      info.algorithm = "AES-256";
    else if (k.detection_method == "S-BOX")
      info.algorithm = "AES-SBOX";
    else
      info.algorithm = "UNKNOWN";
    info.source = k.detection_method;
    info.confidence = k.confidence;
    keys.push_back(info);
  }

  append_rsa_candidates(data, base_addr, &keys);
  return keys;
}

// Hook state is keyed by (pid,address): ASLR commonly gives two processes the
// same function address, and an address-only map made restoring one target
// write another target's saved bytes and discard both records.
static std::mutex g_crypto_mu;
struct CryptoHookState {
  HookInfo inline_hook;
  uint64_t hook_addr = 0;
  size_t hook_size = 0;
  bool ready = false;
};
static std::map<std::pair<int, uint64_t>, CryptoHookState> g_crypto_hooks;


static CryptoHookResult
hook_aes_function(int pid, uint64_t *original, const char *primary_sym,
                  const char *nohw_sym, const char *openssl_sym) {
  uint64_t func_addr =
      FunctionHooker::find_remote_symbol(pid, "libcrypto.so", primary_sym);
  if (func_addr == 0)
    func_addr =
        FunctionHooker::find_remote_symbol(pid, "libcrypto.so", nohw_sym);
  if (func_addr == 0)
    func_addr =
        FunctionHooker::find_remote_symbol(pid, "libcrypto.so", openssl_sym);

  if (func_addr == 0)
    return CryptoHookResult::NotFound;

  if (original)
    *original = func_addr;

  std::lock_guard<std::mutex> lock(g_crypto_mu);
  const auto key = std::make_pair(pid, func_addr);
  auto existing = g_crypto_hooks.find(key);
  if (existing != g_crypto_hooks.end())
    return existing->second.ready ? CryptoHookResult::Installed
                                  : CryptoHookResult::StateUnknown;

  {
    std::vector<uint8_t> hook_code;

    uint32_t prologue[] = {
        0xA9BE7BFD,
        0xA9010FE0,
    };
    for (auto inst : prologue)
      hook_code.insert(hook_code.end(), (uint8_t *)&inst, (uint8_t *)&inst + 4);

    uint32_t epilogue[] = {
        0xA9410FE0,
        0xA8C27BFD,
    };
    for (auto inst : epilogue)
      hook_code.insert(hook_code.end(), (uint8_t *)&inst, (uint8_t *)&inst + 4);

    // ldr x16, #8 then br x16. The old code paired this LDR (which targets
    // x16) with 0xD61F0140 = `br x10`, so the hook jumped to whatever happened
    // to be in x10 -- an immediate crash on every hooked call.
    uint32_t ldr_x16 = 0x58000050;
    uint32_t br_x16 = 0xD61F0200;
    hook_code.insert(hook_code.end(), (uint8_t *)&ldr_x16,
                     (uint8_t *)&ldr_x16 + 4);
    hook_code.insert(hook_code.end(), (uint8_t *)&br_x16,
                     (uint8_t *)&br_x16 + 4);
    hook_code.insert(hook_code.end(), (uint8_t *)&func_addr,
                     (uint8_t *)&func_addr + 8);

    uint64_t hook_addr =
        FunctionHooker::allocate_remote(pid, hook_code.size() + 64);
    if (hook_addr == 0)
      return CryptoHookResult::SafeFailure;

    if (write_generated_executable_checked(
            pid, hook_addr, hook_code.data(), hook_code.size()) !=
        ExecutableWriteResult::WrittenVerified) {
      FunctionHooker::free_remote(pid, hook_addr, hook_code.size() + 64);
      return CryptoHookResult::SafeFailure;
    }

    HookInfo info;
    if (!MemoryInjector::install_inline_hook(pid, func_addr, hook_addr,
                                             &info)) {
      bool state_unknown = info.active;
      if (state_unknown) {
        g_crypto_hooks.emplace(
            key, CryptoHookState{std::move(info), hook_addr,
                                 hook_code.size() + 64, false});
      } else {
        FunctionHooker::free_remote(pid, hook_addr, hook_code.size() + 64);
      }
      return state_unknown ? CryptoHookResult::StateUnknown
                           : CryptoHookResult::SafeFailure;
    }

    ExecutableWriteResult literal_result =
        MemoryInjector::write_executable_checked(
            pid, hook_addr + hook_code.size() - 8, &info.trampoline_addr, 8);
    if (literal_result != ExecutableWriteResult::WrittenVerified) {
      if (MemoryInjector::remove_inline_hook(pid, info)) {
        FunctionHooker::free_remote(pid, hook_addr, hook_code.size() + 64);
      } else {
        // The target may still branch into this allocation. Preserve both the
        // destination and its retryable restore state.
        g_crypto_hooks.emplace(
            key, CryptoHookState{std::move(info), hook_addr,
                                 hook_code.size() + 64, false});
        return CryptoHookResult::StateUnknown;
      }
      return CryptoHookResult::SafeFailure;
    }
    g_crypto_hooks.emplace(
        key, CryptoHookState{std::move(info), hook_addr,
                             hook_code.size() + 64, true});
  }

  return CryptoHookResult::Installed;
}

CryptoHookResult CryptoAnalyzer::hook_aes_encrypt(int pid,
                                                  uint64_t *original) {
  return hook_aes_function(pid, original, "AES_encrypt", "aes_nohw_encrypt",
                           "OPENSSL_AES_encrypt");
}

CryptoHookResult CryptoAnalyzer::hook_aes_decrypt(int pid,
                                                  uint64_t *original) {
  return hook_aes_function(pid, original, "AES_decrypt", "aes_nohw_decrypt",
                           "OPENSSL_AES_decrypt");
}

CryptoRestoreResult CryptoAnalyzer::restore_aes_hooks(int pid) {
  std::lock_guard<std::mutex> lock(g_crypto_mu);
  CryptoRestoreResult result;
  for (auto it = g_crypto_hooks.begin(); it != g_crypto_hooks.end();) {
    if (it->first.first != pid) {
      ++it;
      continue;
    }
    CryptoHookState &state = it->second;
    if (!MemoryInjector::remove_inline_hook(pid, state.inline_hook)) {
      result.remaining++;
      ++it; // keep the live branch destination and retryable state
      continue;
    }
    result.restored++;
    if (state.hook_addr != 0 && state.hook_size != 0)
      (void)FunctionHooker::free_remote(pid, state.hook_addr, state.hook_size);
    it = g_crypto_hooks.erase(it);
  }
  return result;
}
