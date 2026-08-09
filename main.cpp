#include "memory.h"
#include "rizin_bridge.h"
#include "tracer.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <grp.h>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <limits.h>
#include <linux/capability.h>
#include <map>
#include <memory>
#include <mutex>
#include <poll.h>
#include <sched.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <tuple>
#include <unistd.h>

#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_execveat
#define SYS_execveat 281
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

// libzip is already part of the statically linked Rizin IO archive.  Its
// generated zipconf.h is intentionally not on Hayabusa's public include path,
// so keep the tiny C ABI surface used here local instead of adding another
// build-time dependency.  The opaque types never cross this translation unit.
extern "C" {
struct HayabusaZip;
struct HayabusaZipFile;
struct HayabusaZipSource;
struct HayabusaZipError {
  int zip_err;
  int sys_err;
  char *str;
};
void zip_error_init(HayabusaZipError *);
void zip_error_fini(HayabusaZipError *);
const char *zip_error_strerror(HayabusaZipError *);
HayabusaZipSource *zip_source_buffer_create(const void *, uint64_t, int,
                                             HayabusaZipError *);
void zip_source_free(HayabusaZipSource *);
HayabusaZip *zip_open_from_source(HayabusaZipSource *, int,
                                   HayabusaZipError *);
void zip_discard(HayabusaZip *);
int64_t zip_get_num_entries(HayabusaZip *, uint32_t);
const char *zip_get_name(HayabusaZip *, uint64_t, uint32_t);
HayabusaZipFile *zip_fopen_index(HayabusaZip *, uint64_t, uint32_t);
int64_t zip_fread(HayabusaZipFile *, void *, uint64_t);
int zip_fclose(HayabusaZipFile *);
}

thread_local char g_current_module[256] = {};
thread_local const char *g_current_step = nullptr;
// All RzCore instances in this process share Rizin's singleton console, break
// stack and current-core callbacks. This lock must outlive an individual dump
// invocation so no future in-process caller can accidentally create a second
// unsynchronised engine domain.
std::mutex g_rizin_engine_mu;

// Immutable bytes captured while every target thread is ptrace-stopped.
// Analysis must consume these snapshots instead of returning to /proc/<pid>/mem
// after the target has resumed.
struct MemoryRegionSnapshot {
  MapEntry mapping;
  std::vector<uint8_t> data;
};

struct RuntimeMemorySnapshot {
  std::vector<MemoryRegionSnapshot> anonymous;
  std::vector<MemoryRegionSnapshot> writable_modules;
  bool anonymous_truncated = false;
  bool writable_truncated = false;
};

class ScopedProcessStop {
public:
  explicit ScopedProcessStop(int pid) : pid_(pid) {
    active_ = ProcessTracer::attach(pid);
    if (active_) {
      do {
        pidfd_ = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
      } while (pidfd_ < 0 && errno == EINTR);
      int identity_ok = -1;
      if (pidfd_ >= 0) {
        do {
          identity_ok = static_cast<int>(
              syscall(SYS_pidfd_send_signal, pidfd_, 0, nullptr, 0));
        } while (identity_ok < 0 && errno == EINTR);
      }
      if (pidfd_ < 0 || identity_ok != 0) {
        if (!ProcessTracer::detach(pid_))
          (void)ProcessTracer::recover_attached(pid_);
        active_ = false;
      }
    }
    if (!active_ && pidfd_ >= 0) {
        close(pidfd_);
        pidfd_ = -1;
    }
  }

  ScopedProcessStop(const ScopedProcessStop &) = delete;
  ScopedProcessStop &operator=(const ScopedProcessStop &) = delete;

  ~ScopedProcessStop() {
    if (active_ && !ProcessTracer::detach(pid_) &&
        !ProcessTracer::recover_attached(pid_)) {
      if (pidfd_ >= 0) {
        int rc;
        do {
          rc = static_cast<int>(syscall(SYS_pidfd_send_signal, pidfd_,
                                        SIGKILL, nullptr, 0));
        } while (rc < 0 && errno == EINTR);
      }
      ProcessTracer::cleanup_all_attached();
      ProcessTracer::reset_attach_bookkeeping();
    }
    if (pidfd_ >= 0)
      close(pidfd_);
  }

  bool attached() const { return active_; }

  bool resume() {
    if (!active_)
      return false;
    if (!ProcessTracer::detach(pid_))
      return false;
    active_ = false;
    if (pidfd_ >= 0) {
      close(pidfd_);
      pidfd_ = -1;
    }
    return true;
  }

private:
  int pid_;
  int pidfd_ = -1;
  bool active_;
};

static constexpr const char *USAGE =
    "Usage:\n"
    "  hayabusa dump    <target> [--launch | --launch-cmd "
    "<cmd>]\n"
    "                   [--snapshots <n>] [--interval <ms>] [--timeout <sec>]\n"
    "                   [--only <substrings>] [--fast] [--deobf] "
    "[--min-str <n>]\n"
    "                   [--limit <n>] [--listing <n>] [--relink] "
    "[--relink-limit <MiB>] "
    "[--trace-init]\n"
    "                   [--p <files>] [--rd <depth>] [--threads <n>]\n"
    "                   [--rz-analysis off|basic|full]\n"
    "                   [--analysis-timeout <sec>] [--deobf-timeout <sec>]\n"
    "                   [--memory-limit <MiB>] [--image-limit <MiB>]\n"
    "                   [--string-limit <MiB>] [--deobf-probes <n>]\n"
    "                   [--require-complete]\n"
    "  hayabusa unpack  <target> [--launch | --launch-cmd "
    "<cmd>]\n"
    "                   [--timeout <sec>] [--limit <n>] "
    "[--memory-limit <MiB>]\n"
    "  hayabusa hook    <process> <function> [--i "
    "<count>]\n"
    "  hayabusa stub    <process> <function>\n"
    "  hayabusa inject  <process> <so_path> \n"
    "  hayabusa scan    <process> <pattern> \n"
    "  hayabusa extract <process> <function> [--d "
    "<depth>] [--size-limit <MiB>]\n"
    "\n"
    "  <target> selects a running process/package when no launch option is "
    "used.\n"
    "  --launch requires <target> to be an executable file path (direct "
    "exec).\n"
    "  --launch-cmd runs <cmd> verbatim through /system/bin/sh -c.\n"
    "  HAYABUSA_OUTPUT_ROOT selects a trusted absolute output root.\n";

// The signal handler and command loops share this flag across asynchronous
// execution. Require the implementation to provide a genuinely lock-free
// atomic so the handler can never enter a hidden library lock.
static_assert(std::atomic<bool>::is_always_lock_free,
              "hook signal flag must be lock-free");
static std::atomic<bool> g_hook_running{false};

// A launched process tree is owned by a dedicated subreaper supervisor. Keep
// the supervisor PID and the analyzer's sole control-pipe descriptor in one
// lock-free word. Closing that exact descriptor is async-signal-safe and also
// happens automatically on SIGKILL: EOF tells the still-running supervisor to
// pidfd-kill and reap every descendant, including children which escaped the
// original process group with setsid(). UINT64_MAX claims the slot for cleanup.
static constexpr uint64_t kLaunchCleanupClaimed = UINT64_MAX;
static std::atomic<uint64_t> g_active_launch_state{0};
static_assert(std::atomic<uint64_t>::is_always_lock_free);

static uint64_t pack_launch_state(pid_t supervisor, int control_fd) {
  return (uint64_t(static_cast<uint32_t>(supervisor)) << 32) |
         (static_cast<uint32_t>(control_fd) + 1u);
}

static void cleanup_active_launch_signal_safe() {
  const uint64_t state = g_active_launch_state.exchange(
      kLaunchCleanupClaimed, std::memory_order_acq_rel);
  if (state == 0 || state == kLaunchCleanupClaimed)
    return;
  const pid_t supervisor = static_cast<pid_t>(state >> 32);
  const uint32_t encoded_fd = static_cast<uint32_t>(state);
  const int control_fd =
      encoded_fd == 0 ? -1 : static_cast<int>(encoded_fd - 1u);
  if (supervisor > 0 && control_fd >= 0)
    close(control_fd); // EOF is the supervisor's fail-closed command.
}

void cleanup() {
  cleanup_active_launch_signal_safe();
  ProcessTracer::cleanup_all_attached();
}

void signal_handler(int sig) {
  static constexpr char msg[] = "\n[!] Signal received: ";
  write(STDOUT_FILENO, msg, sizeof(msg) - 1);
  char digits[16];
  size_t pos = sizeof(digits);
  unsigned value = sig < 0 ? unsigned(-sig) : unsigned(sig);
  do {
    digits[--pos] = char('0' + value % 10);
    value /= 10;
  } while (value != 0 && pos != 0);
  if (sig < 0 && pos != 0)
    digits[--pos] = '-';
  write(STDOUT_FILENO, digits + pos, sizeof(digits) - pos);
  write(STDOUT_FILENO, "\n", 1);
  cleanup();
  _exit(1);
}

void mkdir_p(const std::string &path) {
  std::string tmp = path;
  for (size_t i = 1; i < tmp.length(); i++) {
    if (tmp[i] == '/') {
      tmp[i] = 0;
      mkdir(tmp.c_str(), 0755);
      tmp[i] = '/';
    }
  }
  mkdir(path.c_str(), 0755);
}

// Every target-derived path component is reduced to a conservative portable
// alphabet. In particular, never allow '.', '..', slashes, control bytes, or
// an overlong component to change the directory selected by the caller.
static std::string safe_path_component(const std::string &value) {
  constexpr size_t kMaxComponent = 160;
  std::string safe;
  safe.reserve(std::min(value.size(), kMaxComponent));
  for (unsigned char c : value) {
    if (safe.size() == kMaxComponent)
      break;
    const bool allowed = (c >= 'a' && c <= 'z') ||
                         (c >= 'A' && c <= 'Z') ||
                         (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                         c == '-';
    safe.push_back(allowed ? static_cast<char>(c) : '_');
  }
  if (safe.empty() || safe == "." || safe == "..")
    safe = "unknown";
  return safe;
}

static bool validate_existing_output_tree(int directory_fd, size_t depth,
                                          size_t *entries,
                                          std::string *error) {
  constexpr size_t kMaxDepth = 32;
  constexpr size_t kMaxEntries = 100000;
  if (directory_fd < 0 || !entries || depth > kMaxDepth) {
    if (error)
      *error = "output tree exceeds the safe recursion depth";
    return false;
  }
  // dup() shares the directory open-file-description and therefore its
  // readdir cursor. Validation followed by clearing would otherwise duplicate
  // an EOF cursor and silently retain every stale artifact. Re-open "." to get
  // an independent description at offset zero for each recursive pass.
  const int scan_fd = openat(directory_fd, ".",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (scan_fd < 0) {
    if (error)
      *error = "cannot open output directory scan: " +
               std::string(strerror(errno));
    return false;
  }
  DIR *directory = fdopendir(scan_fd);
  if (!directory) {
    const int saved = errno;
    close(scan_fd);
    if (error)
      *error = "cannot inspect output directory: " +
               std::string(strerror(saved));
    return false;
  }
  bool ok = true;
  for (;;) {
    errno = 0;
    dirent *entry = readdir(directory);
    if (!entry) {
      if (errno != 0) {
        if (error)
          *error = "cannot enumerate existing output directory";
        ok = false;
      }
      break;
    }
    if (strcmp(entry->d_name, ".") == 0 ||
        strcmp(entry->d_name, "..") == 0)
      continue;
    if (++*entries > kMaxEntries) {
      if (error)
        *error = "output tree exceeds the safe entry budget";
      ok = false;
      break;
    }
    struct stat before {};
    if (fstatat(directory_fd, entry->d_name, &before,
                AT_SYMLINK_NOFOLLOW) != 0) {
      if (error)
        *error = "cannot inspect existing output entry";
      ok = false;
      break;
    }
    const bool is_directory = S_ISDIR(before.st_mode);
    if (!is_directory && (!S_ISREG(before.st_mode) || before.st_nlink != 1)) {
      if (error)
        *error = "refusing non-regular or multiply-linked output entry";
      ok = false;
      break;
    }
    int child = openat(directory_fd, entry->d_name,
                       O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                           (is_directory ? O_DIRECTORY : 0));
    if (child < 0) {
      if (error)
        *error = "cannot safely open existing output entry";
      ok = false;
      break;
    }
    struct stat after {};
    if (fstat(child, &after) != 0 || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_mode != after.st_mode) {
      if (error)
        *error = "output entry changed during validation";
      close(child);
      ok = false;
      break;
    }
    if (after.st_uid != geteuid() ||
        (is_directory && !validate_existing_output_tree(
                             child, depth + 1, entries, error))) {
      if (error && error->empty())
        *error = "refusing output entry with an unexpected owner";
      close(child);
      ok = false;
      break;
    }
    close(child);
  }
  closedir(directory);
  return ok;
}

static bool clear_validated_output_tree(int directory_fd, size_t depth,
                                        size_t *entries,
                                        std::string *error) {
  constexpr size_t kMaxDepth = 32;
  constexpr size_t kMaxEntries = 100000;
  if (directory_fd < 0 || !entries || depth > kMaxDepth)
    return false;
  const int scan_fd = openat(directory_fd, ".",
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (scan_fd < 0)
    return false;
  DIR *directory = fdopendir(scan_fd);
  if (!directory) {
    close(scan_fd);
    return false;
  }
  bool ok = true;
  for (;;) {
    errno = 0;
    dirent *entry = readdir(directory);
    if (!entry) {
      if (errno != 0)
        ok = false;
      break;
    }
    if (strcmp(entry->d_name, ".") == 0 ||
        strcmp(entry->d_name, "..") == 0)
      continue;
    if (++*entries > kMaxEntries) {
      ok = false;
      break;
    }
    struct stat st {};
    if (fstatat(directory_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 ||
        st.st_uid != geteuid()) {
      ok = false;
      break;
    }
    if (S_ISDIR(st.st_mode)) {
      int child = openat(directory_fd, entry->d_name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (child < 0 ||
          !clear_validated_output_tree(child, depth + 1, entries, error)) {
        if (child >= 0)
          close(child);
        ok = false;
        break;
      }
      close(child);
      if (unlinkat(directory_fd, entry->d_name, AT_REMOVEDIR) != 0) {
        ok = false;
        break;
      }
    } else if (!S_ISREG(st.st_mode) || st.st_nlink != 1 ||
               unlinkat(directory_fd, entry->d_name, 0) != 0) {
      ok = false;
      break;
    }
  }
  closedir(directory);
  if (!ok && error && error->empty())
    *error = "cannot safely replace the previous output tree";
  return ok;
}

static constexpr const char *kDefaultOutputRoot = "/data/local/hayabusa";
static std::string g_output_root = kDefaultOutputRoot;

// The default Android deployment area is shared with the shell user, including
// authority to rename children owned by root. Keep authoritative output below
// a separately owned anchor and retain a descriptor to the exact run directory
// for the complete command. HAYABUSA_OUTPUT_ROOT may select another trusted
// absolute root; the same owner/mode/no-follow checks apply there.
class SecureRunDirectory {
public:
  SecureRunDirectory() = default;
  SecureRunDirectory(const SecureRunDirectory &) = delete;
  SecureRunDirectory &operator=(const SecureRunDirectory &) = delete;
  SecureRunDirectory(SecureRunDirectory &&other) noexcept
      : fd_(other.fd_), display_path_(std::move(other.display_path_)),
        io_path_(std::move(other.io_path_)), error_(std::move(other.error_)) {
    other.fd_ = -1;
  }
  SecureRunDirectory &operator=(SecureRunDirectory &&other) noexcept {
    if (this == &other)
      return *this;
    if (fd_ >= 0)
      close(fd_);
    fd_ = other.fd_;
    display_path_ = std::move(other.display_path_);
    io_path_ = std::move(other.io_path_);
    error_ = std::move(other.error_);
    other.fd_ = -1;
    return *this;
  }
  ~SecureRunDirectory() {
    if (fd_ >= 0)
      close(fd_);
  }

  static SecureRunDirectory create(const std::string &output_root,
                                   const std::string &leaf_value) {
    SecureRunDirectory result;
    const std::string leaf = safe_path_component(leaf_value);
    std::string root = output_root;
    while (root.size() > 1 && root.back() == '/')
      root.pop_back();
    if (root.empty() || root.front() != '/') {
      result.error_ = "output root must be an absolute path";
      return result;
    }
    const size_t slash = root.rfind('/');
    const std::string parent_path = slash == 0 ? "/" : root.substr(0, slash);
    const std::string anchor_leaf = root.substr(slash + 1);
    if (anchor_leaf.empty() || safe_path_component(anchor_leaf) != anchor_leaf) {
      result.error_ = "output root has an unsafe final component";
      return result;
    }
    result.display_path_ = root + "/" + leaf;

    int parent = open(parent_path.c_str(),
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) {
      result.error_ = "cannot open trusted output parent: " +
                      std::string(strerror(errno));
      return result;
    }
    struct stat trusted_parent_st {};
    if (fstat(parent, &trusted_parent_st) != 0 ||
        !S_ISDIR(trusted_parent_st.st_mode) ||
        trusted_parent_st.st_uid != geteuid() ||
        (trusted_parent_st.st_mode & 0022) != 0) {
      result.error_ = "refusing output parent with unexpected owner or mode";
      close(parent);
      return result;
    }
    if (mkdirat(parent, anchor_leaf.c_str(), 0700) != 0 && errno != EEXIST) {
      result.error_ = "cannot create trusted output anchor: " +
                      std::string(strerror(errno));
      close(parent);
      return result;
    }
    int anchor = openat(parent, anchor_leaf.c_str(),
                        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const int anchor_error = errno;
    close(parent);
    if (anchor < 0) {
      result.error_ = "refusing unsafe output anchor: " +
                      std::string(strerror(anchor_error));
      return result;
    }
    struct stat parent_st {};
    if (fstat(anchor, &parent_st) != 0 || !S_ISDIR(parent_st.st_mode) ||
        parent_st.st_uid != geteuid() || (parent_st.st_mode & 0022) != 0) {
      result.error_ = "refusing output anchor with unexpected owner or mode";
      close(anchor);
      return result;
    }
    if ((parent_st.st_mode & 0777) != 0700 && fchmod(anchor, 0700) != 0) {
      result.error_ = "cannot secure output anchor permissions: " +
                      std::string(strerror(errno));
      close(anchor);
      return result;
    }
    // The embedded decompiler's content-addressed Sleigh cache is also kept
    // under this validated private root. Module images use memfd and never
    // create a pathname.
    rzb::set_scratch_directory(root);
    if (mkdirat(anchor, leaf.c_str(), 0700) != 0 && errno != EEXIST) {
      result.error_ = "cannot create output directory: " +
                      std::string(strerror(errno));
      close(anchor);
      return result;
    }
    int fd = openat(anchor, leaf.c_str(),
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const int open_error = errno;
    close(anchor);
    if (fd < 0) {
      result.error_ = "refusing unsafe output directory: " +
                      std::string(strerror(open_error));
      return result;
    }
    struct stat st {};
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid()) {
      result.error_ =
          "refusing output directory with unexpected type or owner";
      close(fd);
      return result;
    }
    if ((st.st_mode & 0022) != 0) {
      result.error_ =
          "refusing an existing output directory with writable group/other bits";
      close(fd);
      return result;
    }
    // Old Hayabusa versions created mode-0755 trees. Tighten the run root, then
    // validate and remove the previous run's complete contents so stale PIDs or
    // modules can never be presented as part of the new authoritative result.
    if ((st.st_mode & 0777) != 0700 && fchmod(fd, 0700) != 0) {
      result.error_ = "cannot secure output directory permissions: " +
                      std::string(strerror(errno));
      close(fd);
      return result;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
      result.error_ = errno == EWOULDBLOCK
                          ? "another Hayabusa run owns this output directory"
                          : "cannot lock output directory: " +
                                std::string(strerror(errno));
      close(fd);
      return result;
    }
    size_t existing_entries = 0;
    if (!validate_existing_output_tree(fd, 0, &existing_entries,
                                       &result.error_)) {
      close(fd);
      return result;
    }
    size_t cleared_entries = 0;
    if (!clear_validated_output_tree(fd, 0, &cleared_entries,
                                     &result.error_)) {
      close(fd);
      return result;
    }
    result.fd_ = fd;
    result.io_path_ = "/proc/self/fd/" + std::to_string(fd);
    return result;
  }

  explicit operator bool() const { return fd_ >= 0; }
  const std::string &display_path() const { return display_path_; }
  const std::string &io_path() const { return io_path_; }
  const std::string &error() const { return error_; }

private:
  int fd_ = -1;
  std::string display_path_;
  std::string io_path_;
  std::string error_;
};

// Output directory for a run. The target is named either by package
// (com.example.app) or by path (/data/local/tmp/target); pasting the second
// form into a path produced /data/local/tmp//data/local/tmp/target_analysis,
// so only the last component names the run.
static SecureRunDirectory open_run_out_dir(const std::string &pkg,
                                           const char *suffix) {
  std::string leaf = pkg;
  while (!leaf.empty() && leaf.back() == '/')
    leaf.pop_back();
  const size_t slash = leaf.rfind('/');
  if (slash != std::string::npos)
    leaf = leaf.substr(slash + 1);
  if (leaf.size() > 140)
    leaf.resize(140);
  return SecureRunDirectory::create(g_output_root, leaf + suffix);
}

std::vector<std::string> split_string(const std::string &s, char delimiter) {
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream tokenStream(s);
  while (std::getline(tokenStream, token, delimiter)) {
    if (!token.empty())
      tokens.push_back(token);
  }
  return tokens;
}

static bool parse_uint64_argument(const char *text, uint64_t *value) {
  if (!text || !*text || !value || *text == '-')
    return false;
  errno = 0;
  char *end = nullptr;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (errno == ERANGE || !end || *end != '\0')
    return false;
  *value = static_cast<uint64_t>(parsed);
  return true;
}

static bool parse_mib_argument(const char *text, uint64_t *bytes) {
  uint64_t mib = 0;
  if (!parse_uint64_argument(text, &mib) ||
      mib > std::numeric_limits<uint64_t>::max() / (1024ull * 1024))
    return false;
  *bytes = mib * 1024ull * 1024;
  return true;
}

RelinkConfig make_default_relink_config() {
  RelinkConfig cfg{};
  cfg.max_depth = 8;
  cfg.max_total_size = 512 * 1024 * 1024;
  cfg.fix_relocations = true;
  cfg.inline_plt_calls = true;
  return cfg;
}

enum class CandidateKind {
  Unknown,
  Elf,
  Dex,
  Odex,
  Vdex,
  Zip,
  Cdex,
};

static const char *candidate_kind_name(CandidateKind kind) {
  switch (kind) {
  case CandidateKind::Elf:
    return "ELF";
  case CandidateKind::Dex:
    return "DEX";
  case CandidateKind::Odex:
    return "ODEX";
  case CandidateKind::Vdex:
    return "VDEX";
  case CandidateKind::Zip:
    return "ZIP/APK/JAR";
  case CandidateKind::Cdex:
    return "CDEX";
  default:
    return "unknown";
  }
}

static bool is_dalvik_kind(CandidateKind kind) {
  return kind == CandidateKind::Dex || kind == CandidateKind::Odex ||
         kind == CandidateKind::Vdex || kind == CandidateKind::Zip ||
         kind == CandidateKind::Cdex;
}

// Android's Java payload lives in these containers. Only a verified standard
// DEX is sent to Rizin; ODEX/VDEX/ZIP are extraction containers and CDEX is
// retained raw with an explicit unsupported report.
bool is_dalvik_container_name(const std::string &name) {
  static const char *kExts[] = {".dex",  ".odex", ".vdex",
                                ".apk",  ".jar",  ".zip",
                                ".cdex"};
  for (const char *ext : kExts) {
    size_t pos = name.rfind(ext);
    if (pos != std::string::npos && pos + strlen(ext) == name.size())
      return true;
  }
  return false;
}

bool is_shared_object_name(const std::string &name) {
  if (name.empty())
    return false;
  size_t pos = name.rfind(".so");
  if (pos == std::string::npos)
    return false;
  if (pos + 3 == name.size())
    return true;
  return (pos + 3 < name.size() && name[pos + 3] == '.');
}

bool is_garbage(const std::vector<uint8_t> &data) {
  if (data.size() < 64)
    return true;
  size_t zeros = 0;
  for (size_t i = 0; i < std::min(data.size(), (size_t)4096); i++)
    if (data[i] == 0)
      zeros++;
  return zeros > 3900;
}

bool read_exact(int fd, void *buf, size_t size, uint64_t offset) {
  uint8_t *p = static_cast<uint8_t *>(buf);
  size_t done = 0;
  while (done < size) {
    ssize_t rd = pread(fd, p + done, size - done, offset + done);
    if (rd <= 0)
      return false;
    done += static_cast<size_t>(rd);
  }
  return true;
}

static constexpr uint32_t kDexHeaderSize = 112;
static constexpr uint32_t kCdexHeaderSize = 136;
static constexpr uint64_t kMaxDexSize = 256ull * 1024 * 1024;
static constexpr uint64_t kMaxDalvikContainerSize = 512ull * 1024 * 1024;

static bool versioned_magic(const uint8_t *data, size_t size,
                            const char prefix[4]) {
  return size >= 8 && memcmp(data, prefix, 4) == 0 &&
         data[4] >= '0' && data[4] <= '9' && data[5] >= '0' &&
         data[5] <= '9' && data[6] >= '0' && data[6] <= '9' &&
         data[7] == 0;
}

static CandidateKind detect_candidate_kind(const uint8_t *data, size_t size) {
  if (size >= SELFMAG && memcmp(data, ELFMAG, SELFMAG) == 0)
    return CandidateKind::Elf;
  if (versioned_magic(data, size, "dex\n"))
    return CandidateKind::Dex;
  if (versioned_magic(data, size, "dey\n"))
    return CandidateKind::Odex;
  if (size >= 8 && memcmp(data, "vdex", 4) == 0)
    return CandidateKind::Vdex;
  if (versioned_magic(data, size, "cdex"))
    return CandidateKind::Cdex;
  if (size >= 4 &&
      ((data[0] == 'P' && data[1] == 'K' && data[2] == 3 &&
        data[3] == 4) ||
       (data[0] == 'P' && data[1] == 'K' && data[2] == 5 &&
        data[3] == 6)))
    return CandidateKind::Zip;
  return CandidateKind::Unknown;
}

struct DexValidation {
  bool valid = false;
  uint32_t file_size = 0;
  std::string reason;
};

static DexValidation validate_standard_dex(const uint8_t *data,
                                           size_t available) {
  DexValidation result;
  auto fail = [&](const char *reason) {
    result.reason = reason;
    return result;
  };
  if (!data || available < kDexHeaderSize)
    return fail("truncated DEX header");
  if (!versioned_magic(data, available, "dex\n"))
    return fail("invalid standard DEX magic/version");

  const uint32_t file_size = read_le32(data + 32);
  const uint32_t header_size = read_le32(data + 36);
  const uint32_t endian = read_le32(data + 40);
  if (file_size < kDexHeaderSize || file_size > kMaxDexSize)
    return fail("DEX file_size is outside the safe range");
  if (file_size > available)
    return fail("DEX file_size exceeds captured bytes");
  if (header_size != kDexHeaderSize)
    return fail("DEX header_size is not 112 bytes");
  // Rizin's DEX parser consumes little-endian tables. A reverse-endian DEX must
  // be byte-swapped by a format-aware converter first, not misparsed here.
  if (endian != 0x12345678)
    return fail("unsupported DEX endian tag");

  auto table_ok = [&](uint32_t count, uint32_t offset, uint32_t stride) {
    if (count == 0)
      return offset == 0;
    if (offset < kDexHeaderSize || (offset & 3) != 0 ||
        offset > file_size)
      return false;
    return uint64_t(count) * stride <= uint64_t(file_size) - offset;
  };
  if (!table_ok(read_le32(data + 56), read_le32(data + 60), 4))
    return fail("invalid DEX string_ids range");
  const uint32_t type_count = read_le32(data + 64);
  const uint32_t proto_count = read_le32(data + 72);
  const uint32_t field_count = read_le32(data + 80);
  const uint32_t method_count = read_le32(data + 88);
  if (type_count > 65535 || proto_count > 65535 || field_count > 65535 ||
      method_count > 65535)
    return fail("DEX id count exceeds format limits");
  if (!table_ok(type_count, read_le32(data + 68), 4) ||
      !table_ok(proto_count, read_le32(data + 76), 12) ||
      !table_ok(field_count, read_le32(data + 84), 8) ||
      !table_ok(method_count, read_le32(data + 92), 8) ||
      !table_ok(read_le32(data + 96), read_le32(data + 100), 32))
    return fail("invalid DEX id/class table range");

  auto byte_range_ok = [&](uint32_t length, uint32_t offset) {
    if (length == 0)
      return offset == 0;
    return offset >= kDexHeaderSize && offset <= file_size &&
           uint64_t(length) <= uint64_t(file_size) - offset;
  };
  if (!byte_range_ok(read_le32(data + 44), read_le32(data + 48)))
    return fail("invalid DEX link range");
  if (!byte_range_ok(read_le32(data + 104), read_le32(data + 108)))
    return fail("invalid DEX data range");

  const uint32_t map_off = read_le32(data + 52);
  if (map_off != 0) {
    if ((map_off & 3) != 0 || map_off < kDexHeaderSize ||
        map_off > file_size - sizeof(uint32_t))
      return fail("invalid DEX map offset");
    const uint32_t map_count = read_le32(data + map_off);
    if (map_count > 65536 ||
        uint64_t(map_count) * 12 >
            uint64_t(file_size) - map_off - sizeof(uint32_t))
      return fail("invalid DEX map_list range");
  }

  result.valid = true;
  result.file_size = file_size;
  return result;
}

static bool parse_odex_header(const uint8_t *data, size_t available,
                              uint32_t *dex_offset, uint32_t *dex_length,
                              uint64_t *container_size,
                              std::string *reason = nullptr) {
  auto fail = [&](const char *why) {
    if (reason)
      *reason = why;
    return false;
  };
  if (!data || available < 40 || !versioned_magic(data, available, "dey\n"))
    return fail("invalid or truncated ODEX header");

  const uint32_t dex_off = read_le32(data + 8);
  const uint32_t dex_len = read_le32(data + 12);
  const uint32_t deps_off = read_le32(data + 16);
  const uint32_t deps_len = read_le32(data + 20);
  const uint32_t opt_off = read_le32(data + 24);
  const uint32_t opt_len = read_le32(data + 28);
  uint64_t end = 40;
  auto add_range = [&](uint32_t off, uint32_t len, bool required) {
    if (len == 0)
      return !required;
    if (off < 40 || uint64_t(off) + len > kMaxDalvikContainerSize)
      return false;
    end = std::max<uint64_t>(end, uint64_t(off) + len);
    return true;
  };
  if (!add_range(dex_off, dex_len, true) ||
      !add_range(deps_off, deps_len, false) ||
      !add_range(opt_off, opt_len, false))
    return fail("invalid ODEX section range");
  if (dex_len < kDexHeaderSize)
    return fail("ODEX dexLength is too small");
  *dex_offset = dex_off;
  *dex_length = dex_len;
  *container_size = end;
  return true;
}

static bool parse_cdex_header(const uint8_t *data, size_t available,
                              uint32_t *file_size,
                              std::string *reason = nullptr) {
  auto fail = [&](const char *why) {
    if (reason)
      *reason = why;
    return false;
  };
  if (!data || available < kCdexHeaderSize ||
      !versioned_magic(data, available, "cdex"))
    return fail("invalid or truncated CDEX header");
  const uint32_t size = read_le32(data + 32);
  if (size < kCdexHeaderSize || size > kMaxDexSize)
    return fail("CDEX file_size is outside the safe range");
  if (read_le32(data + 36) != kCdexHeaderSize)
    return fail("CDEX header_size is not 136 bytes");
  if (read_le32(data + 40) != 0x12345678)
    return fail("unsupported CDEX endian tag");
  *file_size = size;
  return true;
}

static bool read_flat_image(int mem_fd, uint64_t base, uint64_t size,
                            uint64_t maximum, std::vector<uint8_t> &out) {
  if (size == 0 || size > maximum ||
      size > std::numeric_limits<size_t>::max())
    return false;
  out.assign(static_cast<size_t>(size), 0);
  for (uint64_t off = 0; off < size; off += 4096) {
    size_t len = static_cast<size_t>(std::min<uint64_t>(4096, size - off));
    if (!read_exact(mem_fd, out.data() + static_cast<size_t>(off), len,
                    base + off)) {
      out.clear();
      return false;
    }
  }
  return true;
}

// Program headers read from another process need the same validation as a
// captured byte vector, but the table itself is fetched separately from
// /proc/<pid>/mem. Keep the arithmetic subtraction-based before issuing that
// read so a forged e_phoff cannot wrap the remote address.
static bool read_remote_elf64_program_headers(
    int mem_fd, uint64_t base, uint64_t maximum,
    Elf64ProgramHeaders *out, uint64_t *load_bias_out = nullptr,
    uint64_t *mapped_span_out = nullptr) {
  if (!out)
    return false;
  *out = {};
  Elf64_Ehdr ehdr{};
  if (!read_exact(mem_fd, &ehdr, sizeof(ehdr), base) ||
      memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
      ehdr.e_ident[EI_DATA] != ELFDATA2LSB ||
      ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
      ehdr.e_version != EV_CURRENT || ehdr.e_machine != EM_AARCH64 ||
      ehdr.e_ehsize != sizeof(Elf64_Ehdr) ||
      ehdr.e_phentsize != sizeof(Elf64_Phdr) || ehdr.e_phnum == 0 ||
      ehdr.e_phnum > 4096 || ehdr.e_phoff == 0 ||
      ehdr.e_phoff > maximum ||
      ehdr.e_phnum >
          (maximum - ehdr.e_phoff) / sizeof(Elf64_Phdr) ||
      base > std::numeric_limits<uint64_t>::max() - ehdr.e_phoff)
    return false;

  Elf64ProgramHeaders parsed;
  parsed.header = ehdr;
  try {
    parsed.entries.resize(ehdr.e_phnum);
  } catch (...) {
    return false;
  }
  const size_t bytes = parsed.entries.size() * sizeof(Elf64_Phdr);
  if (!read_exact(mem_fd, parsed.entries.data(), bytes,
                  base + ehdr.e_phoff))
    return false;
  const uint64_t ph_table_end = ehdr.e_phoff + bytes;
  bool have_header_load = false;
  uint64_t header_vaddr = 0;
  uint64_t mapped_span = 0;
  for (const auto &ph : parsed.entries) {
    if (ph.p_type != PT_LOAD)
      continue;
    if (ph.p_filesz > ph.p_memsz || ph.p_offset > maximum ||
        ph.p_filesz > maximum - ph.p_offset ||
        ph.p_vaddr > std::numeric_limits<uint64_t>::max() - ph.p_memsz)
      return false;
    const uint64_t end = ph.p_vaddr + ph.p_memsz;
    if (end > maximum)
      return false;
    mapped_span = std::max(mapped_span, end);
    if (ph.p_offset == 0 && ph.p_filesz >= ph_table_end) {
      if (have_header_load && header_vaddr != ph.p_vaddr)
        return false;
      have_header_load = true;
      header_vaddr = ph.p_vaddr;
    }
  }
  if (!have_header_load || mapped_span == 0 || base < header_vaddr)
    return false;
  const uint64_t load_bias = base - header_vaddr;
  for (const auto &ph : parsed.entries) {
    if (ph.p_type != PT_LOAD)
      continue;
    if (load_bias > std::numeric_limits<uint64_t>::max() - ph.p_vaddr)
      return false;
    const uint64_t start = load_bias + ph.p_vaddr;
    if (start > std::numeric_limits<uint64_t>::max() - ph.p_memsz)
      return false;
  }
  *out = std::move(parsed);
  if (load_bias_out)
    *load_bias_out = load_bias;
  if (mapped_span_out)
    *mapped_span_out = mapped_span;
  return true;
}

// Android commonly maps uncompressed native libraries directly from a
// page-aligned ZIP entry in base.apk. /proc/<pid>/maps then exposes only the
// APK pathname and a non-zero file offset, not the entry name. Recover the
// loaded object's DT_SONAME from its in-memory dynamic table so --only and
// output naming can still address the actual library.
static bool read_remote_elf_soname(int mem_fd, uint64_t header_address,
                                   uint64_t maximum,
                                   std::string *soname) {
  constexpr size_t kMaxDynamicBytes = 1024 * 1024;
  constexpr size_t kMaxSonameBytes = 512;
  if (!soname)
    return false;
  if (maximum == 0)
    maximum = std::numeric_limits<uint64_t>::max();
  soname->clear();

  Elf64ProgramHeaders headers;
  uint64_t load_bias = 0;
  if (!read_remote_elf64_program_headers(mem_fd, header_address,
                                         maximum, &headers,
                                         &load_bias))
    return false;

  const Elf64_Phdr *dynamic = nullptr;
  for (const auto &ph : headers.entries) {
    if (ph.p_type != PT_DYNAMIC || ph.p_memsz == 0)
      continue;
    if (dynamic)
      return false;
    dynamic = &ph;
  }
  if (!dynamic || dynamic->p_memsz > kMaxDynamicBytes ||
      dynamic->p_memsz < sizeof(Elf64_Dyn) ||
      load_bias > std::numeric_limits<uint64_t>::max() - dynamic->p_vaddr)
    return false;

  const size_t count =
      static_cast<size_t>(dynamic->p_memsz / sizeof(Elf64_Dyn));
  std::vector<Elf64_Dyn> entries(count);
  if (!read_exact(mem_fd, entries.data(), entries.size() * sizeof(Elf64_Dyn),
                  load_bias + dynamic->p_vaddr))
    return false;

  uint64_t strtab = 0, strsz = 0, soname_offset = 0;
  bool terminated = false;
  for (const auto &entry : entries) {
    if (entry.d_tag == DT_NULL) {
      terminated = true;
      break;
    }
    if (entry.d_tag == DT_STRTAB)
      strtab = entry.d_un.d_ptr;
    else if (entry.d_tag == DT_STRSZ)
      strsz = entry.d_un.d_val;
    else if (entry.d_tag == DT_SONAME)
      soname_offset = entry.d_un.d_val;
  }
  if (!terminated || strtab == 0 || strsz == 0 || soname_offset >= strsz ||
      strsz > 16 * 1024 * 1024)
    return false;

  uint64_t strtab_address = 0;
  for (const auto &ph : headers.entries) {
    if (ph.p_type != PT_LOAD || ph.p_memsz == 0)
      continue;
    if (strtab >= ph.p_vaddr && strtab - ph.p_vaddr < ph.p_memsz) {
      if (load_bias > std::numeric_limits<uint64_t>::max() - strtab)
        return false;
      strtab_address = load_bias + strtab;
      break;
    }
    if (load_bias <= std::numeric_limits<uint64_t>::max() - ph.p_vaddr) {
      const uint64_t runtime_start = load_bias + ph.p_vaddr;
      if (strtab >= runtime_start && strtab - runtime_start < ph.p_memsz) {
        strtab_address = strtab;
        break;
      }
    }
  }
  if (strtab_address == 0 ||
      strtab_address > std::numeric_limits<uint64_t>::max() - soname_offset)
    return false;

  const size_t available = static_cast<size_t>(
      std::min<uint64_t>(strsz - soname_offset, kMaxSonameBytes));
  std::vector<char> text(available);
  if (!read_exact(mem_fd, text.data(), text.size(),
                  strtab_address + soname_offset))
    return false;
  const auto nul = std::find(text.begin(), text.end(), '\0');
  if (nul == text.end() || nul == text.begin())
    return false;
  soname->assign(text.begin(), nul);
  if (soname->find('/') != std::string::npos ||
      !is_shared_object_name(*soname)) {
    soname->clear();
    return false;
  }
  return true;
}

static bool read_elf_image_impl(int mem_fd, uint64_t base,
                                std::vector<uint8_t> &out,
                                uint64_t &image_size, uint64_t maximum) {
  if (maximum == 0)
    maximum = std::numeric_limits<uint64_t>::max();
  Elf64ProgramHeaders program_headers;
  uint64_t load_bias = 0;
  if (!read_remote_elf64_program_headers(mem_fd, base, maximum,
                                         &program_headers, &load_bias))
    return false;

  image_size = 0;
  for (const auto &ph : program_headers.entries) {
    if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
      continue;
    if (ph.p_offset > maximum || ph.p_filesz > maximum - ph.p_offset)
      return false;
    uint64_t end = static_cast<uint64_t>(ph.p_offset) + ph.p_filesz;
    if (end > image_size)
      image_size = end;
  }
  if (image_size == 0 || image_size > maximum ||
      image_size > std::numeric_limits<size_t>::max())
    return false;

  out.assign(static_cast<size_t>(image_size), 0);

  for (const auto &ph : program_headers.entries) {
    if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
      continue;
    if (load_bias > std::numeric_limits<uint64_t>::max() - ph.p_vaddr)
      return false;
    uint64_t src = load_bias + ph.p_vaddr;
    uint64_t dst_off = ph.p_offset;
    uint64_t seg_size = ph.p_filesz;
    if (dst_off >= out.size())
      continue;
    if (dst_off + seg_size > out.size())
      seg_size = out.size() - dst_off;
    uint8_t *dest = out.data() + static_cast<size_t>(dst_off);
    for (uint64_t page_off = 0; page_off < seg_size; page_off += 4096) {
      size_t len = std::min<uint64_t>(4096, seg_size - page_off);
      ssize_t rd = pread(mem_fd, dest + page_off, len, src + page_off);
      if (rd != static_cast<ssize_t>(len)) {
        out.clear();
        image_size = 0;
        return false;
      }
    }
  }
  return true;
}

// A DEX is a flat file with no program headers: what is mapped is exactly what
// was on disk, and its length is in the header. There is nothing to reconstruct
// -- the only thing that can go wrong is trusting the declared size, so it is
// bounded before use.
bool read_dex_image(int mem_fd, uint64_t base, std::vector<uint8_t> &out,
                    uint64_t &image_size) {
  uint8_t header[kDexHeaderSize] = {0};
  if (!read_exact(mem_fd, header, sizeof(header), base))
    return false;
  if (!versioned_magic(header, sizeof(header), "dex\n"))
    return false;

  uint32_t file_size = read_le32(header + 32);
  if (!read_flat_image(mem_fd, base, file_size, kMaxDexSize, out))
    return false;
  DexValidation validation = validate_standard_dex(out.data(), out.size());
  if (!validation.valid || validation.file_size != out.size()) {
    out.clear();
    image_size = 0;
    return false;
  }
  image_size = file_size;
  return true;
}

bool read_elf_image(int mem_fd, uint64_t base, std::vector<uint8_t> &out,
                    uint64_t &image_size, uint64_t maximum) {
  unsigned char ident[EI_NIDENT] = {0};
  if (!read_exact(mem_fd, ident, EI_NIDENT, base))
    return false;
  if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F')
    return false;

  // AArch64 only: a 32-bit image is not something we can analyse, so refuse it
  // here rather than producing a half-parsed dump downstream.
  if (ident[EI_CLASS] != ELFCLASS64)
    return false;

  image_size = 0;
  return read_elf_image_impl(mem_fd, base, out, image_size, maximum);
}

std::vector<int> find_pids_by_prefix_all(const std::string &pkg) {
  std::vector<int> pids;
  DIR *dir = opendir("/proc");
  if (!dir)
    return pids;
  struct dirent *ent;
  while ((ent = readdir(dir))) {
    int pid = atoi(ent->d_name);
    if (pid <= 0)
      continue;
    std::ifstream f("/proc/" + std::string(ent->d_name) + "/cmdline");
    std::string cmd;
    std::getline(f, cmd);
    size_t null_pos = cmd.find('\0');
    if (null_pos != std::string::npos)
      cmd = cmd.substr(0, null_pos);
    if (!cmd.empty() && cmd.rfind(pkg, 0) == 0) {
      pids.push_back(pid);
    }
  }
  closedir(dir);
  std::sort(pids.begin(), pids.end());
  return pids;
}

bool split_class_member(const std::string &demangled, std::string &cls,
                        std::string &member, bool &is_method) {
  size_t paren = demangled.find('(');
  is_method = (paren != std::string::npos);
  std::string left = is_method ? demangled.substr(0, paren) : demangled;
  size_t pos = left.rfind("::");
  if (pos == std::string::npos)
    return false;
  cls = left.substr(0, pos);
  member = left.substr(pos + 2);
  if (cls.empty() || member.empty())
    return false;
  return true;
}

bool read_file_prefix(const std::string &path, size_t max_size,
                      std::vector<uint8_t> &out) {
  std::ifstream f(path, std::ios::binary);
  if (!f)
    return false;
  f.seekg(0, std::ios::end);
  std::streampos end = f.tellg();
  if (end <= 0)
    return false;
  size_t size = static_cast<size_t>(end);
  size_t to_read = std::min(size, max_size);
  out.resize(to_read);
  f.seekg(0, std::ios::beg);
  f.read(reinterpret_cast<char *>(out.data()), to_read);
  size_t got = static_cast<size_t>(f.gcount());
  out.resize(got);
  return !out.empty();
}

uint64_t hash_data(const std::vector<uint8_t> &data) {
  uint64_t h = 1469598103934665603ULL;
  for (uint8_t b : data) {
    h ^= b;
    h *= 1099511628211ULL;
  }
  return h;
}

std::string hex_bytes(const uint8_t *data, size_t len) {
  static const char *hex = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out.push_back(hex[(data[i] >> 4) & 0xF]);
    out.push_back(hex[data[i] & 0xF]);
  }
  return out;
}


// Report tuning. Defaults are deliberately conservative: the cipher-hunting
// heuristics produce thousands of speculative hits on ordinary code, so they
// are off unless asked for, and every list section is capped.

// Thin wrapper so the report can translate file offsets to virtual addresses
// without duplicating the PT_LOAD walk.
struct AddrMapView {
  struct Seg { uint64_t vaddr, off, filesz; };
  std::vector<Seg> segs;
  explicit AddrMapView(const std::vector<uint8_t> &data) {
    Elf64ProgramHeaders program_headers;
    if (!parse_elf64_program_headers(data, &program_headers))
      return;
    for (const auto &ph : program_headers.entries)
      if (ph.p_type == PT_LOAD)
        segs.push_back({ph.p_vaddr, ph.p_offset, ph.p_filesz});
  }
  bool to_vaddr(uint64_t off, uint64_t *out) const {
    if (!out)
      return false;
    for (const auto &s : segs)
      if (off >= s.off && off - s.off < s.filesz) {
        *out = s.vaddr + (off - s.off);
        return true;
      }
    return false;
  }
  // The other direction, for the places that hold a symbol's st_value and need
  // to index the image bytes with it. On a library built for 16 KB pages the
  // two differ by a whole segment: p_vaddr 0x4000 against p_offset 0x1000.
  bool to_offset(uint64_t vaddr, uint64_t *out) const {
    if (!out)
      return false;
    for (const auto &s : segs)
      if (vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz) {
        *out = s.off + (vaddr - s.vaddr);
        return true;
      }
    return false;
  }
};

struct AnalysisOptions {
  bool deep = true;       // entropy / AES / vtable-instance scans
  bool trace_init = false; // breakpoint init_array (invasive, can kill target)
  bool deobf = false;      // XOR/RC4/base64 string hunting (noisy)
  size_t min_str = 6;      // minimum printable run to report as a string
  size_t limit = 2000;     // max entries emitted per report section
  size_t listing = 0;      // annotated listings to emit (0 = off)
  size_t string_bytes = 128U * 1024U * 1024U;
  size_t deobf_input_bytes = 128U * 1024U * 1024U;
  size_t deobf_probes = 8U * 1024U * 1024U;
  size_t deobf_candidates = 65536;
  uint64_t deobf_timeout_ms = 30000;
  uint32_t rizin_timeout_seconds = 60;
};

struct CaptureLimits {
  // Zero means no policy limit; allocation/address-space validity still
  // applies.  Defaults are deliberately large enough for real games while
  // preventing an accidental all-process dump from exhausting the device.
  uint64_t memory_bytes = 1024ull * 1024 * 1024;
  uint64_t image_bytes = 2048ull * 1024 * 1024;
};

static std::string normalized_mapping_name(std::string name) {
  size_t deleted = name.find(" (deleted)");
  if (deleted != std::string::npos)
    name.resize(deleted);
  return name;
}

static std::vector<std::pair<std::string, uint64_t>>
dump_got_from_snapshot(const std::vector<uint8_t> &elf_data) {
  std::vector<std::pair<std::string, uint64_t>> result;
  AddrMapView map(elf_data);
  for (const auto &entry : ElfParser::get_plt_entries(elf_data)) {
    uint64_t off = 0;
    if (!map.to_offset(entry.got_offset, &off) ||
        off > elf_data.size() || elf_data.size() - off < sizeof(uint64_t))
      continue;
    result.push_back({entry.symbol_name, read_le64(elf_data.data() + off)});
  }
  return result;
}

struct SnapshotDifference {
  size_t file_offset = 0;
  uint64_t runtime_address = 0;
  size_t size = 0;
};

static std::vector<SnapshotDifference>
find_snapshot_differences(const std::vector<uint8_t> &runtime_data,
                          const std::vector<uint8_t> &disk_data,
                          uint64_t base, size_t max_results = 100000) {
  std::vector<SnapshotDifference> result;
  AddrMapView map(runtime_data);
  const size_t n = std::min(runtime_data.size(), disk_data.size());
  if (n == 0 || map.segs.empty())
    return result;

  struct FileLoadRange {
    size_t begin;
    size_t end;
    uint64_t vaddr;
  };
  std::vector<FileLoadRange> ranges;
  for (const auto &segment : map.segs) {
    if (segment.filesz == 0 || segment.off >= n)
      continue;
    uint64_t available = uint64_t(n) - segment.off;
    uint64_t length = std::min(segment.filesz, available);
    if (length == 0 ||
        length > std::numeric_limits<size_t>::max() -
                     static_cast<size_t>(segment.off))
      continue;
    ranges.push_back({static_cast<size_t>(segment.off),
                      static_cast<size_t>(segment.off + length),
                      segment.vaddr});
  }
  std::sort(ranges.begin(), ranges.end(),
            [](const FileLoadRange &a, const FileLoadRange &b) {
              if (a.begin != b.begin)
                return a.begin < b.begin;
              return a.end < b.end;
            });

  // Compare every byte in PT_LOAD's file-backed p_filesz ranges. Overlapping
  // ranges are visited once, and zero bytes are ordinary bytes: a disk 0x00
  // becoming non-zero at runtime is a real difference.
  size_t covered_until = 0;
  for (const auto &range : ranges) {
    if (result.size() >= max_results)
      break;
    size_t begin = std::max(range.begin, covered_until);
    if (begin >= range.end)
      continue;
    bool in_diff = false;
    size_t start = begin;
    auto emit = [&](size_t end) {
      if (!in_diff || end <= start || result.size() >= max_results)
        return;
      uint64_t vaddr = range.vaddr + (start - range.begin);
      if (vaddr < range.vaddr ||
          (base && vaddr > std::numeric_limits<uint64_t>::max() - base))
        return;
      result.push_back(
          {start, base ? base + vaddr : vaddr, end - start});
    };
    for (size_t i = begin; i < range.end; i++) {
      bool differs = runtime_data[i] != disk_data[i];
      if (differs && !in_diff) {
        start = i;
        in_diff = true;
      } else if (!differs && in_diff) {
        emit(i);
        in_diff = false;
        if (result.size() >= max_results)
          break;
      }
    }
    if (in_diff)
      emit(range.end);
    covered_until = std::max(covered_until, range.end);
  }
  return result;
}

static std::vector<uint64_t> find_instances_in_snapshot(
    const RuntimeMemorySnapshot &snapshot, uint64_t vtable_addr,
    size_t max_results, bool *truncated = nullptr) {
  if (truncated)
    *truncated = false;
  std::vector<uint64_t> result;
  std::set<uint64_t> unique;
  const uint64_t vptr_slot = vtable_addr + 2 * sizeof(uint64_t);
  const uint64_t untagged_vtable = vtable_addr & 0x00FFFFFFFFFFFFFFULL;
  const uint64_t untagged_slot = vptr_slot & 0x00FFFFFFFFFFFFFFULL;
  for (const auto &region : snapshot.anonymous) {
    const MapEntry &m = region.mapping;
    bool heap_like = m.name.find("[heap]") != std::string::npos ||
                     m.name.find("[anon:") != std::string::npos ||
                     (m.name.empty() && m.writable());
    if (!heap_like)
      continue;
    for (size_t off = 0; off + sizeof(uint64_t) <= region.data.size();
         off += sizeof(uint64_t)) {
      uint64_t ptr = read_le64(region.data.data() + off);
      ptr &= 0x00FFFFFFFFFFFFFFULL;
      if (ptr == untagged_slot || ptr == untagged_vtable) {
        unique.insert(m.start + off);
        if (unique.size() >= max_results) {
          if (truncated)
            *truncated = true;
          result.assign(unique.begin(), unique.end());
          return result;
        }
      }
    }
  }
  result.assign(unique.begin(), unique.end());
  return result;
}


// Decompiled C for the most interesting functions in a module.
//
// This used to be an "annotated listing": a hand-written AArch64 decoder that
// resolved branch targets and ADRP/ADD string loads but had no IR, no dataflow
// and no control-flow structuring, so it could not produce C. That whole path
// is gone. rizin recovers the functions and the Ghidra decompiler -- both
// linked into this binary -- turn them into source.
static void write_function_listing(std::ostream &f,
                                   const std::vector<uint8_t> &data,
                                   uint64_t base, size_t limit) {
  // Same session the rest of the report used: a second RzCore over the same
  // module costs another full analysis pass and can fail to load at all.
  rzb::Image *img = rzb::shared_image(data, base);
  if (!img) {
    f << "\n=== DECOMPILED ===\nrizin could not load this image.\n";
    return;
  }

  // Prefer functions that carry a recovered name: in a stripped module the
  // named ones are the entry points a reader is looking for, and decompiling
  // every `fcn.*` would bury them.
  std::vector<uint64_t> named, anonymous;
  for (uint64_t addr : img->functions()) {
    const std::string name = img->name_at(addr);
    if (!name.empty() && name.rfind("fcn.", 0) != 0 && name.rfind("loc.", 0) != 0)
      named.push_back(addr);
    else
      anonymous.push_back(addr);
  }
  std::vector<uint64_t> targets = named;
  for (uint64_t a : anonymous) {
    if (targets.size() >= limit)
      break;
    targets.push_back(a);
  }
  if (targets.size() > limit)
    targets.resize(limit);

  if (targets.empty()) {
    f << "\n=== DECOMPILED ===\nNo functions recovered.\n";
    return;
  }

  f << "\n=== DECOMPILED (" << targets.size() << " functions) ===\n"
    << "Ghidra decompiler output via rizin.\n";

  size_t failed = 0;
  for (uint64_t addr : targets) {
    const std::string name = img->name_at(addr);
    f << "\n// 0x" << std::hex << addr << std::dec;
    if (!name.empty())
      f << "  " << name;
    f << "\n";

    const std::string c = img->decompile(addr);
    if (c.empty()) {
      failed++;
      f << "// not decompiled: " << img->decompiler_error() << "\n";
      continue;
    }
    f << c;
    if (c.back() != '\n')
      f << "\n";
  }
  if (failed)
    f << "\n// " << failed << " of " << targets.size()
      << " functions could not be decompiled.\n";
}

static bool decompiler_failure_text(const std::string &text) {
  if (text.empty())
    return true;
  static const char *kFailures[] = {
      "Ghidra Decompiler Error:", "Decompiler Error:",
      "No function at this offset", "No function in Scope",
      "No sleigh specification", "Unknown print language",
      "decompiler produced no output", "Cannot find function"};
  for (const char *failure : kFailures)
    if (text.find(failure) != std::string::npos)
      return true;
  size_t first = text.find_first_not_of(" \t\r\n");
  return first != std::string::npos &&
         (text.compare(first, 6, "ERROR:") == 0 ||
          text.compare(first, 7, "[ERROR]") == 0);
}

static std::string decompiler_failure_summary(const std::string &text,
                                              const std::string &fallback) {
  if (!fallback.empty())
    return fallback;
  size_t begin = text.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos)
    return "decompiler produced no output";
  size_t end = text.find_first_of("\r\n", begin);
  std::string line = text.substr(begin, end == std::string::npos
                                           ? std::string::npos
                                           : end - begin);
  if (line.size() > 240)
    line.resize(240);
  return line;
}

// Report for a standard Dalvik DEX.
//
// A DEX carries its own class, method, field and string tables, so none of the
// ELF machinery applies and none of it is needed: what the C++ side spends
// RTTI scans and demangling to guess at is written down in the format. rizin's
// dex plugin parses it; everything below is that parse, laid out.
bool analyze_dex_to_txt(const std::vector<uint8_t> &data,
                        const std::string &path, uint64_t base,
                        const std::string &name, const AnalysisOptions &ao,
                        bool *analysis_incomplete = nullptr) {
  if (analysis_incomplete)
    *analysis_incomplete = false;
  thread_local std::string current_name;
  current_name = name;
  snprintf(g_current_module, sizeof(g_current_module), "%s",
           current_name.c_str());

  std::ofstream f(path);
  if (!f)
    return false;
  auto close_report = [&]() {
    f.close();
    return static_cast<bool>(f);
  };

  f << "=== DEX MEMORY ANALYSIS ===\n";
  f << "Module: " << name << "\n";
  f << "Base: 0x" << std::hex << base << std::dec << "\n";
  f << "Size: " << data.size() << " bytes\n";
  if (data.size() >= 40) {
    f << "Version: " << std::string(reinterpret_cast<const char *>(data.data()) + 4, 3)
      << "\n";
    f << "Checksum: 0x" << std::hex << read_le32(data.data() + 8) << std::dec
      << "\n";
  }

  g_current_step = "dex_open";
  rzb::Image *img = rzb::shared_image(data, base);
  if (!img) {
    f << "\nrizin could not load this image.\n";
    if (analysis_incomplete &&
        rzb::analysis_level() != rzb::AnalysisLevel::None)
      *analysis_incomplete = true;
    return close_report();
  }

  g_current_step = "dex_classes";
  auto classes = img->bin_classes();
  size_t method_total = 0, field_total = 0;
  for (const auto &c : classes) {
    method_total += c.methods.size();
    field_total += c.fields.size();
  }

  f << "\n=== DEX CLASSES (" << classes.size() << " classes, " << method_total
    << " methods, " << field_total << " fields) ===\n";
  size_t shown = 0;
  size_t member_details_shown = 0;
  bool member_details_truncated = false;
  for (const auto &c : classes) {
    if (shown++ >= ao.limit) {
      f << "... (" << (classes.size() - shown + 1) << " more)\n";
      break;
    }
    f << "class " << c.name;
    if (!c.super.empty())
      f << " extends " << c.super;
    f << "  methods=" << c.methods.size() << " fields=" << c.fields.size()
      << "\n";
    for (const auto &m : c.methods) {
      if (member_details_shown >= ao.limit) {
        member_details_truncated = true;
        break;
      }
      // A DEX is mapped flat, so the live address of a method's code is the
      // mapping base plus its file offset. rizin's vaddr for a dex symbol sits
      // in a synthetic space of its own and adding the base to that produced
      // addresses outside the mapping entirely.
      f << "  0x" << std::hex << (base ? base + m.paddr : m.paddr) << std::dec
        << "  " << m.name << "\n";
      member_details_shown++;
    }
    for (const auto &fl : c.fields) {
      if (member_details_shown >= ao.limit) {
        member_details_truncated = true;
        break;
      }
      f << "  field " << fl << "\n";
      member_details_shown++;
    }
  }
  if (member_details_truncated)
    f << "... (additional class members suppressed by --limit)\n";

  g_current_step = "dex_strings";
  auto strs = img->strings(ao.limit, ao.string_bytes);
  if (strs.empty()) {
    // rizin's string table comes back empty inside an embedded RzCore for some
    // formats; the scanner over the raw bytes is the fallback, and for a DEX it
    // reaches the same string pool.
    StringScanLimits limits;
    limits.max_results = ao.limit;
    limits.max_retained_bytes = ao.string_bytes;
    StringScanStatus status;
    auto raw = ElfParser::get_strings(data, ao.min_str, limits, &status);
    f << "\n=== DEX STRINGS (" << status.total_matches
      << ", raw scan; retained=" << raw.size() << ") ===\n";
    for (const auto &s : raw) {
      f << "0x" << std::hex << s.offset << std::dec << " " << s.value << "\n";
    }
    if (status.truncated)
      f << "... [truncated by --limit/string byte budget]\n";
  } else {
    f << "\n=== DEX STRINGS (" << strs.size() << ") ===\n";
    for (const auto &s : strs) {
      f << "0x" << std::hex << s.vaddr << std::dec << " " << s.text << "\n";
    }
    if (strs.size() == ao.limit)
      f << "... [truncated by --limit]\n";
  }

  g_current_step = "dex_imports";
  auto imports = img->imports();
  if (!imports.empty()) {
    f << "\n=== DEX EXTERNAL METHODS (" << imports.size() << ") ===\n";
    size_t n = 0;
    for (const auto &imp : imports) {
      if (n++ >= ao.limit) {
        f << "... (" << (imports.size() - n + 1) << " more)\n";
        break;
      }
      f << "0x" << std::hex << imp.stub_vaddr << std::dec << " " << imp.symbol
        << "\n";
    }
  }

  g_current_step = "dex_disasm";
  if (ao.listing) {
    // Dalvik bytecode disassembly comes from Rizin's Dalvik plugin.
    size_t emitted = 0;
    f << "\n=== DEX METHOD LISTINGS ===\n";
    for (const auto &c : classes) {
      for (const auto &m : c.methods) {
        if (emitted >= ao.listing)
          break;
        auto insns = img->disassemble(m.vaddr, 256, m.size);
        if (insns.empty())
          continue;
        emitted++;
        f << "\n// " << c.name << "." << m.name << "  @0x" << std::hex
          << (base ? base + m.paddr : m.paddr) << std::dec << "\n";
        for (const auto &in : insns) {
          if (in.text.empty())
            continue;
          f << "  " << in.text << "\n";
        }
      }
      if (emitted >= ao.listing)
        break;
    }

    // core_ghidra has the embedded Dalvik Sleigh languages even though
    // asm_ghidra is not linked. Ask it for each concrete method and reject the
    // textual error diagnostics that `pdg` sometimes returns as ordinary
    // command output.
    g_current_step = "dex_decompile";
    size_t attempted = 0, succeeded = 0;
    f << "\n=== DEX DECOMPILED METHODS ===\n";
    for (const auto &c : classes) {
      for (const auto &m : c.methods) {
        if (attempted >= ao.listing)
          break;
        if (m.paddr == 0 || m.vaddr == 0 || m.size == 0)
          continue;
        attempted++;
        f << "\n// " << c.name << "." << m.name << "  @0x" << std::hex
          << (base ? base + m.paddr : m.paddr) << std::dec << "\n";
        std::string source = img->decompile_dex_method(m.vaddr, m.size);
        if (decompiler_failure_text(source)) {
          f << "// not decompiled: "
            << decompiler_failure_summary(source, img->decompiler_error())
            << "\n";
          continue;
        }
        succeeded++;
        f << source;
        if (source.back() != '\n')
          f << "\n";
      }
      if (attempted >= ao.listing)
        break;
    }
    if (attempted == 0)
      f << "No concrete method bodies were available.\n";
    else
      f << "\n// " << succeeded << " of " << attempted
        << " methods decompiled successfully.\n";
  }

  if (img->analysis_failed()) {
    f << "\n=== ANALYSIS STATUS ===\nINCOMPLETE: Rizin did not finish the "
         "requested analysis level.\n";
    if (analysis_incomplete)
      *analysis_incomplete = true;
  } else {
    f << "\n=== ANALYSIS STATUS ===\nCOMPLETE for the requested analysis "
         "level.\n";
  }
  return close_report();
}

bool analyze_to_txt(const std::vector<uint8_t> &data, const std::string &path,
                    uint64_t base, const std::string &name,
                    const std::vector<uint8_t> *runtime_image,
                    const std::vector<uint8_t> *disk_snapshot, int pid,
                    std::mutex *runtime_mutex,
                    const RuntimeMemorySnapshot *runtime_snapshot,
                    const std::vector<size_t> *writable_snapshot_indices,
                    const AnalysisOptions &ao,
                    bool *analysis_incomplete = nullptr) {
  if (analysis_incomplete)
    *analysis_incomplete = false;
  const bool deep = ao.deep;
  const bool trace_init = ao.trace_init;
  thread_local std::string current_name;
  current_name = name;
  snprintf(g_current_module, sizeof(g_current_module), "%s",
           current_name.c_str());

  std::ofstream f(path);
  if (!f)
    return false;

  f << "=== ELF MEMORY ANALYSIS ===\n";
  f << "Module: " << name << "\n";
  f << "Base: 0x" << std::hex << base << std::dec << "\n";
  f << "Size: " << data.size() << " bytes\n";

  const AddrMapView report_addr_map(data);
  auto file_offset_runtime_address = [&](uint64_t file_offset) -> uint64_t {
    uint64_t vaddr = 0;
    if (!report_addr_map.to_vaddr(file_offset, &vaddr))
      return file_offset;
    if (base == 0)
      return vaddr;
    if (vaddr > std::numeric_limits<uint64_t>::max() - base)
      return file_offset;
    return base + vaddr;
  };

  std::vector<ElfSymbol> vtables;

  g_current_step = "symbols";
  auto symbols = ElfParser::get_symbols(data);
  const size_t symbol_count = symbols.size();
  f << "=== SYMBOLS (" << symbol_count << ") ===\n";
  size_t symbol_shown = 0;
  for (const auto &s : symbols) {
    if (s.name.rfind("_ZTV", 0) == 0)
      vtables.push_back(s);
    if (symbol_shown >= ao.limit)
      continue;
    f << "0x" << std::hex << std::setw(8) << std::setfill('0') << s.offset
      << std::dec << " " << s.type << " "
      << ElfParser::demangle_symbol(s.name) << "\n";
    symbol_shown++;
  }
  if (symbol_shown < symbol_count)
    f << "... (" << (symbol_count - symbol_shown)
      << " more suppressed by --limit)\n";

  g_current_step = "functions";
  std::vector<ElfSymbol> func_syms;
  std::vector<ElfSymbol> obj_syms;
  func_syms.reserve(symbols.size());
  obj_syms.reserve(symbols.size());
  for (const auto &s : symbols) {
    if (s.type == "FUNC")
      func_syms.push_back(s);
    else if (s.type == "VAR")
      obj_syms.push_back(s);
  }

  if (!func_syms.empty()) {
    f << "\n=== FUNCTIONS (" << func_syms.size() << ") ===\n";
    const size_t shown = std::min(func_syms.size(), ao.limit);
    for (size_t i = 0; i < shown; i++) {
      const auto &s = func_syms[i];
      uint64_t addr = base ? base + s.offset : s.offset;
      f << "0x" << std::hex << addr << std::dec << " "
        << ElfParser::demangle_symbol(s.name);
      if (s.size)
        f << " (" << s.size << ")";
      f << "\n";
    }
    if (shown < func_syms.size())
      f << "... (" << (func_syms.size() - shown)
        << " more suppressed by --limit)\n";
  }

  g_current_step = "objc";
  {
    std::vector<std::pair<std::string, std::string>> objc_methods;
    for (const auto &s : func_syms) {
      if (ElfParser::is_objc_method(s.name)) {
        auto parsed = ElfParser::parse_objc_method(s.name);
        if (!parsed.first.empty())
          objc_methods.push_back(parsed);
      }
    }
    if (!objc_methods.empty()) {
      f << "\n=== OBJC_METHODS (" << objc_methods.size() << ") ===\n";
      const size_t shown = std::min(objc_methods.size(), ao.limit);
      for (size_t i = 0; i < shown; i++)
        f << objc_methods[i].first << " -> " << objc_methods[i].second << "\n";
      if (shown < objc_methods.size())
        f << "... (" << (objc_methods.size() - shown)
          << " more suppressed by --limit)\n";
    }
  }

  if (!obj_syms.empty()) {
    f << "\n=== OBJECTS (" << obj_syms.size() << ") ===\n";
    const size_t shown = std::min(obj_syms.size(), ao.limit);
    for (size_t i = 0; i < shown; i++) {
      const auto &s = obj_syms[i];
      uint64_t addr = base ? base + s.offset : s.offset;
      f << "0x" << std::hex << addr << std::dec << " "
        << ElfParser::demangle_symbol(s.name);
      if (s.size)
        f << " (" << s.size << ")";
      f << "\n";
    }
    if (shown < obj_syms.size())
      f << "... (" << (obj_syms.size() - shown)
        << " more suppressed by --limit)\n";
  }

  std::map<std::string, std::vector<std::string>> class_methods;
  std::map<std::string, std::vector<std::string>> class_fields;
  std::set<std::string> classes;

  for (const auto &s : func_syms) {
    std::string dem = ElfParser::demangle_symbol(s.name);
    std::string cls;
    std::string member;
    bool is_method = false;
    if (split_class_member(dem, cls, member, is_method) && is_method) {
      uint64_t addr = base ? base + s.offset : s.offset;
      std::ostringstream line;
      line << "0x" << std::hex << addr << std::dec << " " << dem;
      class_methods[cls].push_back(line.str());
      classes.insert(cls);
    }
  }

  for (const auto &s : obj_syms) {
    std::string dem = ElfParser::demangle_symbol(s.name);
    std::string cls;
    std::string member;
    bool is_method = false;
    if (split_class_member(dem, cls, member, is_method) && !is_method) {
      uint64_t addr = base ? base + s.offset : s.offset;
      std::ostringstream line;
      line << "0x" << std::hex << addr << std::dec << " " << dem;
      class_fields[cls].push_back(line.str());
      classes.insert(cls);
    }
  }

  if (!classes.empty()) {
    f << "\n=== CLASSES (" << classes.size() << ") ===\n";
    size_t shown = 0;
    for (const auto &cls : classes) {
      if (shown >= ao.limit)
        break;
      shown++;
      size_t m = class_methods[cls].size();
      size_t fld = class_fields[cls].size();
      f << cls << " methods=" << m << " fields=" << fld << "\n";
    }
    if (shown < classes.size())
      f << "... (" << (classes.size() - shown)
        << " more suppressed by --limit)\n";
  }

  size_t method_total = 0;
  for (const auto &kv : class_methods)
    method_total += kv.second.size();
  if (method_total > 0) {
    f << "\n=== METHODS (" << method_total << ") ===\n";
    size_t shown = 0;
    for (const auto &kv : class_methods) {
      for (const auto &line : kv.second) {
        if (shown >= ao.limit)
          break;
        f << line << "\n";
        shown++;
      }
      if (shown >= ao.limit)
        break;
    }
    if (shown < method_total)
      f << "... (" << (method_total - shown)
        << " more suppressed by --limit)\n";
  }

  size_t field_total = 0;
  for (const auto &kv : class_fields)
    field_total += kv.second.size();
  if (field_total > 0) {
    f << "\n=== FIELDS (" << field_total << ") ===\n";
    size_t shown = 0;
    for (const auto &kv : class_fields) {
      for (const auto &line : kv.second) {
        if (shown >= ao.limit)
          break;
        f << line << "\n";
        shown++;
      }
      if (shown >= ao.limit)
        break;
    }
    if (shown < field_total)
      f << "... (" << (field_total - shown)
        << " more suppressed by --limit)\n";
  }

  // Run the selected Rizin pass once, up front, and make its completion an
  // explicit gate for every expensive analysis-backed query below.  Continuing
  // xrefs/RTTI/table/emulation work after `aaa` timed out used several more
  // minutes and over a gigabyte of RAM while only querying a partial database.
  rzb::Image *analysis_image = rzb::shared_image(data, base);
  const bool rizin_requested =
      rzb::analysis_level() != rzb::AnalysisLevel::None;
  if (analysis_image && rizin_requested)
    analysis_image->analyze();
  bool rizin_analysis_complete =
      !rizin_requested ||
      (analysis_image && !analysis_image->analysis_failed());
  bool rizin_incomplete_reported = false;
  auto report_rizin_incomplete = [&]() {
    if (rizin_incomplete_reported)
      return;
    rizin_incomplete_reported = true;
    f << "\n=== RIZIN ANALYSIS ===\n"
         "INCOMPLETE: dependent xref/RTTI/table/emulation passes were "
         "skipped after the shared analysis budget was exhausted or the "
         "primary pass failed.\n";
    if (analysis_incomplete)
      *analysis_incomplete = true;
  };
  auto rizin_work_allowed = [&]() {
    if (!rizin_requested)
      return false;
    if (!analysis_image || analysis_image->budget_exhausted() ||
        analysis_image->analysis_failed())
      rizin_analysis_complete = false;
    if (!rizin_analysis_complete)
      report_rizin_incomplete();
    return rizin_analysis_complete;
  };
  if (rizin_requested && !rizin_analysis_complete) {
    report_rizin_incomplete();
  }

  g_current_step = "rtti";
  std::sort(vtables.begin(), vtables.end(),
            [](const ElfSymbol &a, const ElfSymbol &b) {
              return a.offset < b.offset;
            });
  if (!vtables.empty() && (!rizin_requested || rizin_work_allowed()))
    ElfParser::write_rtti(f, data, base, vtables, ao.limit);

  std::vector<ElfString> report_strings;
  g_current_step = "strings";
  try {
    StringScanLimits limits;
    limits.max_results = ao.limit;
    limits.max_retained_bytes = ao.string_bytes;
    StringScanStatus status;
    report_strings =
        ElfParser::get_strings(data, ao.min_str, limits, &status);
    f << "\n=== STRINGS (" << status.total_matches << "; retained="
      << status.retained_results << ") ===\n";
    for (const auto &entry : report_strings) {
      f << "0x" << std::hex << std::setw(8) << std::setfill('0')
        << entry.offset << std::dec << " " << entry.value << "\n";
    }
    if (status.truncated)
      f << "... [truncated by --limit/string byte budget]\n";
  } catch (...) {
    f << "\n=== STRINGS (error) ===\n";
  }

  g_current_step = "xrefs";
  bool xrefs_truncated = false;
  std::map<uint64_t, std::vector<uint64_t>> xref_map;
  if (rizin_work_allowed())
    xref_map = ElfParser::build_string_xref_map(
        data, base, ao.limit, ao.limit, ao.string_bytes, &xrefs_truncated);
  if (!xref_map.empty() || xrefs_truncated) {
    f << "\n=== STRING_XREFS (" << xref_map.size() << ") ===\n";
    size_t xshown = 0;
    for (const auto &kv : xref_map) {
      if (xshown++ >= ao.limit) {
        f << "... (" << (xref_map.size() - xshown + 1) << " more suppressed)\n";
        break;
      }
      uint64_t addr = base ? base + kv.first : kv.first;
      f << "0x" << std::hex << addr << std::dec << " refs=" << kv.second.size()
        << "\n";
      for (auto ref : kv.second) {
        uint64_t raddr = base ? base + ref : ref;
        f << "  0x" << std::hex << raddr << std::dec << "\n";
      }
    }
    if (xrefs_truncated)
      f << "... [truncated by aggregate --limit xref budget]\n";
  }


  // ---- FUNCTION MAP -------------------------------------------------------
  // The point of an il2cpp-style dump is not the flat lists, it is that every
  // address carries context. Build one inventory of functions (symbols, plus
  // unwind-table entries so stripped modules still get boundaries) and hang
  // the strings and imports each one touches off it.
  g_current_step = "function_map";
  try {
    struct FnEntry {
      uint64_t off;
      uint64_t end;
      std::string name;
      bool named;
    };
    std::vector<FnEntry> fns;

    // Everything below works in virtual-address space: symbol st_value is a
    // vaddr, the unwind table yields vaddrs, and branch targets are vaddrs.
    // Mixing in file offsets silently loses every correlation on modules
    // mapped at p_vaddr != p_offset.
    AddrMapView av(data);
    for (const auto &sym : func_syms) {
      if (sym.offset == 0)
        continue;
      fns.push_back({sym.offset, sym.offset + sym.size,
                     ElfParser::demangle_symbol(sym.name), true});
    }
    size_t named_count = fns.size();
    size_t eh_frame_count = 0;
    for (uint64_t a : ElfParser::get_eh_frame_functions(data)) {
      fns.push_back({a, 0, "", false});
      eh_frame_count++;
    }

    // Names joined out of the module's own registration tables. This is the
    // il2cpp idea applied generically: a pointer table plus a name table gives
    // back names the symbol table no longer carries.
    std::vector<ElfParser::RecoveredName> recovered;
    if (rizin_work_allowed())
      recovered = ElfParser::recover_names(data, base);
    std::map<uint64_t, const ElfParser::RecoveredName *> recovered_at;
    for (const auto &r : recovered) {
      recovered_at.emplace(r.func_vaddr, &r);
      // A registration table may name functions the inventory never saw.
      fns.push_back({r.func_vaddr, 0, "", false});
    }
    size_t recovered_count = recovered.size();

    std::sort(fns.begin(), fns.end(), [](const FnEntry &a, const FnEntry &b) {
      if (a.off != b.off)
        return a.off < b.off;
      return a.named && !b.named; // prefer the named record at equal address
    });
    fns.erase(std::unique(fns.begin(), fns.end(),
                          [](const FnEntry &a, const FnEntry &b) {
                            return a.off == b.off;
                          }),
              fns.end());

    // Close open ranges against the next function start.
    uint64_t va_limit = 0;
    for (const auto &sg : av.segs)
      va_limit = std::max(va_limit, sg.vaddr + sg.filesz);
    if (va_limit == 0)
      va_limit = data.size();
    for (size_t i = 0; i < fns.size(); i++) {
      uint64_t next = (i + 1 < fns.size()) ? fns[i + 1].off : va_limit;
      if (fns[i].end <= fns[i].off || fns[i].end > next)
        fns[i].end = next;
      if (!fns[i].named) {
        auto rit = recovered_at.find(fns[i].off);
        if (rit != recovered_at.end()) {
          fns[i].name = rit->second->name;
          if (!rit->second->signature.empty())
            fns[i].name += rit->second->signature;
          fns[i].name += "  [" + rit->second->source + "]";
        } else {
          std::ostringstream nm;
          nm << "sub_" << std::hex << (base ? base + fns[i].off : fns[i].off);
          fns[i].name = nm.str();
        }
      }
    }

    auto owner_of = [&](uint64_t off) -> const FnEntry * {
      auto it = std::upper_bound(
          fns.begin(), fns.end(), off,
          [](uint64_t v, const FnEntry &e) { return v < e.off; });
      if (it == fns.begin())
        return nullptr;
      --it;
      return (off < it->end) ? &*it : nullptr;
    };

    // string offset -> value, for naming the referenced literals.
    std::map<uint64_t, std::string> string_at;
    for (const auto &st : report_strings)
      string_at[st.offset] = st.value;

    std::map<const FnEntry *, std::set<uint64_t>> fn_string_offsets;
    for (const auto &kv : xref_map) {
      auto sit = string_at.find(kv.first);
      if (sit == string_at.end())
        continue;
      for (uint64_t site : kv.second) {
        // build_string_xref_map keeps keys as file offsets but returns Rizin's
        // reference sites in ELF virtual-address space.
        const FnEntry *o = owner_of(site);
        if (o)
          fn_string_offsets[o].insert(kv.first);
      }
    }

    // Correlate calls to imports (AArch64 BL).
    std::map<const FnEntry *, std::set<std::string>> fn_calls;
    if (rizin_work_allowed())
      for (const auto &c : ElfParser::find_import_calls(data, base)) {
        const FnEntry *o = owner_of(c.site);
        if (o)
          fn_calls[o].insert(c.symbol);
      }

    size_t with_context = 0;
    for (const auto &fn : fns)
      if (fn_string_offsets.count(&fn) || fn_calls.count(&fn))
        with_context++;

    std::vector<ElfParser::RttiClass> rtti;
    if (rizin_work_allowed())
      rtti = ElfParser::scan_rtti_tables(data, base);
    if (!rtti.empty()) {
      size_t with_vt = 0, vfun = 0;
      for (const auto &c : rtti) {
        if (c.vtable_vaddr)
          with_vt++;
        vfun += c.vfuncs.size();
      }
      f << "\n=== RTTI CLASSES (" << rtti.size() << " classes, " << with_vt
        << " with vtables, " << vfun << " virtual methods) ===\n";
      size_t cshown = 0;
      size_t vfuncs_shown = 0;
      bool vfuncs_truncated = false;
      for (const auto &c : rtti) {
        if (cshown++ >= ao.limit) {
          f << "... (" << (rtti.size() - cshown + 1) << " more)\n";
          break;
        }
        f << "class " << c.name;
        if (c.vtable_vaddr)
          f << "  vtable=0x" << std::hex
            << (base ? base + c.vtable_vaddr : c.vtable_vaddr) << std::dec;
        f << "  typeinfo=0x" << std::hex
          << (base ? base + c.typeinfo_vaddr : c.typeinfo_vaddr) << std::dec
          << "\n";
        for (size_t i = 0; i < c.vfuncs.size(); i++) {
          if (vfuncs_shown >= ao.limit) {
            vfuncs_truncated = true;
            break;
          }
          f << "  [" << i << "] 0x" << std::hex
            << (base ? base + c.vfuncs[i] : c.vfuncs[i]) << std::dec << "\n";
          vfuncs_shown++;
        }
      }
      if (vfuncs_truncated)
        f << "... (additional virtual methods suppressed by --limit)\n";
    }

    // Layout inference: names are gone, but offsets/widths are recoverable.
    std::vector<ElfParser::StructLayout> layouts;
    if (rizin_work_allowed())
      layouts = ElfParser::recover_struct_layouts(data, base);
    if (!layouts.empty()) {
      size_t total_fields = 0;
      for (const auto &l : layouts)
        total_fields += l.fields.size();
      f << "\n=== STRUCT LAYOUTS (" << layouts.size() << " classes, "
        << total_fields << " inferred fields) ===\n";
      f << "Offsets and widths come from how virtual methods dereference "
           "`this`;\nfield names do not exist in the binary.\n";
      size_t lshown = 0;
      size_t fields_shown = 0;
      bool fields_truncated = false;
      for (const auto &l : layouts) {
        if (lshown++ >= ao.limit) {
          f << "... (" << (layouts.size() - lshown + 1) << " more)\n";
          break;
        }
        f << "class " << l.name << "  // min size 0x" << std::hex << l.min_size
          << std::dec << "\n";
        for (const auto &fl : l.fields) {
          if (fields_shown >= ao.limit) {
            fields_truncated = true;
            break;
          }
          f << "  +0x" << std::hex << fl.offset << std::dec << "  "
            << fl.width << "B  " << (fl.read ? "R" : "")
            << (fl.written ? "W" : "") << "  field_" << std::hex << fl.offset
            << std::dec << "  (" << fl.hits << " refs)\n";
          fields_shown++;
        }
      }
      if (fields_truncated)
        f << "... (additional inferred fields suppressed by --limit)\n";
    }

    if (!recovered.empty()) {
      f << "\n=== RECOVERED NAMES (" << recovered.size()
        << ") ===\n";
      size_t rshown = 0;
      for (const auto &r : recovered) {
        if (rshown++ >= ao.limit) {
          f << "... (" << (recovered.size() - rshown + 1) << " more)\n";
          break;
        }
        f << "0x" << std::hex << (base ? base + r.func_vaddr : r.func_vaddr)
          << std::dec << " " << r.name << r.signature << "  [" << r.source
          << "]\n";
      }
    }

    bool tables_truncated = false;
    std::vector<ElfParser::PointerTable> tables;
    if (rizin_work_allowed())
      tables = ElfParser::find_function_tables(data, base, &tables_truncated);
    std::map<uint64_t, std::string> fn_name_at;
    for (const auto &e : fns)
      if (!e.name.empty())
        fn_name_at.emplace(e.off, e.name);
    if (!tables.empty() || tables_truncated) {
      size_t total_slots = 0;
      for (const auto &t : tables)
        total_slots += t.count;
      f << "\n=== FUNCTION POINTER TABLES (" << tables.size()
        << " tables, " << total_slots << " slots) ===\n";
      size_t tshown = 0;
      size_t target_lines_shown = 0;
      bool target_lines_truncated = false;
      for (const auto &t : tables) {
        if (tshown++ >= ao.limit) {
          f << "... (" << (tables.size() - tshown + 1) << " more)\n";
          break;
        }
        f << "0x" << std::hex << (base ? base + t.vaddr : t.vaddr) << std::dec
          << "  " << t.count << " function pointers\n";
        // The targets are the point of the section. In a stripped module these
        // are entry points nothing branches to, so this is the only place they
        // are named at all.
        for (size_t si = 0; si < t.targets.size(); si++) {
          if (target_lines_shown >= ao.limit) {
            target_lines_truncated = true;
            break;
          }
          target_lines_shown++;
          f << "  [" << si << "] 0x" << std::hex
            << (base ? base + t.targets[si] : t.targets[si]) << std::dec;
          auto known = fn_name_at.find(t.targets[si]);
          if (known != fn_name_at.end() && !known->second.empty())
            f << "  " << known->second;
          f << "\n";
        }
        if (target_lines_truncated)
          break;
      }
      if (tables_truncated)
        f << "... [truncated by pointer-table slot/table/analysis budget]\n";
      if (target_lines_truncated)
        f << "... [truncated by --limit pointer-target report budget]\n";
    }

    // The three source buckets are reported separately because they overlap:
    // a function can appear in the symbol table, the unwind table and a
    // registration table at once, and the total is the deduplicated union. An
    // earlier version printed `total - named` and labelled it "recovered from
    // unwind data", which is neither of those things and moved whenever any
    // source found more entries.
    f << "\n=== FUNCTION MAP (" << fns.size() << " unique functions; sources: "
      << named_count << " symbols, " << eh_frame_count << " unwind entries, "
      << recovered_count << " recovered names; " << with_context
      << " with correlated context) ===\n";

    size_t emitted = 0;
    for (const auto &fn : fns) {
      auto sit = fn_string_offsets.find(&fn);
      auto cit = fn_calls.find(&fn);
      bool has_ctx = sit != fn_string_offsets.end() || cit != fn_calls.end();
      if (!has_ctx && !fn.named)
        continue; // an unnamed function with no context carries no information
      if (emitted++ >= ao.limit) {
        f << "... (" << (fns.size() - emitted + 1) << " more suppressed; raise "
          << "--limit)\n";
        break;
      }
      uint64_t addr = base ? base + fn.off : fn.off;
      f << "0x" << std::hex << addr << std::dec << " " << fn.name << " ("
        << (fn.end - fn.off) << " bytes)\n";
      if (cit != fn_calls.end()) {
        f << "  calls:";
        size_t n = 0;
        for (const auto &c : cit->second) {
          f << " " << c;
          if (++n >= 12) {
            f << " ...";
            break;
          }
        }
        f << "\n";
      }
      if (sit != fn_string_offsets.end()) {
        size_t n = 0;
        for (uint64_t string_offset : sit->second) {
          const auto value = string_at.find(string_offset);
          if (value == string_at.end())
            continue;
          std::string t = value->second.substr(0, 100);
          f << "  str: \"" << t << "\"\n";
          if (++n >= 12) {
            f << "  str: ... (" << (sit->second.size() - n) << " more)\n";
            break;
          }
        }
      }
    }
  } catch (...) {
    f << "\n=== FUNCTION MAP (error) ===\n";
  }

  try {
    if (ao.listing && rizin_work_allowed())
      write_function_listing(f, data, base, ao.listing);
  } catch (...) {
  }

  g_current_step = "security";
  bool relro = ElfParser::has_relro(data);
  bool full_relro = ElfParser::has_full_relro(data);
  f << "\n=== SECURITY ===\n";
  f << "RELRO: " << (relro ? "yes" : "no") << "\n";
  f << "FULL_RELRO: " << (full_relro ? "yes" : "no") << "\n";

  g_current_step = "init_fini";
  auto init_funcs = ElfParser::get_init_array(data);
  auto fini_funcs = ElfParser::get_fini_array(data);
  auto to_runtime_addr = [&](uint64_t v) -> uint64_t {
    if (base == 0)
      return v;
    // Values coming from dumped runtime may already be absolute addresses.
    // PT_LOAD virtual ranges, not file length, define module membership: a
    // normal ELF can put executable code far beyond its last file offset.
    if (v >= base && ElfParser::is_file_backed_vaddr(data, v - base))
      return v;
    // SoFixer normalizes runtime pointers back to link-time virtual addresses.
    if (ElfParser::is_file_backed_vaddr(data, v) &&
        v <= std::numeric_limits<uint64_t>::max() - base)
      return base + v;
    return v;
  };
  std::vector<uint64_t> init_runtime;
  init_runtime.reserve(init_funcs.size());
  for (auto fn : init_funcs)
    init_runtime.push_back(to_runtime_addr(fn));
  std::vector<uint64_t> fini_runtime;
  fini_runtime.reserve(fini_funcs.size());
  for (auto fn : fini_funcs)
    fini_runtime.push_back(to_runtime_addr(fn));
  f << "\n=== INIT_ARRAY (" << init_funcs.size() << ") ===\n";
  for (size_t i = 0; i < std::min(init_runtime.size(), ao.limit); i++)
    f << "0x" << std::hex << init_runtime[i] << std::dec << "\n";
  if (init_runtime.size() > ao.limit)
    f << "... (" << (init_runtime.size() - ao.limit)
      << " more suppressed by --limit)\n";
  f << "\n=== FINI_ARRAY (" << fini_funcs.size() << ") ===\n";
  for (size_t i = 0; i < std::min(fini_runtime.size(), ao.limit); i++)
    f << "0x" << std::hex << fini_runtime[i] << std::dec << "\n";
  if (fini_runtime.size() > ao.limit)
    f << "... (" << (fini_runtime.size() - ao.limit)
      << " more suppressed by --limit)\n";

  // Planting breakpoints in init_array and resuming the process is invasive:
  // the constructors have already run by the time we attach, so nothing is
  // caught, while a single breakpoint written to a mis-resolved address kills
  // the target. Opt-in only.
  g_current_step = "trace_init";
  if (trace_init && pid > 0 && !init_runtime.empty()) {
    std::unique_lock<std::mutex> runtime_lock;
    if (runtime_mutex)
      runtime_lock = std::unique_lock<std::mutex>(*runtime_mutex);
    try {
      const std::vector<uint8_t> &identity_image =
          runtime_image ? *runtime_image : data;
      size_t breakpoint_hits = RuntimeAnalyzer::trace_init_array(
          pid, base, normalized_mapping_name(name), identity_image,
          init_runtime);
      f << "\n=== INIT_ARRAY_TRACE ===\n";
      f << "Status: " << RuntimeAnalyzer::last_trace_status() << "\n";
      if (breakpoint_hits != 0) {
        f << "Captured " << breakpoint_hits
          << " init-array breakpoint hit(s)\n";
      } else {
        f << "Trace attempt completed with no captured breakpoints\n";
      }
    } catch (...) {
      f << "\n=== INIT_ARRAY_TRACE ===\n";
      f << "Trace failed with runtime exception\n";
    }
  } else if (pid > 0 && !init_runtime.empty()) {
    f << "\n=== INIT_ARRAY_TRACE ===\n";
    f << "Skipped (pass --trace-init to breakpoint constructors; "
         "this resumes the target and can kill it)\n";
  }

  // Entropy scanning is a whole-image pass; --fast skips it along with the
  // other speculative scans.
  g_current_step = "entropy";
  std::vector<EntropyInfo> entropy;
  if (deep)
    entropy = ElfParser::find_high_entropy_regions(data, 256, 7.0, ao.limit);
  if (!entropy.empty()) {
    f << "\n=== HIGH_ENTROPY (" << entropy.size() << ") ===\n";
    size_t shown = 0;
    for (const auto &e : entropy) {
      if (shown++ >= ao.limit) {
        f << "... (" << (entropy.size() - shown + 1)
          << " more suppressed)\n";
        break;
      }
      uint64_t addr = file_offset_runtime_address(e.offset);
      f << "0x" << std::hex << addr << std::dec << " size=" << e.size
        << " entropy=" << std::fixed << std::setprecision(3) << e.entropy
        << " enc=" << (e.likely_encrypted ? "yes" : "no")
        << " comp=" << (e.likely_compressed ? "yes" : "no") << "\n";
    }
  }

  bool deobf_header_printed = false;
  auto ensure_deobf_header = [&]() {
    if (!deobf_header_printed) {
      f << "\n=== DEOBFUSCATION ===\n";
      deobf_header_printed = true;
    }
  };

  // The XOR-string sweep and the multi-cipher probe dominate runtime (tens of
  // seconds on a multi-megabyte module), so they only run in deep mode.
  g_current_step = "deobf_scan";
  std::vector<std::string> enc_strings;
  bool enc_strings_truncated = false;
  if (ao.deobf)
    enc_strings = ElfParser::find_encrypted_strings(
        data, ao.deobf_input_bytes, ao.limit, ao.deobf_timeout_ms,
        &enc_strings_truncated);
  if (!enc_strings.empty()) {
    ensure_deobf_header();
    f << "[ENCRYPTED_STRINGS] count=" << enc_strings.size() << "\n";
    for (const auto &s : enc_strings)
      f << "  " << s << "\n";
  }
  if (ao.deobf && enc_strings_truncated) {
    ensure_deobf_header();
    f << "[ENCRYPTED_STRINGS] truncated by input/result/deadline budget\n";
  }

  g_current_step = "decrypt";
  std::vector<DecryptResult> decrypted;
  AutoDecryptStatus decrypt_status;
  if (ao.deobf) {
    AutoDecryptLimits decrypt_limits;
    decrypt_limits.max_input_bytes = ao.deobf_input_bytes;
    decrypt_limits.max_probes = ao.deobf_probes;
    decrypt_limits.max_candidates = ao.deobf_candidates;
    decrypt_limits.max_results = ao.limit;
    decrypt_limits.deadline_ms = ao.deobf_timeout_ms;
    decrypted = ElfParser::auto_decrypt_strings(data, decrypt_limits,
                                                &decrypt_status);
  }
  std::set<std::pair<uint64_t, std::string>> dec_seen;
  for (const auto &r : decrypted)
    dec_seen.emplace(r.offset, r.method);

  auto add_decrypted = [&](const std::vector<DecryptResult> &extra) {
    for (const auto &r : extra) {
      if (decrypted.size() >= ao.limit)
        break;
      std::pair<uint64_t, std::string> key = {r.offset, r.method};
      if (dec_seen.insert(key).second)
        decrypted.push_back(r);
    }
  };

  const std::vector<uint8_t> &runtime_diff_image =
      runtime_image && !runtime_image->empty() ? *runtime_image : data;
  std::vector<SnapshotDifference> runtime_disk_differences;
  if (disk_snapshot && !disk_snapshot->empty())
    runtime_disk_differences =
        find_snapshot_differences(runtime_diff_image, *disk_snapshot, base,
                                  ao.limit);

  auto dump_diff = [&](const std::vector<SnapshotDifference> &diff_regions,
                       const std::string &title) {
    if (!diff_regions.empty()) {
      ensure_deobf_header();
      f << "[" << title << "] count=" << diff_regions.size() << "\n";
      size_t shown = 0;
      size_t decrypt_probes = 0;
      for (const auto &r : diff_regions) {
        if (shown++ >= ao.limit) {
          f << "  ... (" << (diff_regions.size() - shown + 1)
            << " more suppressed)\n";
          break;
        }
        f << "  0x" << std::hex << r.runtime_address << std::dec << " ("
          << r.size
          << ")\n";
        if (ao.deobf && decrypt_probes++ < ao.deobf_candidates) {
          size_t span = std::min(r.size, (size_t)1024);
          auto extra =
              ElfParser::try_decrypt(runtime_diff_image, r.file_offset, span);
          if (!extra.empty())
            add_decrypted(extra);
        }
      }
    }
  };

  dump_diff(runtime_disk_differences, "RUNTIME_DIFF_DISK");

  if (ao.deobf && !entropy.empty()) {
    size_t probes = 0;
    for (const auto &e : entropy) {
      if (probes >= ao.deobf_candidates || decrypted.size() >= ao.limit)
        break;
      if (!e.likely_encrypted)
        continue;
      probes++;
      size_t span = std::min(e.size, (size_t)1024);
      auto extra = ElfParser::try_decrypt(data, e.offset, span);
      if (!extra.empty())
        add_decrypted(extra);
    }
  }

  if (ao.deobf && decrypt_status.truncated()) {
    ensure_deobf_header();
    f << "[DECRYPTED] truncated by input/probe/candidate/result/deadline "
         "budget\n";
  }

  if (!decrypted.empty()) {
    ensure_deobf_header();
    f << "[DECRYPTED] count=" << decrypted.size() << "\n";
    auto preview = [](const std::vector<uint8_t> &buf) -> std::string {
      std::string out;
      out.reserve(buf.size());
      for (size_t i = 0; i < buf.size(); i++) {
        uint8_t b = buf[i];
        if (b == 0)
          break;
        if (b >= 0x20 && b <= 0x7E)
          out.push_back(static_cast<char>(b));
        else
          out.push_back('.');
        if (out.size() >= 200)
          break;
      }
      return out;
    };
    size_t dec_shown = 0;
    for (const auto &r : decrypted) {
      if (dec_shown++ >= ao.limit) {
        f << "  ... (" << (decrypted.size() - dec_shown + 1)
          << " more suppressed)\n";
        break;
      }
      uint64_t addr = file_offset_runtime_address(r.offset);
      f << "  0x" << std::hex << addr << std::dec << " " << r.method;
      if (r.key_size) {
        size_t klen = std::min(r.key_size, sizeof(r.key_or_info));
        f << " keylen=" << r.key_size << " key=" << hex_bytes(r.key_or_info, klen);
      }
      f << "\n";
      std::string text = preview(r.decrypted);
      if (!text.empty())
        f << "    " << text << "\n";
    }
  }

  bool crypto_header_printed = false;
  auto ensure_crypto_header = [&]() {
    if (!crypto_header_printed) {
      f << "\n=== CRYPTO ===\n";
      crypto_header_printed = true;
    }
  };

  g_current_step = "plt";
  try {
    auto plt = ElfParser::get_plt_entries(data);
    if (!plt.empty()) {
      f << "\n=== PLT (" << plt.size() << ") ===\n";
      const size_t shown = std::min(plt.size(), ao.limit);
      for (size_t i = 0; i < shown; i++) {
        const auto &e = plt[i];
        uint64_t addr = base ? base + e.offset : e.offset;
        f << "0x" << std::hex << addr << std::dec;
        if (!e.symbol_name.empty())
          f << " " << ElfParser::demangle_symbol(e.symbol_name);
        f << "\n";
      }
      if (shown < plt.size())
        f << "... (" << (plt.size() - shown)
          << " more suppressed by --limit)\n";
    }
  } catch (...) {
  }

  g_current_step = "got_dump";
  try {
    const std::vector<uint8_t> &live =
        runtime_image && !runtime_image->empty() ? *runtime_image : data;
    auto got_entries = dump_got_from_snapshot(live);
    if (!got_entries.empty()) {
      f << "\n=== GOT (" << got_entries.size() << ") ===\n";
      const size_t shown = std::min(got_entries.size(), ao.limit);
      for (size_t i = 0; i < shown; i++) {
        const auto &e = got_entries[i];
        f << "0x" << std::hex << e.second << std::dec;
        if (!e.first.empty())
          f << " " << ElfParser::demangle_symbol(e.first);
        f << "\n";
      }
      if (shown < got_entries.size())
        f << "... (" << (got_entries.size() - shown)
          << " more suppressed by --limit)\n";
    }
  } catch (...) {
  }

  g_current_step = "signatures";
  try {
    if (!deep || !rizin_work_allowed())
      throw 0; // --fast: byte signatures are a per-symbol scan, skip them
    auto &sig_src = func_syms.empty() ? symbols : func_syms;
    size_t sig_count = std::min(sig_src.size(), ao.limit);
    if (sig_count > 0) {
      // A symbol's offset is its st_value, a virtual address; the signature is
      // cut out of the image, which is indexed by file offset. Feeding one to
      // the other produced an empty section for every 16 KB-aligned library,
      // because every st_value landed past the end of the buffer.
      AddrMapView sig_map(data);
      std::ostringstream sigs;
      size_t emitted = 0;
      for (size_t i = 0; i < sig_count; i++) {
        const auto &s = sig_src[i];
        uint64_t file_off = 0;
        if (s.offset == 0 || !sig_map.to_offset(s.offset, &file_off))
          continue;
        if (file_off + 32 >= data.size())
          continue;
        std::string sig = ElfParser::generate_signature(data, file_off, 32);
        if (sig.empty())
          continue;
        uint64_t addr = base ? base + s.offset : s.offset;
        sigs << "0x" << std::hex << addr << std::dec << " "
             << ElfParser::demangle_symbol(s.name) << "\n  " << sig << "\n";
        emitted++;
      }
      if (emitted)
        f << "\n=== SIGNATURES (" << emitted << ") ===\n" << sigs.str();
    }
  } catch (...) {
  }

  g_current_step = "enc_key";
  try {
    auto enc_key = rizin_work_allowed()
                       ? ElfParser::find_encryption_key(data, base)
                       : std::vector<uint8_t>{};
    if (!enc_key.empty()) {
      ensure_crypto_header();
      f << "[ENCRYPTION_KEY] size=" << enc_key.size()
        << " bytes validation=RzIL+AES-EXPANDED-SCHEDULE\n";
      f << "  " << hex_bytes(enc_key.data(), enc_key.size()) << "\n";
    }
  } catch (...) {
  }

  g_current_step = "crypto_scan";
  try {
    auto crypto_keys =
        deep ? CryptoAnalyzer::scan_for_keys(data, base)
             : std::vector<CryptoKeyInfo>{};
    if (!crypto_keys.empty()) {
      ensure_crypto_header();
      f << "[CRYPTO_KEYS] count=" << crypto_keys.size() << "\n";
      const size_t shown_count = std::min(crypto_keys.size(), ao.limit);
      for (size_t i = 0; i < shown_count; i++) {
        const auto &k = crypto_keys[i];
        f << "  0x" << std::hex << k.key_addr << std::dec << " " << k.algorithm
          << " conf=" << std::fixed << std::setprecision(2) << k.confidence
          << " " << k.source << "\n";
        if (!k.key_data.empty()) {
          size_t shown = std::min<size_t>(k.key_data.size(), 64);
          f << "    " << hex_bytes(k.key_data.data(), shown);
          if (shown < k.key_data.size())
            f << " ... (" << k.key_data.size() << " bytes)";
          f << "\n";
        }
      }
      if (shown_count < crypto_keys.size())
        f << "  ... (" << (crypto_keys.size() - shown_count)
          << " more suppressed by --limit)\n";
    }
  } catch (...) {
  }

  // File reconstruction intentionally preserves ELF file layout and therefore
  // does not append PT_LOAD .bss. Expanded AES schedules and decoded RSA
  // containers commonly live in those writable runtime pages, so scan the
  // module's live writable mappings as a separate address-accurate source.
  if (deep && runtime_snapshot && writable_snapshot_indices) {
    std::vector<CryptoKeyInfo> runtime_keys;
    std::set<std::tuple<uint64_t, std::string, std::string>> seen;
    for (size_t index : *writable_snapshot_indices) {
      if (index >= runtime_snapshot->writable_modules.size())
        continue;
      const auto &captured = runtime_snapshot->writable_modules[index];
      for (auto &key : CryptoAnalyzer::scan_for_keys(
               captured.data, captured.mapping.start)) {
        std::string material;
        if (!key.key_data.empty())
          material.assign(
              reinterpret_cast<const char *>(key.key_data.data()),
              std::min<size_t>(key.key_data.size(), 64));
        if (seen.emplace(key.key_addr, key.algorithm, material).second)
          runtime_keys.push_back(std::move(key));
      }
    }
    if (!runtime_keys.empty()) {
      ensure_crypto_header();
      f << "[RUNTIME_CRYPTO_KEYS] count=" << runtime_keys.size() << "\n";
      const size_t shown_count = std::min(runtime_keys.size(), ao.limit);
      for (size_t i = 0; i < shown_count; i++) {
        const auto &k = runtime_keys[i];
        f << "  0x" << std::hex << k.key_addr << std::dec << " "
          << k.algorithm << " conf=" << std::fixed << std::setprecision(2)
          << k.confidence << " " << k.source << "\n";
        if (!k.key_data.empty()) {
          size_t shown = std::min<size_t>(k.key_data.size(), 64);
          f << "    " << hex_bytes(k.key_data.data(), shown);
          if (shown < k.key_data.size())
            f << " ... (" << k.key_data.size() << " bytes)";
          f << "\n";
        }
      }
      if (shown_count < runtime_keys.size())
        f << "  ... (" << (runtime_keys.size() - shown_count)
          << " more suppressed by --limit)\n";
    }
  }

  g_current_step = "vtable_instances";
  if (deep && runtime_snapshot) {
    try {
      // Both sources of vtable addresses, not just the symbol table.
      //
      // _ZTV* symbols only survive in a module that was not stripped, which is
      // exactly the case where this scan is least interesting. In a stripped
      // one the vtables come from RTTI, and skipping the class list meant the
      // section never appeared for the modules it was written for.
      std::vector<std::pair<uint64_t, std::string>> vt_addrs;
      for (const auto &vt : vtables)
        vt_addrs.push_back({base ? base + vt.offset : vt.offset,
                            ElfParser::demangle_symbol(vt.name)});
      if (rizin_work_allowed())
        for (const auto &cls : ElfParser::scan_rtti_tables(data, base)) {
          if (!cls.vtable_vaddr)
            continue;
          uint64_t a = base ? base + cls.vtable_vaddr : cls.vtable_vaddr;
          bool dup = false;
          for (const auto &have : vt_addrs)
            dup = dup || have.first == a;
          if (!dup)
            vt_addrs.push_back({a, cls.name});
        }

      size_t vt_scan = std::min(vt_addrs.size(), ao.limit);
      std::vector<std::pair<size_t, std::vector<uint64_t>>> instances;
      bool instances_truncated = false;
      for (size_t i = 0; i < vt_scan; i++) {
        bool local_truncated = false;
        auto found = find_instances_in_snapshot(
            *runtime_snapshot, vt_addrs[i].first, ao.limit,
            &local_truncated);
        instances_truncated = instances_truncated || local_truncated;
        if (!found.empty())
          instances.push_back({i, found});
      }
      if (!instances.empty()) {
        f << "\n=== VTABLE_INSTANCES ===\n";
        size_t addresses_shown = 0;
        for (const auto &kv : instances) {
          f << "VT 0x" << std::hex << vt_addrs[kv.first].first << std::dec;
          if (!vt_addrs[kv.first].second.empty())
            f << " " << vt_addrs[kv.first].second;
          f << " instances=" << kv.second.size() << "\n";
          for (auto a : kv.second) {
            if (addresses_shown >= ao.limit) {
              instances_truncated = true;
              break;
            }
            f << "  0x" << std::hex << a << std::dec << "\n";
            addresses_shown++;
          }
          if (addresses_shown >= ao.limit)
            break;
        }
        if (instances_truncated)
          f << "... (additional instances suppressed by --limit)\n";
      }
    } catch (...) {
    }
  }

  const bool partial =
      rzb::analysis_level() != rzb::AnalysisLevel::None &&
      (!rizin_analysis_complete || !analysis_image ||
       analysis_image->analysis_failed());
  f << "\n=== ANALYSIS STATUS ===\n"
    << (partial ? "INCOMPLETE: Rizin did not finish the requested analysis "
                  "level.\n"
                : "COMPLETE for the requested analysis level.\n");
  if (partial && analysis_incomplete)
    *analysis_incomplete = true;
  f.close();
  return static_cast<bool>(f);
}


// ---- shared command plumbing -------------------------------------------------
// cmd_hook / cmd_inject / cmd_scan / cmd_extract all begin the same way; these
// three helpers are the single implementation of that preamble.

using Emitter = std::function<void(const std::string &)>;

// Block until a process whose cmdline starts with `pkg` appears.
// Returns -1 if `timeout_sec` > 0 and elapses first.
int wait_for_process(const std::string &pkg, const Emitter &emit,
                     int timeout_sec) {
  emit("[1] Waiting for process...\n");
  std::cout.flush();
  time_t start = time(nullptr);
  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    if (!pids.empty()) {
      emit("[2] Found PID: " + std::to_string(pids[0]) + "\n");
      return pids[0];
    }
    if (timeout_sec > 0 && time(nullptr) - start >= timeout_sec) {
      emit("[!] Timed out after " + std::to_string(timeout_sec) +
           "s waiting for '" + pkg + "'\n");
      return -1;
    }
    usleep(100000);
  }
}

bool attach_and_prepare(int pid, const Emitter &emit) {
  emit("[3] Attaching...\n");
  if (!ProcessTracer::attach(pid)) {
    emit("[!] Failed to attach to " + std::to_string(pid) + "\n");
    return false;
  }
  return true;
}

// Search every mapped .so for `func_name`. Returns 0 if not found.
uint64_t find_symbol_in_process(int pid, const std::string &func_name,
                                std::string *found_lib) {
  for (const auto &r : ProcessTracer::get_library_ranges(pid)) {
    if (r.name.empty() || r.name.find(".so") == std::string::npos)
      continue;
    std::string lib = r.name;
    size_t slash = lib.rfind('/');
    if (slash != std::string::npos)
      lib = lib.substr(slash + 1);
    if (lib.find(".so") == std::string::npos)
      continue;
    uint64_t a = FunctionHooker::find_remote_symbol(pid, lib, func_name);
    if (a != 0) {
      if (found_lib)
        *found_lib = r.name;
      return a;
    }
  }
  return 0;
}

void hook_signal_handler(int) {
  g_hook_running.store(false, std::memory_order_relaxed);
}

// A patch must never exist while SIGINT/SIGTERM still point at the process-wide
// fatal handler: that handler exits immediately, leaving the target modified.
// Block both signals, install the cooperative handler, apply every patch, then
// unblock only after the tracee is running. A pending signal is consequently
// delivered to hook_signal_handler and drives the normal restore path.
class PatchSignalWindow {
public:
  bool prepare() {
    if (prepared_)
      return true;

    sigemptyset(&blocked_set_);
    sigaddset(&blocked_set_, SIGINT);
    sigaddset(&blocked_set_, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blocked_set_, &previous_mask_) != 0)
      return false;
    mask_blocked_ = true;

    struct sigaction sa = {};
    sa.sa_handler = hook_signal_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGINT, &sa, &previous_int_) != 0) {
      restore_mask();
      return false;
    }
    have_previous_int_ = true;
    if (sigaction(SIGTERM, &sa, &previous_term_) != 0) {
      sigaction(SIGINT, &previous_int_, nullptr);
      have_previous_int_ = false;
      restore_mask();
      return false;
    }
    have_previous_term_ = true;
    g_hook_running.store(true, std::memory_order_relaxed);
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

  ~PatchSignalWindow() {
    g_hook_running.store(false, std::memory_order_relaxed);
    // If the mask is still blocked, restore the old dispositions before
    // releasing it. Callers only let this happen before patching or after
    // completing their restore attempt.
    if (have_previous_term_)
      sigaction(SIGTERM, &previous_term_, nullptr);
    if (have_previous_int_)
      sigaction(SIGINT, &previous_int_, nullptr);
    restore_mask();
  }

private:
  void restore_mask() {
    if (!mask_blocked_)
      return;
    sigprocmask(SIG_SETMASK, &previous_mask_, nullptr);
    mask_blocked_ = false;
  }

  sigset_t blocked_set_{};
  sigset_t previous_mask_{};
  struct sigaction previous_int_ {};
  struct sigaction previous_term_ {};
  bool mask_blocked_ = false;
  bool have_previous_int_ = false;
  bool have_previous_term_ = false;
  bool prepared_ = false;
};

// Own the dangerous interval in which the tracee may contain temporary code.
// Normal completion is allowed only after every original byte was read back
// and every tracee was verifiably detached. Any other exit kills the target
// before discarding attach and transaction bookkeeping.
class PatchTransactionGuard {
public:
  explicit PatchTransactionGuard(int pid) : pid_(pid) {}

  PatchTransactionGuard(const PatchTransactionGuard &) = delete;
  PatchTransactionGuard &operator=(const PatchTransactionGuard &) = delete;

  bool begin() {
    if (active_)
      return true;
    active_ = ProcessTracer::begin_patch_transaction(pid_);
    return active_;
  }

  bool finish_verified(bool bytes_restored, bool detached) {
    if (!active_)
      return false;
    if (!bytes_restored || !detached) {
      fail_closed();
      return false;
    }
    ProcessTracer::end_patch_transaction(pid_);
    active_ = false;
    return true;
  }

  void fail_closed() {
    if (!active_)
      return;
    // The active dangerous transaction owns a pidfd. cleanup_all_attached()
    // signals that stable process identity before it releases any ptrace stop;
    // a raw numeric kill here could hit a recycled PID after an exit race.
    ProcessTracer::cleanup_all_attached();
    ProcessTracer::reset_attach_bookkeeping();
    ProcessTracer::end_patch_transaction(pid_);
    active_ = false;
  }

  ~PatchTransactionGuard() { fail_closed(); }

private:
  int pid_ = -1;
  bool active_ = false;
};

bool cmd_hook(const std::string &pkg, const std::string &func_name,
              int inst_count) {
  SecureRunDirectory output = open_run_out_dir(pkg, "_analysis");
  if (!output) {
    std::cerr << "[!] " << output.error() << "\n";
    return false;
  }
  const std::string log_leaf =
      "hook_" + safe_path_component(func_name) + ".txt";
  const std::string log_path = output.io_path() + "/" + log_leaf;
  const std::string log_display = output.display_path() + "/" + log_leaf;
  std::ofstream log(log_path);
  if (!log.is_open()) {
    std::cerr << "[!] Could not open hook log: " << log_display << "\n";
    return false;
  }

  auto finish_log = [&](bool command_ok) {
    log.flush();
    bool log_ok = log.good();
    log.close();
    log_ok = log_ok && !log.fail();
    if (log_ok)
      std::cout << "Log saved: " << log_display << "\n";
    else
      std::cerr << "[!] Could not flush and close hook log: " << log_display
                << "\n";
    return command_ok && log_ok;
  };

  auto emit = [&](const std::string &msg) {
    std::cout << msg;
    log << msg;
  };

  emit("\n=== HAYABUSA FUNCTION HOOK ===\n");
  emit("Target: " + pkg + "\n");
  emit("Function: " + func_name + "\n");
  emit("Instructions: " + std::to_string(inst_count) + "\n\n");

  int pid = wait_for_process(pkg, emit, 0);
  if (pid < 0 || !attach_and_prepare(pid, emit))
    return finish_log(false);

  emit("[5] Searching for function '" + func_name + "'...\n");
  std::string found_lib;
  uint64_t func_addr = find_symbol_in_process(pid, func_name, &found_lib);

  if (func_addr == 0) {
    emit("[!] Function '" + func_name + "' not found\n");
    ProcessTracer::detach(pid);
    return finish_log(false);
  }

  {
    std::ostringstream ss;
    ss << "    Found at 0x" << std::hex << func_addr << std::dec << " in "
       << found_lib << "\n";
    emit(ss.str());
  }

  // Disassemble instructions
  {
    size_t count = static_cast<size_t>(inst_count);
    const size_t inst_size = 4;
    std::vector<uint8_t> code_buf(count * inst_size);
    if (ProcessTracer::read_memory(pid, func_addr, code_buf.data(),
                                   code_buf.size())) {
      std::ostringstream ss;
      ss << "    === DISASSEMBLY (first " << count << " instructions) ===\n";
      // rizin already produces the full mnemonic with resolved operands.
      // Re-deriving a name from the instruction category, as this used to,
      // covered eight cases and printed "???" for everything else -- which on
      // real code is most of it.
      for (size_t i = 0; i < count; i++) {
        uint64_t addr = func_addr + i * inst_size;
        ss << "    0x" << std::hex << addr << ": "
           << hex_bytes(code_buf.data() + i * inst_size, 4) << " ";
        rzb::Insn insn;
        if (rzb::decode_one(code_buf.data() + i * inst_size,
                            code_buf.size() - i * inst_size, addr, &insn) &&
            !insn.text.empty())
          ss << insn.text;
        else
          ss << "(undecodable)";
        ss << std::dec << "\n";
      }
      emit(ss.str());
    }
  }

  // Prove the log is writable before changing target code. A successful open
  // alone is insufficient when the filesystem is full or an I/O error is
  // reported only on flush.
  log.flush();
  if (!log.good()) {
    std::cerr << "[!] Hook log became unwritable before patching: "
              << log_display
              << "\n";
    ProcessTracer::detach(pid);
    return finish_log(false);
  }

  PatchSignalWindow signal_window;
  if (!signal_window.prepare()) {
    emit("[!] Could not install the restore signal handler\n");
    ProcessTracer::detach(pid);
    return finish_log(false);
  }
  PatchTransactionGuard transaction(pid);
  if (!transaction.begin()) {
    emit("[!] Another patch transaction is already active\n");
    ProcessTracer::detach(pid);
    return finish_log(false);
  }

  LoggingHook hook{};
  if (!MemoryInjector::install_logging_hook(pid, func_addr, &hook)) {
    emit("[!] Inline hook could not be installed: " + hook.info.error + "\n");
    emit("    (use `hayabusa stub` to force an immediate return instead)\n");
    // `active` is published before any target branch can become ambiguous.
    // Pre-patch failures (for example a refused scratch mmap) are safe to
    // detach; only an unverified live branch requires terminal cleanup.
    if (hook.info.active) {
      transaction.fail_closed();
    } else {
      bool detached = ProcessTracer::detach(pid);
      (void)transaction.finish_verified(true, detached);
    }
    return finish_log(false);
  }
  {
    std::ostringstream ss;
    ss << "[6] Inline hook installed (trampoline=0x" << std::hex
       << hook.info.trampoline_addr << ", records=0x" << hook.record_addr
       << std::dec << ")\n";
    emit(ss.str());
  }

  emit("[7] Scanning for crypto functions...\n");
  size_t installed_crypto = 0;
  bool crypto_state_unknown = false;
  {
    uint64_t orig_enc = 0, orig_dec = 0;
    CryptoHookResult enc_result =
        CryptoAnalyzer::hook_aes_encrypt(pid, &orig_enc);
    CryptoHookResult dec_result = CryptoHookResult::NotFound;
    if (enc_result != CryptoHookResult::StateUnknown)
      dec_result = CryptoAnalyzer::hook_aes_decrypt(pid, &orig_dec);
    std::set<uint64_t> crypto_targets;
    auto report_crypto_result = [&](const char *name, CryptoHookResult result,
                                    uint64_t address) {
      if (result == CryptoHookResult::Installed) {
        crypto_targets.insert(address);
        std::ostringstream ss;
        ss << "    [+] " << name << " hooked (orig=0x" << std::hex
           << address << std::dec << ")\n";
        emit(ss.str());
      } else if (result == CryptoHookResult::SafeFailure) {
        emit(std::string("    [!] ") + name +
             " hook could not be installed safely\n");
      } else if (result == CryptoHookResult::StateUnknown) {
        emit(std::string("    [!] ") + name +
             " hook state is unknown; restoring before detach\n");
        crypto_state_unknown = true;
      }
    };
    report_crypto_result("AES encrypt", enc_result, orig_enc);
    report_crypto_result("AES decrypt", dec_result, orig_dec);
    installed_crypto = crypto_targets.size();
    if (enc_result == CryptoHookResult::NotFound &&
        dec_result == CryptoHookResult::NotFound)
      emit("    [!] No crypto functions found to hook\n");
  }

  if (crypto_state_unknown) {
    CryptoRestoreResult crypto_restore =
        CryptoAnalyzer::restore_aes_hooks(pid);
    bool logging_restored = MemoryInjector::remove_logging_hook(pid, hook);
    bool bytes_restored = logging_restored && crypto_restore.all_clean();
    bool detached = bytes_restored && ProcessTracer::detach(pid);
    emit("    AES rollback: restored=" +
         std::to_string(crypto_restore.restored) +
         " remaining=" + std::to_string(crypto_restore.remaining) + "\n");
    if (!transaction.finish_verified(bytes_restored, detached))
      emit("    [!] Unknown crypto hook was not fully restored; target killed\n");
    emit("=== FAILED ===\n");
    return finish_log(false);
  }

  emit("    Logging calls. Press Ctrl+C to unhook and exit\n");
  std::cout.flush();

  if (!signal_window.unblock()) {
    emit("[!] Could not enable cooperative termination signals\n");
    bool logging_restored = MemoryInjector::remove_logging_hook(pid, hook);
    CryptoRestoreResult crypto_restore =
        CryptoAnalyzer::restore_aes_hooks(pid);
    bool bytes_restored = logging_restored && crypto_restore.all_clean();
    bool detached = bytes_restored && ProcessTracer::detach(pid);
    if (!transaction.finish_verified(bytes_restored, detached))
      emit("    [!] Hook restore was not fully verified; target killed\n");
    emit("=== FAILED ===\n");
    return finish_log(false);
  }

  uint64_t last_reported = 0;
  auto report_records = [&]() {
    std::vector<CallRecord> records;
    uint64_t count = MemoryInjector::read_logging_hook(pid, hook, &records);
    if (count == last_reported)
      return;
    last_reported = count;
    std::ostringstream ss;
    ss << "    [hit] " << func_name << " calls=" << count << "\n";
    for (size_t i = 0; i < records.size(); i++) {
      ss << "      #" << i << " args=";
      for (int k = 0; k < 4; k++)
        ss << (k ? ", 0x" : "0x") << std::hex << records[i].args[k] << std::dec;
      ss << "\n";
    }
    emit(ss.str());
    std::cout.flush();
  };

  PatchSupervisionResult supervision = ProcessTracer::supervise_patch_target(
      pid,
      [] { return g_hook_running.load(std::memory_order_relaxed); },
      report_records);
  if (supervision != PatchSupervisionResult::Stopped &&
      supervision != PatchSupervisionResult::GroupStopped) {
    emit(supervision == PatchSupervisionResult::TargetGone
             ? "    [!] Target exited while hooks were supervised\n"
             : "    [!] Fork-aware hook supervision failed; target killed\n");
    transaction.fail_closed();
    emit("=== FAILED ===\n");
    return finish_log(false);
  }

  emit("\n[8] Removing hook...\n");
  std::vector<CallRecord> records;
  uint64_t count = MemoryInjector::read_logging_hook(pid, hook, &records);
  bool logging_restored = MemoryInjector::remove_logging_hook(pid, hook);
  CryptoRestoreResult crypto_restore = CryptoAnalyzer::restore_aes_hooks(pid);
  bool aes_restored = crypto_restore.all_clean();
  bool bytes_restored = logging_restored && aes_restored;
  bool detached = bytes_restored && ProcessTracer::detach(pid);
  emit("    Total calls observed: " + std::to_string(count) + "\n");
  if (logging_restored)
    emit("    Logging hook restored\n");
  else
    emit("    [!] Logging hook restore failed\n");
  if (installed_crypto > 0 && aes_restored) {
    emit("    Restored " + std::to_string(crypto_restore.restored) +
         " AES hook(s)\n");
  } else if (!aes_restored) {
    emit("    [!] AES hook restore incomplete (restored=" +
         std::to_string(crypto_restore.restored) +
         " remaining=" + std::to_string(crypto_restore.remaining) + ")\n");
  }
  if (bytes_restored && !detached)
    emit("    [!] Could not resume target after restoring hooks\n");
  bool restore_ok = transaction.finish_verified(bytes_restored, detached);
  if (!restore_ok)
    emit("    [!] Restore/detach was not fully verified; target killed\n");

  bool ok = restore_ok;
  emit(ok ? "=== DONE ===\n" : "=== FAILED ===\n");
  return finish_log(ok);
}

bool cmd_stub(const std::string &pkg, const std::string &func_name) {
  std::cout << "\n=== HAYABUSA FUNCTION STUB ===\n";
  std::cout << "Target: " << pkg << "\n";
  std::cout << "Function: " << func_name << "\n\n";

  auto emit = [](const std::string &msg) { std::cout << msg; };
  int pid = wait_for_process(pkg, emit, 0);
  if (pid < 0 || !attach_and_prepare(pid, emit))
    return false;

  std::cout << "[5] Searching for function '" << func_name << "'...\n";
  std::string found_lib;
  uint64_t func_addr = find_symbol_in_process(pid, func_name, &found_lib);
  if (func_addr == 0) {
    std::cout << "[!] Function '" << func_name << "' not found\n";
    ProcessTracer::detach(pid);
    return false;
  }
  std::cout << "    Found at 0x" << std::hex << func_addr << std::dec << " in "
            << found_lib << "\n";

  PatchSignalWindow signal_window;
  if (!signal_window.prepare()) {
    std::cout << "[!] Could not install the restore signal handler\n";
    ProcessTracer::detach(pid);
    return false;
  }
  PatchTransactionGuard transaction(pid);
  if (!transaction.begin()) {
    std::cout << "[!] Another patch transaction is already active\n";
    ProcessTracer::detach(pid);
    return false;
  }

  std::vector<uint8_t> original;
  ExecutableWriteResult stub_result =
      MemoryInjector::stub_out_function(pid, func_addr, &original);
  if (stub_result != ExecutableWriteResult::WrittenVerified) {
    std::cout << "[!] Failed to write stub\n";
    if (stub_result == ExecutableWriteResult::StateUnknown) {
      transaction.fail_closed();
    } else {
      bool detached = ProcessTracer::detach(pid);
      (void)transaction.finish_verified(true, detached);
    }
    return false;
  }
  std::cout << "[6] Function stubbed out (returns immediately, "
            << original.size() << " bytes replaced)\n";
  std::cout << "    Press Ctrl+C to restore and exit\n";
  std::cout.flush();

  if (!signal_window.unblock()) {
    std::cout << "[!] Could not enable cooperative termination signals\n";
    bool bytes_restored =
        MemoryInjector::restore_function(pid, func_addr, original);
    bool detached = bytes_restored && ProcessTracer::detach(pid);
    if (!transaction.finish_verified(bytes_restored, detached))
      std::cout << "    [!] Stub restore was not fully verified; target killed\n";
    return false;
  }

  PatchSupervisionResult supervision = ProcessTracer::supervise_patch_target(
      pid, [] { return g_hook_running.load(std::memory_order_relaxed); });
  if (supervision != PatchSupervisionResult::Stopped &&
      supervision != PatchSupervisionResult::GroupStopped) {
    std::cout << (supervision == PatchSupervisionResult::TargetGone
                      ? "[!] Target exited while the stub was supervised\n"
                      : "[!] Fork-aware stub supervision failed; target killed\n");
    transaction.fail_closed();
    return false;
  }

  std::cout << "\n[7] Restoring...\n";
  bool restored = MemoryInjector::restore_function(pid, func_addr, original);
  bool detached = restored && ProcessTracer::detach(pid);
  if (restored)
    std::cout << "    Stub restored\n";
  else
    std::cout << "    [!] Stub restore failed\n";
  if (!detached)
    std::cout << "    [!] Could not resume target after restore\n";
  bool ok = transaction.finish_verified(restored, detached);
  if (!ok)
    std::cout << "    [!] Restore/detach was not fully verified; target killed\n";
  std::cout << (ok ? "=== DONE ===\n" : "=== FAILED ===\n");
  return ok;
}

bool cmd_inject(const std::string &pkg, const std::string &so_path) {
  std::cout << "\n=== HAYABUSA LIBRARY INJECTION ===\n";
  std::cout << "Target: " << pkg << "\n";
  std::cout << "Library: " << so_path << "\n\n";

  auto emit = [](const std::string &msg) { std::cout << msg; };

  int pid = wait_for_process(pkg, emit, 0);
  if (pid < 0 || !attach_and_prepare(pid, emit))
    return false;

  std::cout << "[5] Injecting library...\n";
  RemoteCallResult injection = FunctionHooker::inject_library(pid, so_path);
  bool ok = injection.success && injection.return_value != 0;
  bool target_gone = injection.target_gone;
  bool target_group_stopped = injection.target_group_stopped;

  if (ok) {
    std::cout << "    [+] Library injected successfully\n";
  } else {
    std::cout << "    [!] Injection failed\n";
    if (!injection.error_message.empty())
      std::cout << "    " << injection.error_message << "\n";
    // A timed-out constructor can leave linker state ambiguous, so call_remote
    // kills the target fail-closed. Never ask that dead (and recyclable) PID for
    // dlerror. Likewise, do not wake a genuine job-control stop for diagnostics.
    if (!target_gone && !target_group_stopped) {
      RemoteStringResult dlerror = MemoryInjector::remote_dlerror(pid);
      target_gone = dlerror.target_gone;
      target_group_stopped = dlerror.target_group_stopped;
      if (!dlerror.value.empty())
        std::cout << "    dlerror: " << dlerror.value << "\n";
    }
  }

  bool detached = target_gone || ProcessTracer::detach(pid);
  if (!detached)
    std::cout << "    [!] Could not resume target after injection\n";
  bool success = ok && detached;
  std::cout << (success ? "=== DONE ===\n" : "=== FAILED ===\n");
  return success;
}

bool cmd_scan(const std::string &pkg, const std::string &pattern) {
  std::cout << "\n=== HAYABUSA PATTERN SCAN ===\n";
  std::cout << "Target: " << pkg << "\n";
  std::cout << "Pattern: " << pattern << "\n\n";

  auto emit = [](const std::string &msg) { std::cout << msg; };

  int pid = wait_for_process(pkg, emit, 0);
  if (pid < 0)
    return false;

  auto ranges = Memory::read_maps(pid);
  size_t pattern_bytes = 0;
  {
    std::istringstream tokens(pattern);
    std::string token;
    while (tokens >> token)
      pattern_bytes++;
  }
  if (pattern_bytes == 0) {
    std::cout << "[!] Pattern contains no bytes\n";
    return false;
  }

  size_t total_matches = 0;
  int mem_fd =
      open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
  if (mem_fd < 0) {
    std::cout << "[!] Cannot open target memory: " << strerror(errno) << "\n";
    return false;
  }

  for (const auto &r : ranges) {
    if (!r.readable() || r.name.empty())
      continue;
    if (r.name.find(".so") == std::string::npos &&
        r.name.find(".dex") == std::string::npos &&
        r.name.find(".odex") == std::string::npos &&
        r.name.find(".vdex") == std::string::npos &&
        r.name.find(".apk") == std::string::npos &&
        r.name.find(".jar") == std::string::npos &&
        r.name.find(".oat") == std::string::npos &&
        r.name.find(".art") == std::string::npos)
      continue;

    const size_t region_size = r.size();
    if (region_size == 0)
      continue;

    // 16 MiB is only the working-set chunk, never a mapping-size limit.  The
    // previous code silently skipped every mapping larger than 64 MiB, which
    // is common for game OAT/DEX containers.  Re-read an overlap so a pattern
    // crossing a chunk boundary is still found, and emit only matches not
    // wholly covered by the preceding chunk.
    constexpr size_t kScanChunkBytes = 16U * 1024U * 1024U;
    const size_t overlap = pattern_bytes > 0 ? pattern_bytes - 1 : 0;
    size_t cursor = 0;
    size_t map_matches = 0;
    std::string lib = r.name;
    size_t slash = lib.rfind('/');
    if (slash != std::string::npos)
      lib = lib.substr(slash + 1);
    while (cursor < region_size) {
      const size_t read_start = cursor > overlap ? cursor - overlap : 0;
      const size_t read_end = std::min(
          region_size, cursor + std::min(kScanChunkBytes,
                                         region_size - cursor));
      const size_t span = read_end - read_start;
      std::vector<uint8_t> mem(span);
      if (!read_exact(mem_fd, mem.data(), span, r.start + read_start)) {
        cursor = read_end;
        continue;
      }

      for (const auto &m : ElfParser::pattern_scan(mem, pattern)) {
        if (m.offset > std::numeric_limits<size_t>::max() - read_start)
          continue;
        const size_t map_offset = read_start + static_cast<size_t>(m.offset);
        if (cursor != 0 && map_offset <= cursor &&
            pattern_bytes <= cursor - map_offset)
          continue;
        const uint64_t addr = r.start + map_offset;
        if (map_matches == 0)
          std::cout << "\n  [" << lib << "] matches:\n";
        std::cout << "    0x" << std::hex << addr << std::dec
                  << " offset=0x" << std::hex << map_offset << std::dec
                  << " map=" << r.perms << "\n";
        map_matches++;
        total_matches++;
      }
      cursor = read_end;
    }
    if (map_matches != 0)
      std::cout << "    map total: " << map_matches << " match(es)\n";
  }
  close(mem_fd);

  if (total_matches == 0)
    std::cout << "[!] No matches found\n";
  else
    std::cout << "\nTotal: " << total_matches << " match(es)\n";

  std::cout << "=== DONE ===\n";
  return total_matches > 0;
}

bool cmd_extract(const std::string &pkg, const std::string &func_name,
                 int max_depth, size_t max_total_size) {
  std::cout << "\n=== HAYABUSA FUNCTION EXTRACT ===\n";
  std::cout << "Target: " << pkg << "\n";
  std::cout << "Function: " << func_name << "\n";
  std::cout << "Max depth: " << max_depth << "\n";
  std::cout << "Size limit: " << (max_total_size / (1024 * 1024))
            << " MiB\n\n";

  auto emit = [](const std::string &msg) { std::cout << msg; };

  int pid = wait_for_process(pkg, emit, 0);
  if (pid < 0 || !attach_and_prepare(pid, emit))
    return false;

  std::cout << "[5] Searching for function '" << func_name << "'...\n";
  std::string found_lib;
  uint64_t func_addr = find_symbol_in_process(pid, func_name, &found_lib);

  if (func_addr == 0) {
    std::cout << "[!] Function '" << func_name << "' not found\n";
    ProcessTracer::detach(pid);
    return false;
  }

  std::cout << "    Found at 0x" << std::hex << func_addr << std::dec << " in "
            << found_lib << "\n";

  std::cout << "[6] Extracting function with dependencies (depth=" << max_depth
            << ")...\n";
  auto result =
      StaticRelinkerEx::extract_function_with_deps(pid, func_addr, max_depth,
                                                   max_total_size);

  if (result.empty()) {
    std::cout << "[!] Extraction failed\n";
    ProcessTracer::detach(pid);
    return false;
  }

  SecureRunDirectory output =
      SecureRunDirectory::create(g_output_root, "hayabusa_extract");
  if (!output) {
    std::cout << "    [!] " << output.error() << "\n";
    ProcessTracer::detach(pid);
    return false;
  }
  const std::string leaf = safe_path_component(func_name) + ".bin";
  const std::string out_path = output.io_path() + "/" + leaf;
  const std::string out_display = output.display_path() + "/" + leaf;
  std::ofstream out(out_path, std::ios::binary);
  if (out)
    out.write(reinterpret_cast<const char *>(result.data()), result.size());
  bool wrote = static_cast<bool>(out);
  out.close();

  if (wrote)
    std::cout << "    [+] Extracted " << result.size() << " bytes to "
              << out_display << "\n";
  else
    std::cout << "    [!] Could not write " << out_display << "\n";

  bool detached = ProcessTracer::detach(pid);
  if (!detached)
    std::cout << "    [!] Could not resume target after extraction\n";
  bool ok = wrote && detached;
  std::cout << (ok ? "=== DONE ===\n" : "=== FAILED ===\n");
  return ok;
}

struct Candidate {
  uint64_t base;
  // Actual address of the offset-zero mapping. For ELF, `base` is the load
  // bias and can be lower when the first PT_LOAD has a non-zero p_vaddr.
  uint64_t mapping_start = 0;
  uint64_t mapping_end = 0;
  uint64_t mapped_span = 0;
  uint64_t captured_size = 0;
  CandidateKind kind = CandidateKind::Unknown;
  std::string name;
  std::string display_name;
  std::string safe_name;
  std::string raw_path;
  std::string raw_display_path;
  std::string disk_snapshot_path;
  std::string disk_snapshot_display_path;
  // For an ELF mapped directly from a stored APK entry, name remains the APK
  // backing path while display_name is the recovered DT_SONAME. The entry's
  // first byte is exactly this page-aligned backing-file offset.
  bool embedded_elf = false;
  uint64_t backing_file_offset = 0;
  // ZIP/VDEX are reconstructed by file offset from this one coherent mmap
  // view while the process is stopped.
  std::vector<MapEntry> file_mappings;
  // Indices into RuntimeMemorySnapshot::writable_modules that belong to this
  // exact load-bias instance. Same-path linker namespaces must not share BSS.
  std::vector<size_t> writable_snapshot_indices;
  bool captured = false;
  bool relink_attempted = false;
  bool relink_succeeded = false;
  size_t relink_size = 0;
  uint64_t relink_hash = 0;
  std::vector<uint8_t> relink_preview;
};

std::string make_display_name(const std::string &name) {
  if (name.find('/') != std::string::npos)
    return name.substr(name.rfind('/') + 1);
  return name;
}

std::string make_safe_name(const std::string &name) {
  return safe_path_component(name);
}

std::string make_raw_dump_path(const std::string &raw_dir,
                               const std::string &source_name, uint64_t start,
                               uint64_t offset, bool include_offset) {
  std::string display = make_display_name(source_name);
  std::string stem = display;
  std::string ext;

  size_t so_pos = display.find(".so");
  if (so_pos != std::string::npos) {
    stem = display.substr(0, so_pos);
    ext = display.substr(so_pos);
  } else {
    size_t dot = display.rfind('.');
    if (dot != std::string::npos && dot > 0) {
      stem = display.substr(0, dot);
      ext = display.substr(dot);
    }
  }

  std::string safe_stem = make_safe_name(stem);
  // An executable commonly has no suffix. Sanitising an empty extension via
  // safe_path_component turns it into the literal word "unknown", so preserve
  // emptiness here and use the documented .raw fallback below.
  std::string safe_ext = ext.empty() ? std::string() : make_safe_name(ext);
  std::ostringstream ss;
  ss << raw_dir << "/" << safe_stem << "_0x" << std::hex << start;
  if (include_offset && offset != 0)
    ss << "_off0x" << offset;
  if (!safe_ext.empty())
    ss << safe_ext;
  else
    ss << ".raw";
  return ss.str();
}

static std::vector<MapEntry>
coherent_mapped_file_view(const std::vector<MapEntry> &regions,
                          const std::string &name, uint64_t base) {
  std::vector<MapEntry> result;
  for (const auto &mapping : regions) {
    if (!mapping.readable() || normalized_mapping_name(mapping.name) != name ||
        mapping.start < mapping.offset ||
        mapping.start - mapping.offset != base)
      continue;
    result.push_back(mapping);
  }
  std::sort(result.begin(), result.end(),
            [](const MapEntry &a, const MapEntry &b) {
              if (a.offset != b.offset)
                return a.offset < b.offset;
              return a.start < b.start;
            });
  return result;
}

static uint64_t
mapped_file_view_span(const std::vector<MapEntry> &file_mappings) {
  uint64_t covered = 0;
  for (const auto &mapping : file_mappings) {
    if (mapping.offset > covered ||
        mapping.size() >
            std::numeric_limits<uint64_t>::max() - mapping.offset)
      return 0;
    uint64_t end = mapping.offset + mapping.size();
    if (end > kMaxDalvikContainerSize)
      return 0;
    covered = std::max(covered, end);
  }
  return covered;
}

static bool
read_mapped_file_view(int mem_fd, const std::vector<MapEntry> &file_mappings,
                      uint64_t span, std::vector<uint8_t> &out) {
  if (span == 0 || span > kMaxDalvikContainerSize ||
      span > std::numeric_limits<size_t>::max())
    return false;
  out.assign(static_cast<size_t>(span), 0);
  uint64_t covered = 0;
  for (const auto &mapping : file_mappings) {
    if (mapping.offset > covered || mapping.offset >= span)
      break;
    size_t amount = static_cast<size_t>(
        std::min<uint64_t>(mapping.size(), span - mapping.offset));
    if (!read_exact(mem_fd, out.data() + static_cast<size_t>(mapping.offset),
                    amount, mapping.start)) {
      out.clear();
      return false;
    }
    covered = std::max<uint64_t>(covered, mapping.offset + amount);
  }
  if (covered != span) {
    out.clear();
    return false;
  }
  return true;
}

struct ExtractedDex {
  std::vector<uint8_t> data;
  std::string label;
  std::string origin;
  uint64_t container_offset = 0;
  uint64_t runtime_address = 0;
  std::string raw_path;
  std::string raw_display_path;
  std::string report_path;
  std::string report_display_path;
};

struct DexExtractionResult {
  bool container_ok = true;
  std::vector<ExtractedDex> dexes;
  std::vector<uint64_t> cdex_offsets;
  std::vector<std::string> issues;
};

static DexExtractionResult
extract_odex_dex(const std::vector<uint8_t> &container, uint64_t base) {
  DexExtractionResult result;
  uint32_t dex_offset = 0, dex_length = 0;
  uint64_t container_size = 0;
  std::string reason;
  if (!parse_odex_header(container.data(), container.size(), &dex_offset,
                         &dex_length, &container_size, &reason) ||
      container_size > container.size() ||
      dex_offset > container.size() ||
      dex_length > container.size() - dex_offset) {
    result.container_ok = false;
    result.issues.push_back(reason.empty() ? "ODEX sections exceed snapshot"
                                           : reason);
    return result;
  }
  DexValidation validation =
      validate_standard_dex(container.data() + dex_offset, dex_length);
  if (!validation.valid || validation.file_size != dex_length) {
    result.container_ok = false;
    result.issues.push_back(
        validation.valid ? "ODEX dexLength does not match DEX file_size"
                         : "ODEX embedded DEX rejected: " + validation.reason);
    return result;
  }
  ExtractedDex dex;
  dex.data.assign(container.begin() + dex_offset,
                  container.begin() + dex_offset + dex_length);
  dex.label = "odex";
  dex.origin = "ODEX dexOffset/dexLength";
  dex.container_offset = dex_offset;
  dex.runtime_address = base + dex_offset;
  result.dexes.push_back(std::move(dex));
  return result;
}

static DexExtractionResult
carve_standard_dex_from_vdex(const std::vector<uint8_t> &container,
                             uint64_t base) {
  DexExtractionResult result;
  if (container.size() < 8 || memcmp(container.data(), "vdex", 4) != 0) {
    result.container_ok = false;
    result.issues.push_back("invalid VDEX magic");
    return result;
  }

  size_t scan_begin = 8;
  size_t scan_end = container.size();
  std::vector<uint32_t> expected_checksums;
  if (memcmp(container.data() + 4, "027\0", 4) == 0) {
    // Android 12/13 VDEX: 12-byte header followed by four explicit, absolute
    // section descriptors {kind, offset, size}. Refuse a padding-only fake
    // header and only carve inside the declared DexFile section.
    if (container.size() < 60 || read_le32(container.data() + 8) != 4) {
      result.container_ok = false;
      result.issues.push_back("invalid VDEX027 section count/header");
      return result;
    }
    struct Section {
      uint32_t kind;
      uint32_t offset;
      uint32_t size;
    };
    Section sections[4]{};
    std::vector<std::pair<uint64_t, uint64_t>> occupied;
    for (size_t i = 0; i < 4; i++) {
      const uint8_t *entry = container.data() + 12 + i * 12;
      sections[i] = {read_le32(entry), read_le32(entry + 4),
                     read_le32(entry + 8)};
      if (sections[i].kind != i || sections[i].offset > container.size() ||
          sections[i].size > container.size() - sections[i].offset ||
          (sections[i].size != 0 && sections[i].offset < 60)) {
        result.container_ok = false;
        result.issues.push_back("invalid VDEX027 section kind/range");
        return result;
      }
      if (sections[i].size != 0)
        occupied.push_back(
            {sections[i].offset, uint64_t(sections[i].offset) +
                                     sections[i].size});
    }
    std::sort(occupied.begin(), occupied.end());
    for (size_t i = 1; i < occupied.size(); i++) {
      if (occupied[i].first < occupied[i - 1].second) {
        result.container_ok = false;
        result.issues.push_back("overlapping VDEX027 sections");
        return result;
      }
    }
    if ((sections[0].size & 3) != 0 || sections[1].size == 0) {
      result.container_ok = false;
      result.issues.push_back("invalid VDEX027 checksum/DEX section size");
      return result;
    }
    for (uint32_t off = 0; off < sections[0].size; off += 4)
      expected_checksums.push_back(
          read_le32(container.data() + sections[0].offset + off));
    scan_begin = sections[1].offset;
    scan_end = scan_begin + sections[1].size;
  }

  size_t next_label = 1;
  for (size_t off = scan_begin; off + 8 <= scan_end;) {
    const uint8_t *at = container.data() + off;
    if (versioned_magic(at, scan_end - off, "dex\n")) {
      DexValidation validation = validate_standard_dex(at, scan_end - off);
      if (validation.valid) {
        ExtractedDex dex;
        dex.data.assign(container.begin() + static_cast<ptrdiff_t>(off),
                        container.begin() +
                            static_cast<ptrdiff_t>(off + validation.file_size));
        dex.label =
            next_label == 1 ? "classes" : "classes" + std::to_string(next_label);
        dex.origin = "validated standard DEX carved from VDEX";
        dex.container_offset = off;
        dex.runtime_address = base + off;
        result.dexes.push_back(std::move(dex));
        next_label++;
        off += validation.file_size;
        if (result.dexes.size() >= 1024) {
          result.issues.push_back("VDEX DEX count hit the safety limit");
          break;
        }
        continue;
      }
    } else if (versioned_magic(at, scan_end - off, "cdex")) {
      uint32_t cdex_size = 0;
      if (parse_cdex_header(at, scan_end - off, &cdex_size) &&
          cdex_size <= scan_end - off) {
        result.cdex_offsets.push_back(off);
        off += cdex_size;
        continue;
      }
    }
    off++;
  }
  if (!expected_checksums.empty() && !result.dexes.empty()) {
    if (expected_checksums.size() != result.dexes.size()) {
      result.container_ok = false;
      result.issues.push_back(
          "VDEX027 checksum count does not match standard DEX count");
      result.dexes.clear();
    } else {
      for (size_t i = 0; i < result.dexes.size(); i++) {
        if (read_le32(result.dexes[i].data.data() + 8) !=
            expected_checksums[i]) {
          result.container_ok = false;
          result.issues.push_back("VDEX027 DEX checksum mismatch");
          result.dexes.clear();
          break;
        }
      }
    }
  }
  if (result.dexes.empty())
    result.issues.push_back("no validated standard DEX payload found");
  if (!result.cdex_offsets.empty())
    result.issues.push_back(
        "CDEX payload(s) recognized but not sent to the standard DEX parser");
  return result;
}

static bool zip_multidex_entry_name(const std::string &name,
                                    std::string *label) {
  if (name == "classes.dex") {
    *label = "classes";
    return true;
  }
  static constexpr char prefix[] = "classes";
  static constexpr char suffix[] = ".dex";
  if (name.size() <= sizeof(prefix) - 1 + sizeof(suffix) - 1 ||
      name.compare(0, sizeof(prefix) - 1, prefix) != 0 ||
      name.compare(name.size() - (sizeof(suffix) - 1), sizeof(suffix) - 1,
                   suffix) != 0)
    return false;
  size_t begin = sizeof(prefix) - 1;
  size_t end = name.size() - (sizeof(suffix) - 1);
  if (name[begin] < '2' || name[begin] > '9')
    return false;
  for (size_t i = begin + 1; i < end; i++)
    if (name[i] < '0' || name[i] > '9')
      return false;
  *label = name.substr(0, end);
  return true;
}

static DexExtractionResult
extract_zip_multidex(const std::vector<uint8_t> &container) {
  DexExtractionResult result;
  result.container_ok = false;
  HayabusaZipError error{};
  zip_error_init(&error);
  HayabusaZipSource *source =
      zip_source_buffer_create(container.data(), container.size(), 0, &error);
  if (!source) {
    result.issues.push_back(std::string("libzip memory source failed: ") +
                            zip_error_strerror(&error));
    zip_error_fini(&error);
    return result;
  }
  // ZIP_RDONLY from libzip's public ABI. The source is owned by the archive
  // after a successful open and still owned by us after a failed one.
  HayabusaZip *archive = zip_open_from_source(source, 16, &error);
  if (!archive) {
    result.issues.push_back(std::string("libzip rejected snapshot: ") +
                            zip_error_strerror(&error));
    zip_source_free(source);
    zip_error_fini(&error);
    return result;
  }
  result.container_ok = true;

  int64_t count = zip_get_num_entries(archive, 0);
  if (count < 0 || count > 1000000) {
    result.container_ok = false;
    result.issues.push_back("ZIP entry count is invalid or exceeds safety cap");
  } else {
    std::set<std::string> labels;
    size_t multidex_entries = 0;
    uint64_t aggregate_uncompressed = 0;
    for (int64_t index = 0; index < count; index++) {
      const char *raw_name =
          zip_get_name(archive, static_cast<uint64_t>(index), 0);
      if (!raw_name)
        continue;
      std::string entry_name(raw_name);
      std::string label;
      if (!zip_multidex_entry_name(entry_name, &label))
        continue;
      if (++multidex_entries > 64) {
        result.container_ok = false;
        result.issues.push_back(
            "ZIP classes*.dex count exceeds the 64-entry safety cap");
        break;
      }
      if (!labels.insert(label).second)
        label += "_entry" + std::to_string(index);

      HayabusaZipFile *file =
          zip_fopen_index(archive, static_cast<uint64_t>(index), 0);
      if (!file) {
        result.issues.push_back(
            "could not open ZIP entry " + entry_name +
            " (encrypted or unsupported entries are not extracted)");
        continue;
      }
      std::vector<uint8_t> bytes;
      std::vector<uint8_t> chunk(64 * 1024);
      bool read_ok = true;
      for (;;) {
        int64_t amount = zip_fread(file, chunk.data(), chunk.size());
        if (amount < 0) {
          read_ok = false;
          result.issues.push_back("ZIP read/CRC/decompression failure for " +
                                  entry_name);
          break;
        }
        if (amount == 0)
          break;
        uint64_t unsigned_amount = static_cast<uint64_t>(amount);
        if (unsigned_amount >
                kMaxDexSize -
                    std::min<uint64_t>(bytes.size(), kMaxDexSize) ||
            unsigned_amount >
                kMaxDalvikContainerSize -
                    std::min<uint64_t>(aggregate_uncompressed,
                                       kMaxDalvikContainerSize)) {
          read_ok = false;
          result.container_ok = false;
          result.issues.push_back(
              "ZIP multidex data exceeds per-entry or 512 MiB aggregate cap");
          break;
        }
        aggregate_uncompressed += unsigned_amount;
        bytes.insert(bytes.end(), chunk.begin(), chunk.begin() + amount);
      }
      int close_status = zip_fclose(file);
      if (!read_ok || close_status != 0) {
        if (read_ok)
          result.issues.push_back("ZIP CRC/decompression failure for " +
                                  entry_name);
        continue;
      }

      DexValidation validation =
          validate_standard_dex(bytes.data(), bytes.size());
      if (!validation.valid || validation.file_size != bytes.size()) {
        result.issues.push_back(
            "ZIP entry " + entry_name + " rejected: " +
            (validation.valid ? "entry size differs from DEX file_size"
                              : validation.reason));
        continue;
      }
      ExtractedDex dex;
      dex.data = std::move(bytes);
      dex.label = std::move(label);
      dex.origin = "libzip memory entry " + entry_name;
      result.dexes.push_back(std::move(dex));
    }
  }
  zip_discard(archive);
  zip_error_fini(&error);
  if (result.dexes.empty())
    result.issues.push_back("no validated classes*.dex ZIP entry found");
  return result;
}

static bool write_binary_snapshot(const std::string &path,
                                  const std::vector<uint8_t> &data) {
  std::ofstream file(path, std::ios::binary);
  if (!file)
    return false;
  file.write(reinterpret_cast<const char *>(data.data()), data.size());
  file.close();
  return static_cast<bool>(file);
}

static std::string extracted_dex_stem(const Candidate &candidate,
                                      const std::string &directory,
                                      int snapshot,
                                      const std::string &label) {
  std::ostringstream path;
  path << directory << "/" << candidate.safe_name << "_0x" << std::hex
       << candidate.base << std::dec << "_s" << snapshot << "_" << label;
  return path.str();
}

static bool mapped_elf_layout(int mem_fd, uint64_t header_address,
                              uint64_t maximum, uint64_t *load_bias,
                              uint64_t *mapped_span) {
  if (maximum == 0)
    maximum = std::numeric_limits<uint64_t>::max();
  if (!load_bias || !mapped_span)
    return false;
  *load_bias = 0;
  *mapped_span = 0;
  Elf64ProgramHeaders program_headers;
  return read_remote_elf64_program_headers(
      mem_fd, header_address, maximum, &program_headers, load_bias,
      mapped_span);
}

static bool capture_exact_backing_file(int pid, const Candidate &candidate,
                                       const std::string &path,
                                       uint64_t maximum) {
  std::ostringstream map_file;
  map_file << "/proc/" << pid << "/map_files/" << std::hex
           << candidate.mapping_start
           << "-" << candidate.mapping_end;
  int fd = open(map_file.str().c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return false;

  struct stat st {};
  if (fstat(fd, &st) != 0 || st.st_size <= 0) {
    close(fd);
    return false;
  }

  // Some Android procfs implementations expose map_files through a view whose
  // apparent size ends at the last mapped PT_LOAD byte.  That omits the ELF
  // section table. Prefer the process-root path only after proving that it is
  // the exact same inode as the stopped mapping; a pathname alone is not a
  // safe baseline because it can be replaced concurrently.
  std::string backing_name = normalized_mapping_name(candidate.name);
  if (!backing_name.empty() && backing_name.front() == '/') {
    const std::string rooted =
        "/proc/" + std::to_string(pid) + "/root" + backing_name;
    int rooted_fd = open(rooted.c_str(), O_RDONLY | O_CLOEXEC);
    if (rooted_fd >= 0) {
      struct stat rooted_st {};
      if (fstat(rooted_fd, &rooted_st) == 0 && rooted_st.st_size > 0 &&
          rooted_st.st_dev == st.st_dev && rooted_st.st_ino == st.st_ino) {
        close(fd);
        fd = rooted_fd;
        st = rooted_st;
      } else {
        close(rooted_fd);
      }
    }
  }
  const uint64_t source_offset =
      candidate.embedded_elf ? candidate.backing_file_offset : 0;
  const uint64_t file_size = static_cast<uint64_t>(st.st_size);
  uint64_t wanted = candidate.embedded_elf ? candidate.captured_size
                                            : file_size;
  if (candidate.embedded_elf) {
    // PT_LOAD ends before the section-header table in ordinary Android .so
    // files.  The runtime mapping cannot supply that tail, but the exact APK
    // backing inode can.  Derive the complete entry extent from its own ELF
    // metadata rather than copying the following ZIP entry.
    Elf64_Ehdr eh{};
    if (source_offset > file_size || sizeof(eh) > file_size - source_offset ||
        pread(fd, &eh, sizeof(eh), source_offset) !=
            static_cast<ssize_t>(sizeof(eh)) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_ehsize != sizeof(Elf64_Ehdr)) {
      close(fd);
      return false;
    }
    if (eh.e_shoff != 0) {
      if (eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_shnum == 0 ||
          eh.e_shoff > file_size - source_offset ||
          eh.e_shnum > (file_size - source_offset - eh.e_shoff) /
                           sizeof(Elf64_Shdr)) {
        close(fd);
        return false;
      }
      const uint64_t table_bytes =
          uint64_t(eh.e_shnum) * sizeof(Elf64_Shdr);
      std::vector<Elf64_Shdr> sections(eh.e_shnum);
      if (pread(fd, sections.data(), static_cast<size_t>(table_bytes),
                source_offset + eh.e_shoff) !=
          static_cast<ssize_t>(table_bytes)) {
        close(fd);
        return false;
      }
      uint64_t complete_size = eh.e_shoff + table_bytes;
      for (const auto &section : sections) {
        if (section.sh_type == SHT_NOBITS || section.sh_size == 0)
          continue;
        if (section.sh_offset > file_size - source_offset ||
            section.sh_size >
                file_size - source_offset - section.sh_offset) {
          close(fd);
          return false;
        }
        complete_size =
            std::max<uint64_t>(complete_size,
                               section.sh_offset + section.sh_size);
      }
      wanted = std::max(wanted, complete_size);
    }
  }
  if (source_offset > file_size || wanted == 0 ||
      wanted > file_size - source_offset ||
      (maximum != 0 && wanted > maximum) ||
      wanted > std::numeric_limits<size_t>::max()) {
    close(fd);
    return false;
  }

  std::ofstream out(path, std::ios::binary);
  if (!out) {
    close(fd);
    return false;
  }
  std::vector<uint8_t> chunk(
      static_cast<size_t>(std::min<uint64_t>(wanted, 1024 * 1024)));
  uint64_t done = 0;
  while (done < wanted) {
    size_t amount =
        static_cast<size_t>(std::min<uint64_t>(chunk.size(), wanted - done));
    ssize_t rd = pread(fd, chunk.data(), amount, source_offset + done);
    if (rd != static_cast<ssize_t>(amount)) {
      close(fd);
      out.close();
      unlink(path.c_str());
      return false;
    }
    out.write(reinterpret_cast<const char *>(chunk.data()), amount);
    if (!out) {
      close(fd);
      out.close();
      unlink(path.c_str());
      return false;
    }
    done += amount;
  }
  close(fd);
  out.close();
  return static_cast<bool>(out);
}


// Runtime-decrypted payloads routinely live outside any mapped module -- an
// unpacker constructor writes plaintext to the heap, or JITs code into an
// anonymous RWX page. The ELF-module pass cannot see any of it, so anonymous
// and heap regions get their own sweep.
// Cross-region name recovery: a registration table built at runtime lives on
// the heap while the functions it names live in a module. That is structurally
// the same split as global-metadata.dat versus libil2cpp.so, so the join has to
// span regions -- running it per-module finds nothing.
static size_t recover_names_across_regions(
    const std::vector<MemoryRegionSnapshot> &regions,
    const std::set<uint64_t> &func_addrs, std::ostream &out, size_t limit) {
  if (func_addrs.empty() || regions.empty())
    return 0;

  // Android tags heap pointers in the top byte; mask it before resolving.
  auto untag = [](uint64_t v) { return v & 0x00FFFFFFFFFFFFFFULL; };
  auto resolve = [&](uint64_t raw, const uint8_t **p,
                     size_t *avail) -> bool {
    uint64_t addr = untag(raw);
    for (const auto &r : regions) {
      if (addr >= r.mapping.start &&
          addr < r.mapping.start + r.data.size()) {
        *p = r.data.data() + (addr - r.mapping.start);
        *avail = size_t(r.mapping.start + r.data.size() - addr);
        return true;
      }
    }
    return false;
  };
  auto read_str = [&](uint64_t addr, std::string *s) {
    const uint8_t *p;
    size_t avail;
    if (!resolve(addr, &p, &avail))
      return false;
    s->clear();
    for (size_t i = 0; i < avail && i < 128; i++) {
      uint8_t c = p[i];
      if (c == 0)
        return s->size() >= 2;
      if (c < 0x20 || c > 0x7E)
        return false;
      s->push_back(char(c));
    }
    return false;
  };
  auto is_ident = [](const std::string &s) {
    if (s.size() < 2)
      return false;
    for (unsigned char c : s)
      if (!isalnum(c) && c != '_' && c != '$' && c != '.' && c != '/')
        return false;
    return isalpha((unsigned char)s[0]) || s[0] == '_';
  };
  auto is_sig = [](const std::string &s) {
    return s.size() >= 3 && s[0] == '(' &&
           s.find(')') != std::string::npos;
  };

  size_t found = 0, diag = 0;
  std::set<uint64_t> claimed;
  for (const auto &r : regions) {
    const uint8_t *d = r.data.data();
    size_t n = r.data.size();
    for (size_t off = 0; off + 24 <= n; off += 8) {
      uint64_t p0, p1, p2;
      memcpy(&p0, d + off, 8);
      memcpy(&p1, d + off + 8, 8);
      memcpy(&p2, d + off + 16, 8);
      std::string name, sig;
      if (!read_str(p0, &name) || !is_ident(name))
        continue;
      if (!read_str(p1, &sig) || !is_sig(sig))
        continue;
      uint64_t fn = untag(p2) & ~uint64_t(1);
      if (!func_addrs.count(fn)) {
        if (diag < 5) {
          out << "  [unmatched] " << name << sig << " fn=0x" << std::hex << fn
              << std::dec << "\n";
          diag++;
        }
        continue;
      }
      if (!claimed.insert(fn).second)
        continue;
      if (found == 0)
        out << "\n=== RUNTIME REGISTRATION TABLES ===\n"
            << "Name/function bindings assembled in memory (heap tables whose\n"
               "code pointers land in a dumped module).\n";
      if (found < limit)
        out << "0x" << std::hex << fn << std::dec << " " << name << sig
            << "  [JNINativeMethod @ 0x" << std::hex
            << (r.mapping.start + off)
            << std::dec << "]\n";
      found++;
    }
  }
  if (found > limit)
    out << "... (" << (found - limit) << " more)\n";
  return found;
}

static bool is_runtime_anonymous_region(const MapEntry &m) {
  if (!m.readable())
    return false;
  if (m.name.empty())
    return true;
  return m.name.rfind("[anon", 0) == 0 || m.name == "[heap]" ||
         m.name == "[stack]" || m.name.rfind("/memfd:", 0) == 0 ||
         m.name.rfind("memfd:", 0) == 0;
}

static bool exceeds_policy_limit(uint64_t value, uint64_t limit) {
  return limit != 0 && value > limit;
}

// Copy anonymous bytes before any expensive Rizin work. Runtime-only
// containers are often short-lived; deferring the read until all named modules
// have been analysed can lose them even though their mapping was present at the
// start of the snapshot.
static std::vector<MemoryRegionSnapshot>
capture_anonymous_regions(const std::vector<MapEntry> &maps, int mem_fd,
                          uint64_t memory_limit, bool *truncated) {
  if (truncated)
    *truncated = false;

  std::vector<MapEntry> groups;
  // This is an allocation/read granularity, not a capture limit. Splitting a
  // 1 GiB Dalvik arena into bounded pieces avoids a single fatal allocation;
  // every byte remains eligible until the user-selected aggregate budget is
  // reached.
  constexpr uint64_t kCaptureChunkBytes = 64ull * 1024 * 1024;
  for (const auto &m : maps) {
    if (!is_runtime_anonymous_region(m) || m.size() == 0)
      continue;
    uint64_t cursor = m.start;
    while (cursor < m.end) {
      const uint64_t amount =
          std::min<uint64_t>(kCaptureChunkBytes, m.end - cursor);
      MapEntry part = m;
      part.start = cursor;
      part.end = cursor + amount;
      if (m.offset <= std::numeric_limits<uint64_t>::max() -
                          (cursor - m.start))
        part.offset = m.offset + (cursor - m.start);

      const uint64_t previous_size =
          groups.empty() ? 0 : static_cast<uint64_t>(groups.back().size());
      const bool merge_fits =
          previous_size <= kCaptureChunkBytes - amount;
      if (!groups.empty() && groups.back().end == part.start && merge_fits) {
        // mprotect commonly splits one allocation. Merge neighbouring pieces
        // up to the working chunk size so a container crossing the protection
        // boundary stays visible to the scanner.
        groups.back().end = part.end;
        if (groups.back().name != part.name)
          groups.back().name = "[anonymous merged mappings]";
        if (part.perms.find('x') != std::string::npos &&
            groups.back().perms.find('x') == std::string::npos)
          groups.back().perms += "x";
      } else {
        groups.push_back(std::move(part));
      }
      cursor += amount;
    }
  }

  auto priority = [](const MapEntry &m) {
    int score = 0;
    if (m.name.find("memfd:") != std::string::npos)
      score -= 8;
    if (m.name.rfind("[anon", 0) == 0 || m.name.empty())
      score -= 4;
    if (m.perms.find('x') != std::string::npos)
      score -= 2;
    if (m.name == "[heap]" || m.name == "[stack]")
      score += 4;
    return score;
  };
  std::stable_sort(groups.begin(), groups.end(), [&](const MapEntry &a,
                                                      const MapEntry &b) {
    int pa = priority(a), pb = priority(b);
    return pa != pb ? pa < pb : a.size() < b.size();
  });

  uint64_t total = 0;
  std::vector<MemoryRegionSnapshot> snapshots;
  for (const auto &m : groups) {
    size_t size = m.size();
    if (total > std::numeric_limits<uint64_t>::max() - size ||
        exceeds_policy_limit(total + size, memory_limit)) {
      if (truncated)
        *truncated = true;
      continue;
    }
    total += size;
    std::vector<uint8_t> data(size);
    if (!read_exact(mem_fd, data.data(), size, m.start)) {
      if (truncated)
        *truncated = true;
      continue;
    }
    if (std::all_of(data.begin(), data.end(),
                    [](uint8_t b) { return b == 0; }))
      continue;
    snapshots.push_back({m, std::move(data)});
  }
  return snapshots;
}

static std::vector<MemoryRegionSnapshot> capture_writable_module_regions(
    const std::vector<MapEntry> &maps, int mem_fd,
    const std::set<std::string> &module_names, uint64_t memory_limit,
    bool *truncated) {
  if (truncated)
    *truncated = false;
  uint64_t total = 0;
  std::vector<MemoryRegionSnapshot> result;
  constexpr uint64_t kCaptureChunkBytes = 64ull * 1024 * 1024;
  for (const auto &m : maps) {
    if (!m.readable() || !m.writable() || m.size() == 0 ||
        !module_names.count(normalized_mapping_name(m.name)))
      continue;
    uint64_t cursor = m.start;
    while (cursor < m.end) {
      const uint64_t amount =
          std::min<uint64_t>(kCaptureChunkBytes, m.end - cursor);
      if (total > std::numeric_limits<uint64_t>::max() - amount ||
          exceeds_policy_limit(total + amount, memory_limit)) {
        if (truncated)
          *truncated = true;
        break;
      }
      MapEntry part = m;
      part.start = cursor;
      part.end = cursor + amount;
      if (m.offset <= std::numeric_limits<uint64_t>::max() -
                          (cursor - m.start))
        part.offset = m.offset + (cursor - m.start);
      std::vector<uint8_t> data(static_cast<size_t>(amount));
      total += amount;
      if (!read_exact(mem_fd, data.data(), data.size(), cursor)) {
        if (truncated)
          *truncated = true;
      } else {
        result.push_back({std::move(part), std::move(data)});
      }
      cursor += amount;
    }
  }
  return result;
}

struct AnonymousDumpResult {
  int regions = 0;
  bool artifacts_ok = false;
};

static AnonymousDumpResult dump_anonymous_regions(
    const std::string &out, const std::string &out_display,
    const std::string &raw_dir, const std::string &raw_display_dir,
    int snapshot,
    const std::set<uint64_t> &func_addrs,
    const AnalysisOptions &analysis, std::mutex *runtime_mutex, size_t limit,
    uint64_t image_limit, const RuntimeMemorySnapshot &runtime_snapshot,
    bool *analysis_incomplete) {
  if (analysis_incomplete)
    *analysis_incomplete = false;
  const auto &snapshots = runtime_snapshot.anonymous;
  std::ofstream report(out + "/anonymous_memory_s" +
                       std::to_string(snapshot) + ".txt");
  if (!report)
    return {};
  report << "=== ANONYMOUS / HEAP MEMORY ===\n";
  report << "Regions not backed by any mapped module.\n";
  if (runtime_snapshot.anonymous_truncated)
    report << "[!] INCOMPLETE SNAPSHOT: anonymous capture budget or read "
              "failure omitted at least one region.\n";
  if (runtime_snapshot.writable_truncated)
    report << "[!] INCOMPLETE SNAPSHOT: writable module capture budget or "
              "read failure omitted at least one region.\n";

  size_t total = 0;
  int dumped = 0;
  size_t embedded_dex = 0, embedded_elf = 0;
  bool artifacts_ok = true;
  size_t string_results_remaining = limit;
  size_t string_bytes_remaining = analysis.string_bytes;
  size_t decrypt_input_remaining = analysis.deobf_input_bytes;
  size_t decrypt_probes_remaining = analysis.deobf_probes;
  size_t decrypt_candidates_remaining = analysis.deobf_candidates;
  size_t decrypt_results_remaining = limit;
  const auto decrypt_deadline =
      analysis.deobf_timeout_ms == 0
          ? std::chrono::steady_clock::time_point::max()
          : std::chrono::steady_clock::now() +
                std::chrono::milliseconds(analysis.deobf_timeout_ms);

  auto analyze_runtime_dex = [&](const std::vector<uint8_t> &region,
                                 uint64_t region_base, size_t off) -> size_t {
    if (off + kDexHeaderSize > region.size() || embedded_dex >= limit)
      return 0;
    const uint8_t *h = region.data() + off;
    DexValidation validation =
        validate_standard_dex(h, region.size() - off);
    if (!validation.valid)
      return 0;
    uint32_t file_size = validation.file_size;

    std::vector<uint8_t> dex(region.begin() + static_cast<ptrdiff_t>(off),
                             region.begin() +
                                 static_cast<ptrdiff_t>(off + file_size));
    uint64_t address = region_base + off;
    std::ostringstream stem;
    stem << "anon_dex_0x" << std::hex << address << std::dec << "_s"
         << snapshot;
    std::string raw_path = raw_dir + "/" + stem.str() + ".dex";
    const std::string raw_display_path =
        raw_display_dir + "/" + stem.str() + ".dex";
    if (!write_binary_snapshot(raw_path, dex)) {
      artifacts_ok = false;
      return file_size;
    }
    std::string report_path = out + "/" + stem.str() + ".txt";
    const std::string report_display_path =
        out_display + "/" + stem.str() + ".txt";
    bool report_ok = false;
    {
      std::lock_guard<std::mutex> engine_lock(g_rizin_engine_mu);
      struct SessionReset {
        ~SessionReset() { rzb::release_shared_image(); }
      } session_reset;
      bool partial = false;
      report_ok = analyze_dex_to_txt(dex, report_path, address,
                                     "[anonymous runtime DEX]", analysis,
                                     &partial);
      if (partial && analysis_incomplete)
        *analysis_incomplete = true;
    }
    if (!report_ok) {
      artifacts_ok = false;
      return file_size;
    }
    report << "[EMBEDDED DEX] raw=" << raw_display_path
           << " report=" << report_display_path << "\n";
    embedded_dex++;
    return file_size;
  };

  auto analyze_runtime_elf = [&](const std::vector<uint8_t> &region,
                                 uint64_t region_base, size_t off) -> size_t {
    if (off + sizeof(Elf64_Ehdr) > region.size() || embedded_elf >= limit)
      return 0;
    const size_t available = region.size() - off;
    Elf64ProgramHeaders program_headers;
    if (!parse_elf64_program_headers(region.data() + off, available,
                                     &program_headers) ||
        program_headers.header.e_machine != EM_AARCH64 ||
        program_headers.entries.size() > 1024)
      return 0;
    const uint64_t phdr_bytes =
        static_cast<uint64_t>(program_headers.header.e_phnum) *
        sizeof(Elf64_Phdr);
    uint64_t header_end = 0;
    if (program_headers.header.e_phoff >
        std::numeric_limits<uint64_t>::max() - phdr_bytes)
      return 0;
    header_end = program_headers.header.e_phoff + phdr_bytes;

    uint64_t header_vaddr = 0;
    bool have_header_load = false;
    uint64_t file_size = 0, mapped_span = 0;
    for (const auto &ph : program_headers.entries) {
      if (ph.p_type != PT_LOAD)
        continue;
      if (ph.p_offset == 0 && ph.p_filesz >= header_end) {
        if (have_header_load && header_vaddr != ph.p_vaddr)
          return 0;
        header_vaddr = ph.p_vaddr;
        have_header_load = true;
      }
      file_size = std::max<uint64_t>(
          file_size, uint64_t(ph.p_offset) + uint64_t(ph.p_filesz));
    }
    if (!have_header_load || file_size < sizeof(Elf64_Ehdr) ||
        exceeds_policy_limit(file_size, image_limit) ||
        file_size > std::numeric_limits<size_t>::max())
      return 0;

    for (const auto &ph : program_headers.entries) {
      if (ph.p_type != PT_LOAD || ph.p_memsz == 0)
        continue;
      if (ph.p_vaddr < header_vaddr ||
          ph.p_vaddr - header_vaddr >
              std::numeric_limits<uint64_t>::max() - ph.p_memsz)
        return 0;
      mapped_span =
          std::max<uint64_t>(mapped_span, static_cast<uint64_t>(ph.p_vaddr) -
                                              header_vaddr +
                                              static_cast<uint64_t>(ph.p_memsz));
    }
    if (mapped_span < sizeof(Elf64_Ehdr) || mapped_span > available)
      return 0;

    std::vector<uint8_t> elf(static_cast<size_t>(file_size), 0);
    for (const auto &ph : program_headers.entries) {
      if (ph.p_type != PT_LOAD || ph.p_filesz == 0 ||
          ph.p_offset >= elf.size())
        continue;
      uint64_t copy = std::min<uint64_t>(ph.p_filesz, elf.size() - ph.p_offset);
      if (ph.p_vaddr < header_vaddr)
        return 0;
      const uint64_t relative_src = ph.p_vaddr - header_vaddr;
      if (relative_src > available || copy > available - relative_src)
        return 0;
      const size_t src = off + static_cast<size_t>(relative_src);
      memcpy(elf.data() + ph.p_offset, region.data() + src, copy);
    }
    if (!ElfParser::is_elf(elf))
      return 0;
    const uint64_t header_address = region_base + off;
    if (header_address < header_vaddr)
      return 0;
    const uint64_t load_bias = header_address - header_vaddr;
    auto fixed = SoFixer::repair(elf, load_bias);
    if (!fixed.empty() && ElfParser::is_elf(fixed))
      elf.swap(fixed);

    std::ostringstream stem;
    stem << "anon_elf_0x" << std::hex << header_address << std::dec << "_s"
         << snapshot;
    std::string raw_path = raw_dir + "/" + stem.str() + "_fixed.so";
    const std::string raw_display_path =
        raw_display_dir + "/" + stem.str() + "_fixed.so";
    if (!write_binary_snapshot(raw_path, elf)) {
      artifacts_ok = false;
      return static_cast<size_t>(file_size);
    }
    std::string report_path = out + "/" + stem.str() + ".txt";
    const std::string report_display_path =
        out_display + "/" + stem.str() + ".txt";
    bool report_ok = false;
    {
      std::lock_guard<std::mutex> engine_lock(g_rizin_engine_mu);
      struct SessionReset {
        ~SessionReset() { rzb::release_shared_image(); }
      } session_reset;
      bool partial = false;
      report_ok = analyze_to_txt(
          elf, report_path, load_bias, "[anonymous runtime ELF]", &elf,
          nullptr, 0, runtime_mutex, &runtime_snapshot, nullptr, analysis,
          &partial);
      if (partial && analysis_incomplete)
        *analysis_incomplete = true;
    }
    if (!report_ok) {
      artifacts_ok = false;
      return static_cast<size_t>(mapped_span);
    }
    report << "[EMBEDDED ELF] raw=" << raw_display_path
           << " report=" << report_display_path << "\n";
    embedded_elf++;
    return static_cast<size_t>(mapped_span);
  };

  for (const auto &captured : snapshots) {
    const MapEntry &m = captured.mapping;
    const std::vector<uint8_t> &data = captured.data;
    size_t size = data.size();

    std::ostringstream path;
    path << raw_dir << "/anon_0x" << std::hex << m.start << std::dec << "_s"
         << snapshot << ".bin";
    std::ostringstream display_path;
    display_path << raw_display_dir << "/anon_0x" << std::hex << m.start
                 << std::dec << "_s" << snapshot << ".bin";
    bool region_written = write_binary_snapshot(path.str(), data);
    if (!region_written)
      artifacts_ok = false;

    report << "\n--- 0x" << std::hex << m.start << "-0x" << m.end << std::dec
           << " " << m.perms << " " << (m.name.empty() ? "[anon]" : m.name)
           << " (" << Utils::format_size(size) << ") -> "
           << display_path.str();
    if (!region_written)
      report << " [WRITE FAILED]";
    report << "\n";

    StringScanLimits string_limits;
    string_limits.max_results = string_results_remaining;
    string_limits.max_retained_bytes = string_bytes_remaining;
    StringScanStatus string_status;
    auto strings =
        ElfParser::get_strings(data, 8, string_limits, &string_status);
    string_results_remaining -=
        std::min(string_results_remaining, string_status.retained_results);
    string_bytes_remaining -=
        std::min(string_bytes_remaining, string_status.retained_bytes);
    if (!strings.empty()) {
      report << "  strings (matches=" << string_status.total_matches
             << ", retained=" << strings.size() << "):\n";
      for (const auto &st : strings) {
        report << "    0x" << std::hex << (m.start + st.offset) << std::dec
               << " " << st.value << "\n";
      }
    }
    if (string_status.truncated)
      report << "  strings truncated by aggregate result/byte budget\n";

    // Executable anonymous memory is a strong unpacked-code signal.
    if (m.perms.find('x') != std::string::npos) {
      report << "  [!] EXECUTABLE anonymous mapping (JIT or unpacked code)\n";
      if (ElfParser::is_elf(data))
        report << "  [!] contains an ELF header -- likely a loaded-from-memory "
                  "module\n";
    }

    std::vector<DecryptResult> dec;
    AutoDecryptStatus decrypt_status;
    if (analysis.deobf && decrypt_input_remaining != 0 &&
        decrypt_probes_remaining != 0 &&
        decrypt_candidates_remaining != 0 &&
        decrypt_results_remaining != 0) {
      const auto now = std::chrono::steady_clock::now();
      if (now < decrypt_deadline) {
        AutoDecryptLimits decrypt_limits;
        decrypt_limits.max_input_bytes = decrypt_input_remaining;
        decrypt_limits.max_probes = decrypt_probes_remaining;
        decrypt_limits.max_candidates = decrypt_candidates_remaining;
        decrypt_limits.max_results = decrypt_results_remaining;
        decrypt_limits.deadline_ms = static_cast<uint64_t>(
            std::max<int64_t>(1, std::chrono::duration_cast<
                                     std::chrono::milliseconds>(
                                     decrypt_deadline - now)
                                     .count()));
        dec = ElfParser::auto_decrypt_strings(data, decrypt_limits,
                                              &decrypt_status);
        decrypt_input_remaining -= std::min(decrypt_input_remaining,
                                            decrypt_status.input_bytes);
        decrypt_probes_remaining -= std::min(decrypt_probes_remaining,
                                             decrypt_status.probes);
        decrypt_candidates_remaining -=
            std::min(decrypt_candidates_remaining,
                     decrypt_status.candidates);
        decrypt_results_remaining -=
            std::min(decrypt_results_remaining,
                     decrypt_status.retained_results);
      } else {
        decrypt_status.deadline_reached = true;
      }
    } else if (analysis.deobf) {
      decrypt_status.candidate_limit_reached = true;
    }
    if (!dec.empty()) {
      report << "  decrypted candidates (" << dec.size() << "):\n";
      size_t shown = 0;
      for (const auto &d : dec) {
        std::string text;
        for (uint8_t b : d.decrypted) {
          if (b == 0)
            break;
          text.push_back((b >= 0x20 && b <= 0x7E) ? (char)b : '.');
          if (text.size() >= 160)
            break;
        }
        report << "    0x" << std::hex << (m.start + d.offset) << std::dec
               << " " << d.method << " " << text << "\n";
        if (++shown >= 200)
          break;
      }
    }
    if (analysis.deobf && decrypt_status.truncated())
      report << "  deobfuscation truncated by aggregate work/deadline budget\n";

    auto crypto = CryptoAnalyzer::scan_for_keys(data, m.start);
    if (!crypto.empty()) {
      report << "  runtime crypto material (" << crypto.size() << "):\n";
      size_t shown = 0;
      for (const auto &key : crypto) {
        report << "    0x" << std::hex << key.key_addr << std::dec << " "
               << key.algorithm << " conf=" << std::fixed
               << std::setprecision(2) << key.confidence << " " << key.source
               << "\n";
        if (!key.key_data.empty()) {
          size_t bytes = std::min<size_t>(key.key_data.size(), 64);
          report << "      " << hex_bytes(key.key_data.data(), bytes);
          if (bytes < key.key_data.size())
            report << " ... (" << key.key_data.size() << " bytes)";
          report << "\n";
        }
        if (++shown >= limit)
          break;
      }
    }

    // Search at byte granularity: InMemoryDexClassLoader and custom loaders do
    // not have to page-align a container inside their anonymous allocation.
    for (size_t off = 0; off + 4 <= data.size();) {
      size_t consumed = 0;
      if (memcmp(data.data() + off, "dex\n", 4) == 0)
        consumed = analyze_runtime_dex(data, m.start, off);
      else if (memcmp(data.data() + off, ELFMAG, SELFMAG) == 0)
        consumed = analyze_runtime_elf(data, m.start, off);
      off += consumed ? consumed : 1;
    }
    if (region_written) {
      total += size;
      dumped++;
    }
  }

  report << "\nKnown module function addresses for cross-region joins: "
         << func_addrs.size() << "\n";
  size_t n = recover_names_across_regions(snapshots, func_addrs, report, limit);
  if (n)
    report << "Total runtime-registered names: " << n << "\n";
  report << "\nRegions captured: " << dumped << " ("
         << Utils::format_size(total) << ")\n";
  report << "Embedded runtime containers: DEX=" << embedded_dex
         << " ELF=" << embedded_elf << "\n";
  report.close();
  return {dumped, artifacts_ok && static_cast<bool>(report)};
}

// How many workers to run when the user did not say.
//
// hardware_concurrency() reports the machine's CPUs, which is the wrong number
// whenever the process is confined -- an Android app in a restricted cpuset, a
// container with a cpu quota, or a shell pinned with taskset. sched_getaffinity
// reports what this process may actually run on, so it is tried first. Both are
// only advisory, hence the final floor of 1: returning 0 here would silently
// spawn no workers at all.
static size_t default_worker_threads() {
  cpu_set_t set;
  CPU_ZERO(&set);
  if (sched_getaffinity(0, sizeof(set), &set) == 0) {
    int n = CPU_COUNT(&set);
    if (n > 0)
      return static_cast<size_t>(n);
  }
  unsigned hc = std::thread::hardware_concurrency();
  return hc ? hc : 1;
}

// Tuning for one dump run. Defaults favour completeness; the flags exist
// because a real app maps 300+ modules and the deep string heuristics cost
// tens of seconds per multi-megabyte module.
struct DumpOptions {
  std::vector<std::string> priority_files;
  const RelinkConfig *relink_cfg = nullptr; // null: skip static relinking
  std::vector<std::string> only;            // substrings; empty means all
  AnalysisOptions analysis;
  CaptureLimits capture;
  bool require_complete = false;
  size_t threads = 0; // 0: decide from the CPUs this process may use
};

int dump_analysis(int pid, const std::string &out,
                  const std::string &out_display,
                  std::map<std::string, uint64_t> &raw_hash_by_key,
                  std::map<std::string, uint64_t> &module_hash_by_key,
                  const DumpOptions &opt, int snapshot,
                  size_t *matched_container_count, bool *partial_result,
                  std::set<std::string> *matched_only_patterns) {
  if (matched_container_count)
    *matched_container_count = 0;
  if (partial_result)
    *partial_result = false;
  const std::vector<std::string> &priority_files = opt.priority_files;
  const RelinkConfig *relink_cfg = opt.relink_cfg;
  size_t thread_count = opt.threads;
  ScopedProcessStop snapshot_stop(pid);
  if (!snapshot_stop.attached()) {
    std::cout << "    [!] Cannot stop every target thread; refusing an "
                 "incoherent live-memory dump\n";
    return -1;
  }
  auto regions = Memory::read_maps(pid);
  if (regions.empty()) {
    std::cout << "    [!] Target maps disappeared during snapshot\n";
    return -1;
  }

  int mem_fd =
      open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
  if (mem_fd < 0) {
    std::cout << "    [!] Cannot open /proc/" << pid
              << "/mem: " << strerror(errno) << "\n";
    if (errno == EACCES || errno == EPERM) {
      std::cout << "    [i] Reading another process's memory needs root. "
                   "Run `adb root` (userdebug builds)\n"
                   "        or `su -c hayabusa ...` on a rooted device. "
                   "Same-uid targets work without root.\n";
    }
    return -1;
  }
  std::string raw_dir = out + "/raw";
  const std::string raw_display_dir = out_display + "/raw";
  mkdir_p(raw_dir);
  RuntimeMemorySnapshot runtime_snapshot;
  runtime_snapshot.anonymous = capture_anonymous_regions(
      regions, mem_fd, opt.capture.memory_bytes,
      &runtime_snapshot.anonymous_truncated);
  // Anonymous memory is intentionally budgeted. A large real application can
  // exceed that optional sweep without invalidating exact selected-module
  // bytes; retain an explicit truncation marker instead of turning a sound ELF
  // dump into a global failure. Writable mappings belonging to a selected
  // module remain strict below.
  bool snapshot_incomplete = false;

  // Handle RAW dump for priority files that are NOT ELFs (like
  // global-metadata.dat). Decide this per mapped file, not per mapping: the
  // executable's offset-zero page has ELF magic while its later PT_LOAD pages
  // naturally do not. Treating those later pages as unrelated RAW files made
  // --p emit duplicate, partial executable artifacts.
  std::set<std::string> mapped_elf_paths;
  for (const auto &r : regions) {
    if (!r.readable() || r.offset != 0)
      continue;
    const std::string path = normalized_mapping_name(r.name);
    if (path.empty())
      continue;
    unsigned char magic[SELFMAG] = {};
    if (pread(mem_fd, magic, sizeof(magic), r.start) ==
            static_cast<ssize_t>(sizeof(magic)) &&
        memcmp(magic, ELFMAG, SELFMAG) == 0) {
      mapped_elf_paths.insert(path);
    }
  }

  for (const auto &p_file : priority_files) {
    bool found_mapping = false;
    bool dumped_raw = false;
    bool saw_elf = false;
    bool unchanged_raw = false;

    for (const auto &r : regions) {
      if (!r.readable())
        continue;
      if (r.name.find(p_file) != std::string::npos) {
        found_mapping = true;
        const std::string path = normalized_mapping_name(r.name);
        if (mapped_elf_paths.count(path) != 0) {
          saw_elf = true;
          continue;
        }
        // Only treat as non-ELF if magic check fails
        unsigned char magic[4] = {0};
        ssize_t magic_rd = pread(mem_fd, magic, sizeof(magic), r.start);
        if (magic_rd != (ssize_t)sizeof(magic)) {
          snapshot_incomplete = true;
          continue;
        }
        if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' ||
            magic[3] != 'F') {
          size_t size = r.size();
          if (size > 0 &&
              !exceeds_policy_limit(size, opt.capture.image_bytes)) {
            std::vector<uint8_t> data(size);
            if (read_exact(mem_fd, data.data(), size, r.start)) {
              std::ostringstream key_ss;
              key_ss << p_file << "@0x" << std::hex << r.start << "-0x" << r.end
                     << "@off0x" << r.offset;
              std::string raw_key = key_ss.str();
              uint64_t raw_hash = hash_data(data);
              auto it = raw_hash_by_key.find(raw_key);
              if (it != raw_hash_by_key.end() && it->second == raw_hash) {
                unchanged_raw = true;
                continue;
              }

              std::string dump_path =
                  make_raw_dump_path(raw_dir, p_file, r.start, r.offset, true);
              const std::string dump_display_path = make_raw_dump_path(
                  raw_display_dir, p_file, r.start, r.offset, true);

              std::ofstream fout(dump_path, std::ios::binary);
              fout.write(reinterpret_cast<const char *>(data.data()),
                         data.size());
              fout.close();
              if (!fout) {
                snapshot_incomplete = true;
                continue;
              }
              // Commit the skip-cache only after the artifact is durable
              // enough for this run. Otherwise a short write/close failure
              // makes the retry incorrectly skip the missing RAW dump.
              raw_hash_by_key[raw_key] = raw_hash;
              std::cout << "    [PRIORITY] " << p_file << " ("
                        << Utils::format_size(size) << ") (RAW dump) -> "
                        << dump_display_path << "\n";
              std::cout.flush();
              dumped_raw = true;
            } else {
              snapshot_incomplete = true;
            }
          } else if (size != 0) {
            snapshot_incomplete = true;
          }
        } else {
          saw_elf = true;
        }
        // Note: We don't break here because a priority file (like metadata)
        // might be split across multiple mapped regions.
      }
    }

    if (!found_mapping) {
      std::cout << "    [PRIORITY] " << p_file << " not mapped yet\n";
      std::cout.flush();
    } else if (!dumped_raw && unchanged_raw) {
      std::cout << "    [PRIORITY] " << p_file << " unchanged (RAW skip)\n";
      std::cout.flush();
    } else if (!dumped_raw && saw_elf) {
      std::cout << "    [PRIORITY] " << p_file
                << " mapped as ELF (handled in ELF pass)\n";
      std::cout.flush();
    }
  }

  std::vector<Candidate> candidates;
  candidates.reserve(regions.size());

  // One path may be loaded more than once in distinct Android linker
  // namespaces. Keep one candidate per load-bias; only collapse offset-zero
  // header aliases that fall inside the same PT_LOAD span.
  std::map<std::string, std::vector<size_t>> instances_by_path;

  for (const auto &r : regions) {
    if (!r.readable())
      continue;

    std::string name = normalized_mapping_name(r.name);

    bool is_priority_elf = false;
    for (const auto &p : priority_files) {
      if (name.find(p) != std::string::npos) {
        is_priority_elf = true;
        break;
      }
    }
    std::string display_name = make_display_name(name);

    if (name.empty() ||
        (!is_shared_object_name(name) && !is_dalvik_container_name(name) &&
         !is_priority_elf))
      continue;

    uint8_t header[kCdexHeaderSize] = {};
    ssize_t rd = pread(mem_fd, header, sizeof(header), r.start);
    if (rd < 8)
      continue;
    CandidateKind kind =
        detect_candidate_kind(header, static_cast<size_t>(rd));
    if (kind == CandidateKind::Unknown)
      continue;
    bool embedded_elf = false;
    if (kind == CandidateKind::Elf && r.offset != 0) {
      // Uncompressed APK native entries are mmap'd directly. Their mapping
      // path is base.apk and the entry begins at a page-aligned non-zero file
      // offset, so recover the real library identity from DT_SONAME.
      if (!is_dalvik_container_name(name) ||
          !read_remote_elf_soname(mem_fd, r.start, opt.capture.image_bytes,
                                  &display_name))
        continue;
      embedded_elf = true;
      for (const auto &p : priority_files) {
        if (display_name.find(p) != std::string::npos) {
          is_priority_elf = true;
          break;
        }
      }
    }
    // A direct DEX/CDEX or an uncompressed APK ELF entry can begin at a
    // non-zero backing-file offset. Other file containers must start at zero.
    if (r.offset != 0 && kind != CandidateKind::Dex &&
        kind != CandidateKind::Cdex && !embedded_elf)
      continue;

    // --only matches both the backing pathname and the recovered logical ELF
    // name. This is what makes `--only libfoo.so` work for base.apk mappings.
    if (!opt.only.empty() && !is_priority_elf) {
      bool wanted = false;
      for (const auto &pat : opt.only) {
        if (name.find(pat) != std::string::npos ||
            display_name.find(pat) != std::string::npos) {
          wanted = true;
          break;
        }
      }
      if (!wanted)
        continue;
    }

    uint64_t candidate_base = r.start;
    uint64_t mapped_span = 0;
    std::vector<MapEntry> file_mappings;
    if (kind == CandidateKind::Elf) {
      if (!mapped_elf_layout(mem_fd, r.start, opt.capture.image_bytes,
                             &candidate_base,
                             &mapped_span))
        continue;
    } else if (kind == CandidateKind::Dex) {
      if (rd < static_cast<ssize_t>(kDexHeaderSize) &&
          !read_exact(mem_fd, header, kDexHeaderSize, r.start))
        continue;
      mapped_span = read_le32(header + 32);
      if (mapped_span < kDexHeaderSize || mapped_span > kMaxDexSize)
        continue;
    } else if (kind == CandidateKind::Odex) {
      uint32_t dex_offset = 0, dex_length = 0;
      if (!parse_odex_header(header, static_cast<size_t>(rd), &dex_offset,
                             &dex_length, &mapped_span))
        continue;
    } else if (kind == CandidateKind::Cdex) {
      if (rd < static_cast<ssize_t>(kCdexHeaderSize) &&
          !read_exact(mem_fd, header, kCdexHeaderSize, r.start))
        continue;
      uint32_t cdex_size = 0;
      if (!parse_cdex_header(header, kCdexHeaderSize, &cdex_size))
        continue;
      mapped_span = cdex_size;
    } else {
      file_mappings = coherent_mapped_file_view(regions, name, r.start);
      mapped_span = mapped_file_view_span(file_mappings);
    }
    if (mapped_span == 0 ||
        mapped_span > std::numeric_limits<uint64_t>::max() - candidate_base)
      continue;

    bool alias_of_existing = false;
    for (size_t index : instances_by_path[name]) {
      const Candidate &existing = candidates[index];
      bool direct_flat =
          kind == CandidateKind::Elf || kind == CandidateKind::Dex ||
          kind == CandidateKind::Odex || kind == CandidateKind::Cdex;
      if (r.start == existing.mapping_start ||
          (direct_flat && kind == existing.kind && r.start >= existing.base &&
           r.start < existing.base + existing.mapped_span)) {
        alias_of_existing = true;
        break;
      }
    }
    if (alias_of_existing)
      continue;

    Candidate c;
    c.base = candidate_base;
    c.mapping_start = r.start;
    c.mapping_end = r.end;
    c.mapped_span = mapped_span;
    c.kind = kind;
    c.name = name;
    c.display_name = display_name;
    c.safe_name = make_safe_name(display_name);
    c.embedded_elf = embedded_elf;
    c.backing_file_offset = embedded_elf ? r.offset : 0;
    c.file_mappings = std::move(file_mappings);
    instances_by_path[name].push_back(candidates.size());
    candidates.push_back(c);
    if (matched_only_patterns) {
      for (const auto &pattern : opt.only)
        if (name.find(pattern) != std::string::npos ||
            display_name.find(pattern) != std::string::npos)
          matched_only_patterns->insert(pattern);
    }
  }

  // If priority mode, sort candidates by their order in priority_files
  if (!priority_files.empty()) {
    std::stable_sort(
        candidates.begin(), candidates.end(),
        [&](const Candidate &a, const Candidate &b) {
          int idx_a = -1, idx_b = -1;
          for (size_t i = 0; i < priority_files.size(); ++i) {
            if (a.name.find(priority_files[i]) != std::string::npos ||
                a.display_name.find(priority_files[i]) != std::string::npos) {
              idx_a = (int)i;
              break;
            }
          }
          for (size_t i = 0; i < priority_files.size(); ++i) {
            if (b.name.find(priority_files[i]) != std::string::npos ||
                b.display_name.find(priority_files[i]) != std::string::npos) {
              idx_b = (int)i;
              break;
            }
          }
          if (idx_a != idx_b) {
            if (idx_a == -1)
              return false;
            if (idx_b == -1)
              return true;
            return idx_a < idx_b;
          }
          return false;
        });
  }

  size_t total = candidates.size();
  if (matched_container_count)
    *matched_container_count = total;
  // 0 means "auto". Never spawn more workers than there are modules to chew on,
  // and never fewer than one even when there is nothing to do.
  if (thread_count == 0)
    thread_count = default_worker_threads();
  thread_count = std::min(thread_count, total);
  if (thread_count == 0)
    thread_count = 1;

  std::set<std::string> module_names;
  for (const auto &c : candidates)
    module_names.insert(c.name);
  runtime_snapshot.writable_modules = capture_writable_module_regions(
      regions, mem_fd, module_names, opt.capture.memory_bytes,
      &runtime_snapshot.writable_truncated);
  snapshot_incomplete =
      snapshot_incomplete || runtime_snapshot.writable_truncated;

  // Bind each writable mapping to one exact candidate instance. Path alone is
  // ambiguous when the same inode is loaded in multiple linker namespaces;
  // address-span matching plus nearest load bias prevents BSS/key material
  // from one instance leaking into another instance's report or cache key.
  for (size_t region_index = 0;
       region_index < runtime_snapshot.writable_modules.size();
       region_index++) {
    const MapEntry &mapping =
        runtime_snapshot.writable_modules[region_index].mapping;
    const std::string mapping_name =
        normalized_mapping_name(mapping.name);
    size_t best = std::numeric_limits<size_t>::max();
    uint64_t best_distance = std::numeric_limits<uint64_t>::max();
    for (size_t candidate_index = 0; candidate_index < candidates.size();
         candidate_index++) {
      const Candidate &candidate = candidates[candidate_index];
      if (candidate.name != mapping_name ||
          candidate.mapped_span >
              std::numeric_limits<uint64_t>::max() - candidate.base)
        continue;
      uint64_t candidate_end = candidate.base + candidate.mapped_span;
      if (mapping.start >= candidate_end || mapping.end <= candidate.base)
        continue;
      uint64_t distance = mapping.start >= candidate.base
                              ? mapping.start - candidate.base
                              : candidate.base - mapping.start;
      if (distance < best_distance) {
        best = candidate_index;
        best_distance = distance;
      }
    }
    if (best != std::numeric_limits<size_t>::max())
      candidates[best].writable_snapshot_indices.push_back(region_index);
  }

  // Persist the exact writable mappings used by runtime crypto/registration
  // analysis.  File-layout ELF dumps cannot represent PT_LOAD .bss bytes, so
  // without these address-labelled artifacts a test could only trust the
  // report's own abbreviated key preview instead of verifying live bytes.
  for (const auto &captured : runtime_snapshot.writable_modules) {
    const MapEntry &mapping = captured.mapping;
    std::ostringstream path;
    path << raw_dir << "/module_rw_0x" << std::hex << mapping.start << "_0x"
         << mapping.end << std::dec << "_s" << snapshot << ".bin";
    if (!write_binary_snapshot(path.str(), captured.data))
      snapshot_incomplete = true;
  }

  // Capture every candidate and its exact mapped backing inode in one stopped
  // epoch. Only these immutable files are handed to the expensive worker
  // phase; /proc/<pid>/mem is closed before Rizin starts.
  for (auto &c : candidates) {
    std::vector<uint8_t> captured;
    uint64_t image_size = 0;
    bool read_ok = false;
    try {
      switch (c.kind) {
      case CandidateKind::Elf:
        read_ok = read_elf_image(mem_fd, c.mapping_start, captured, image_size,
                                 opt.capture.image_bytes);
        break;
      case CandidateKind::Dex:
        read_ok = read_dex_image(mem_fd, c.base, captured, image_size);
        break;
      case CandidateKind::Odex:
      case CandidateKind::Cdex:
        read_ok =
            read_flat_image(mem_fd, c.base, c.mapped_span,
                            kMaxDalvikContainerSize, captured);
        image_size = read_ok ? captured.size() : 0;
        break;
      case CandidateKind::Vdex:
      case CandidateKind::Zip:
        read_ok = read_mapped_file_view(mem_fd, c.file_mappings, c.mapped_span,
                                        captured);
        image_size = read_ok ? captured.size() : 0;
        break;
      default:
        break;
      }
    } catch (...) {
      read_ok = false;
    }
    if (!read_ok || captured.empty() || image_size != captured.size()) {
      snapshot_incomplete = true;
      std::cout << "    [!] Incomplete stopped snapshot for " << c.display_name
                << " at 0x" << std::hex << c.base << std::dec << "\n";
      continue;
    }

    std::string raw_source_name = c.embedded_elf ? c.display_name : c.name;
    auto force_extension = [&](const char *extension) {
      size_t length = strlen(extension);
      if (raw_source_name.size() < length ||
          raw_source_name.compare(raw_source_name.size() - length, length,
                                  extension) != 0)
        raw_source_name += extension;
    };
    if (c.kind == CandidateKind::Dex)
      force_extension(".dex");
    else if (c.kind == CandidateKind::Cdex)
      force_extension(".cdex");
    c.raw_path = make_raw_dump_path(raw_dir, raw_source_name, c.base, snapshot,
                                    snapshot > 0);
    c.raw_display_path = make_raw_dump_path(
        raw_display_dir, raw_source_name, c.base, snapshot, snapshot > 0);
    std::ofstream raw(c.raw_path, std::ios::binary);
    if (!raw) {
      snapshot_incomplete = true;
      continue;
    }
    raw.write(reinterpret_cast<const char *>(captured.data()), captured.size());
    raw.close();
    if (!raw) {
      snapshot_incomplete = true;
      unlink(c.raw_path.c_str());
      continue;
    }
    c.captured_size = captured.size();
    c.captured = true;

    if (c.kind == CandidateKind::Elf) {
      c.disk_snapshot_path = c.raw_path + ".disk";
      c.disk_snapshot_display_path = c.raw_display_path + ".disk";
      if (!capture_exact_backing_file(pid, c, c.disk_snapshot_path,
                                      opt.capture.image_bytes)) {
        c.disk_snapshot_path.clear();
        c.disk_snapshot_display_path.clear();
      }
    }

    if (relink_cfg && c.kind == CandidateKind::Elf) {
      c.relink_attempted = true;
      try {
        auto relinked =
            StaticRelinkerEx::relink_full(captured, pid, c.base, *relink_cfg);
        if (!relinked.empty()) {
          c.relink_succeeded = true;
          c.relink_size = relinked.size();
          c.relink_hash = hash_data(relinked);
          size_t preview = std::min<size_t>(relinked.size(), 512);
          c.relink_preview.assign(relinked.begin(),
                                  relinked.begin() + preview);
        }
      } catch (...) {
      }
      if (!c.relink_succeeded)
        snapshot_incomplete = true;
    }
  }

  close(mem_fd);
  mem_fd = -1;
  if (!snapshot_stop.resume()) {
    std::cout << "    [!] Could not resume every target thread after capture\n";
    return -1;
  }

  const size_t bar_width = 20;
  std::cout << "    [Scan 1] Found " << candidates.size()
            << " module container(s) in stopped mappings\n";
  if (runtime_snapshot.anonymous_truncated)
    std::cout << "    [!] Anonymous snapshot truncated by budget/read "
                 "failure; selected-module capture continues\n";
  if (runtime_snapshot.writable_truncated)
    std::cout << "    [!] Writable selected-module snapshot is incomplete\n";
  std::cout << "    [i] Worker threads: " << thread_count << "\n";
  std::cout.flush();

  std::mutex print_mu;
  std::mutex hash_mu;
  std::mutex runtime_mu;
  std::atomic<size_t> next_index{0};
  std::atomic<size_t> progress_done{0};
  std::atomic<int> dumped_count{0};
  std::atomic<int> unchanged_count{0};
  std::atomic<bool> worker_failed{false};
  std::atomic<bool> analysis_incomplete{false};
  std::set<uint64_t> all_func_addrs;
  std::mutex func_mu;

  auto mix_hash = [](uint64_t seed, uint64_t value) {
    seed ^= value;
    seed *= 1099511628211ULL;
    return seed;
  };
  uint64_t anonymous_runtime_hash = 1469598103934665603ULL;
  for (const auto &region : runtime_snapshot.anonymous) {
    const auto &m = region.mapping;
    bool heap_like = m.name.find("[heap]") != std::string::npos ||
                     m.name.find("[anon:") != std::string::npos ||
                     (m.name.empty() && m.writable());
    if (!heap_like)
      continue;
    anonymous_runtime_hash = mix_hash(anonymous_runtime_hash, m.start);
    anonymous_runtime_hash =
        mix_hash(anonymous_runtime_hash, hash_data(region.data));
  }

  auto is_priority_name = [&](const std::string &name) -> bool {
    for (const auto &p : priority_files) {
      if (name.find(p) != std::string::npos)
        return true;
    }
    return false;
  };

  auto worker = [&]() {
    for (;;) {
      size_t i = next_index.fetch_add(1);
      if (i >= candidates.size())
        break;
      const Candidate &c = candidates[i];

      if (!c.captured) {
        worker_failed.store(true);
        continue;
      }
      std::vector<uint8_t> runtime_data;
      if (!read_file_prefix(c.raw_path, c.captured_size, runtime_data) ||
          runtime_data.size() != c.captured_size) {
        worker_failed.store(true);
        continue;
      }
      std::vector<uint8_t> data = runtime_data;
      std::vector<uint8_t> disk_data;
      if (!c.disk_snapshot_path.empty())
        read_file_prefix(c.disk_snapshot_path,
                         opt.capture.image_bytes == 0
                             ? std::numeric_limits<size_t>::max()
                             : static_cast<size_t>(std::min<uint64_t>(
                                   opt.capture.image_bytes,
                                   std::numeric_limits<size_t>::max())),
                         disk_data);

      bool candidate_outputs_ok = true;
      // SoFixer rebuilds ELF headers; Dalvik containers must retain their exact
      // stopped-epoch bytes for format-aware extraction.
      try {
        if (c.kind == CandidateKind::Elf) {
          const std::vector<uint8_t> *disk_baseline =
              disk_data.empty() ? nullptr : &disk_data;
          std::vector<uint8_t> fixed =
              SoFixer::repair(data, c.base, disk_baseline);
          if (!fixed.empty() && ElfParser::is_elf(fixed) &&
              !is_garbage(fixed)) {
            // The repaired image is what makes the dump openable in another
            // tool -- a raw memory image has p_offset values that no longer
            // match the file, and no section table. It used to exist only as
            // an analysis buffer and was thrown away at the end of the run.
            std::string fixed_path = c.raw_path;
            size_t so = fixed_path.rfind(".so");
            if (so != std::string::npos)
              fixed_path.insert(so, "_fixed");
            else
              fixed_path += "_fixed";
            if (write_binary_snapshot(fixed_path, fixed))
              data.swap(fixed);
            else
              candidate_outputs_ok = false;
          }
        }
      } catch (...) {
      }
      if (!candidate_outputs_ok) {
        worker_failed.store(true);
        continue;
      }
      const std::vector<uint8_t> &analysis_data = data;
      if (analysis_data.empty() ||
          (c.kind == CandidateKind::Elf && is_garbage(analysis_data))) {
        worker_failed.store(true);
        continue;
      }
      if (c.kind == CandidateKind::Elf &&
          !ElfParser::is_elf(analysis_data)) {
        worker_failed.store(true);
        continue;
      }
      if (c.kind == CandidateKind::Dex) {
        DexValidation validation =
            validate_standard_dex(analysis_data.data(), analysis_data.size());
        if (!validation.valid ||
            validation.file_size != analysis_data.size()) {
          worker_failed.store(true);
          continue;
        }
      }
      if (c.kind == CandidateKind::Cdex) {
        uint32_t cdex_size = 0;
        if (!parse_cdex_header(analysis_data.data(), analysis_data.size(),
                               &cdex_size) ||
            cdex_size != analysis_data.size()) {
          worker_failed.store(true);
          continue;
        }
      }

      // Rebuild the cross-region address set for this snapshot even when the
      // expensive report is cache-skipped. Persisting addresses from an older
      // snapshot creates false joins after unload/address reuse.
      if (c.kind == CandidateKind::Elf) {
        std::vector<uint64_t> local;
        for (const auto &sym : ElfParser::get_symbols(analysis_data))
          if (sym.type == "FUNC" && sym.offset)
            local.push_back(c.base + sym.offset);
        for (uint64_t a : ElfParser::get_eh_frame_functions(analysis_data))
          local.push_back(c.base + a);
        std::lock_guard<std::mutex> lk(func_mu);
        all_func_addrs.insert(local.begin(), local.end());
      }

      uint64_t h = hash_data(analysis_data);
      h = mix_hash(h, anonymous_runtime_hash);
      if (!disk_data.empty()) {
        h = mix_hash(h, 0x4449534b5f425954ULL); // "DISK_BYT"
        h = mix_hash(h, disk_data.size());
        h = mix_hash(h, hash_data(disk_data));
      }
      if (!c.writable_snapshot_indices.empty()) {
        uint64_t writable_hash = 1469598103934665603ULL;
        for (size_t region_index : c.writable_snapshot_indices) {
          if (region_index >= runtime_snapshot.writable_modules.size())
            continue;
          const auto &region =
              runtime_snapshot.writable_modules[region_index];
          writable_hash = mix_hash(writable_hash, region.mapping.start);
          writable_hash = mix_hash(writable_hash, region.mapping.end);
          writable_hash = mix_hash(writable_hash, region.mapping.offset);
          writable_hash =
              mix_hash(writable_hash, hash_data(region.data));
        }
        h = mix_hash(h, 0x5752495441424c45ULL); // "WRITABLE"
        h = mix_hash(h, writable_hash);
      }
      std::ostringstream key_builder;
      key_builder << c.name << "@0x" << std::hex << c.base;
      const std::string cache_key = key_builder.str();
      {
        std::lock_guard<std::mutex> lk(hash_mu);
        // Cache identity includes the full path and load bias, so two linker
        // namespace instances never suppress each other's address-specific
        // report. Runtime heap/BSS hashes are mixed in above so changed live
        // facts cannot hide behind an unchanged static ELF.
        auto it = module_hash_by_key.find(cache_key);
        if (it != module_hash_by_key.end() && it->second == h) {
          unchanged_count.fetch_add(1);
          continue;
        }
      }

      size_t progress = progress_done.fetch_add(1) + 1;
      int percent =
          total == 0 ? 100 : (int)((progress * 100) / static_cast<int>(total));
      size_t filled = (percent * bar_width) / 100;
      std::string bar(filled, '#');
      bar.append(bar_width - filled, '.');

      std::string pri_tag = is_priority_name(c.name) ? "[PRIORITY] " : "";
      {
        std::lock_guard<std::mutex> lk(print_mu);
        std::cout << "    " << pri_tag << "[" << progress << "/" << total
                  << "] [" << bar << "] " << percent << "% " << c.display_name
                  << " (" << Utils::format_size(analysis_data.size()) << ")\n";
        std::cout.flush();
      }

      std::ostringstream path;
      path << out << "/" << c.safe_name << "_0x" << std::hex << c.base
           << std::dec << "_s" << snapshot << ".txt";
      std::string analysis_txt_path = path.str();

      DexExtractionResult extraction;
      if (c.kind == CandidateKind::Odex) {
        extraction = extract_odex_dex(analysis_data, c.base);
      } else if (c.kind == CandidateKind::Vdex) {
        extraction = carve_standard_dex_from_vdex(analysis_data, c.base);
      } else if (c.kind == CandidateKind::Zip) {
        extraction = extract_zip_multidex(analysis_data);
      }

      const bool has_container_manifest =
          is_dalvik_kind(c.kind) && c.kind != CandidateKind::Dex;
      if (has_container_manifest) {
        for (auto &dex : extraction.dexes) {
          std::string raw_stem =
              extracted_dex_stem(c, raw_dir, snapshot, dex.label);
          std::string raw_display_stem =
              extracted_dex_stem(c, raw_display_dir, snapshot, dex.label);
          std::string report_stem =
              extracted_dex_stem(c, out, snapshot, dex.label);
          std::string report_display_stem =
              extracted_dex_stem(c, out_display, snapshot, dex.label);
          dex.raw_path = raw_stem + ".dex";
          dex.raw_display_path = raw_display_stem + ".dex";
          dex.report_path = report_stem + ".txt";
          dex.report_display_path = report_display_stem + ".txt";
          if (!write_binary_snapshot(dex.raw_path, dex.data)) {
            extraction.issues.push_back("could not write extracted DEX " +
                                        dex.raw_display_path);
            candidate_outputs_ok = false;
          }
        }

        std::ofstream manifest(analysis_txt_path);
        if (manifest) {
          manifest << "=== DALVIK CONTAINER EXTRACTION ===\n";
          manifest << "Module: " << c.name << "\n";
          manifest << "Kind: " << candidate_kind_name(c.kind) << "\n";
          manifest << "Base: 0x" << std::hex << c.base << std::dec << "\n";
          manifest << "Snapshot bytes: " << analysis_data.size() << "\n";
          manifest << "Raw snapshot: " << c.raw_display_path << "\n";
          manifest << "Container status: "
                   << (extraction.container_ok ? "validated" : "rejected")
                   << "\n";
          if (c.kind == CandidateKind::Zip)
            manifest << "ZIP validation: libzip read each selected entry to "
                         "EOF; zip_fclose CRC/decompression status had to "
                         "succeed before DEX validation.\n";
          if (c.kind == CandidateKind::Cdex) {
            manifest << "\nsemantic-analysis=unsupported\n";
            manifest << "CDEX uses compact code-item/data semantics and is not "
                         "a standard DEX. It was deliberately not passed to "
                         "Rizin or core_ghidra.\n";
          } else {
            manifest << "Validated standard DEX payloads: "
                     << extraction.dexes.size() << "\n";
            for (const auto &dex : extraction.dexes) {
              manifest << "  " << dex.label << ": " << dex.data.size()
                       << " bytes";
              if (dex.container_offset)
                manifest << " at container offset 0x" << std::hex
                         << dex.container_offset << std::dec;
              manifest << "\n    origin: " << dex.origin
                       << "\n    raw: " << dex.raw_display_path
                       << "\n    report: " << dex.report_display_path
                       << "\n";
            }
          }
          if (!extraction.cdex_offsets.empty()) {
            manifest << "Recognized CDEX payload offsets (not sent to Rizin):";
            for (uint64_t offset : extraction.cdex_offsets)
              manifest << " 0x" << std::hex << offset << std::dec;
            manifest << "\n";
          }
          if (!extraction.issues.empty()) {
            manifest << "\nIssues/notes:\n";
            for (const auto &issue : extraction.issues)
              manifest << "  - " << issue << "\n";
          }
          manifest.close();
          if (!manifest)
            candidate_outputs_ok = false;
        } else {
          candidate_outputs_ok = false;
        }
        if (!extraction.container_ok)
          candidate_outputs_ok = false;
      }

      bool reports_ok = true;
      {
        std::lock_guard<std::mutex> engine_lock(g_rizin_engine_mu);
        struct SessionReset {
          ~SessionReset() { rzb::release_shared_image(); }
        } session_reset;

        if (c.kind == CandidateKind::Dex) {
          bool partial = false;
          reports_ok =
              analyze_dex_to_txt(analysis_data, analysis_txt_path, c.base,
                                 c.name, opt.analysis, &partial) &&
              reports_ok;
          if (partial)
            analysis_incomplete.store(true);
        } else if (c.kind == CandidateKind::Elf) {
          bool partial = false;
          reports_ok =
              analyze_to_txt(
                  analysis_data, analysis_txt_path, c.base,
                  c.embedded_elf ? c.display_name : c.name,
                  &runtime_data, disk_data.empty() ? nullptr : &disk_data, pid,
                  &runtime_mu, &runtime_snapshot,
                  &c.writable_snapshot_indices, opt.analysis, &partial) &&
              reports_ok;
          if (partial)
            analysis_incomplete.store(true);
        } else if (c.kind != CandidateKind::Cdex) {
          for (const auto &dex : extraction.dexes) {
            if (dex.raw_path.empty() || dex.report_path.empty()) {
              reports_ok = false;
              continue;
            }
            rzb::release_shared_image();
            bool partial = false;
            reports_ok =
                analyze_dex_to_txt(dex.data, dex.report_path,
                                   dex.runtime_address,
                                   c.name + "!" + dex.label, opt.analysis,
                                   &partial) &&
                reports_ok;
            if (partial)
              analysis_incomplete.store(true);
            rzb::release_shared_image();
          }
        }

        if (c.relink_attempted) {
          std::ofstream tfile(analysis_txt_path, std::ios::app);
          if (tfile) {
            tfile << "\n=== RELINK ===\n";
            if (c.relink_succeeded) {
              tfile << "epoch=stopped-process-snapshot\n";
              tfile << "size=" << c.relink_size << " bytes\n";
              tfile << "hash=0x" << std::hex << c.relink_hash << std::dec
                    << "\n";
              if (!c.relink_preview.empty())
                tfile << "preview[" << c.relink_preview.size()
                      << "]="
                      << hex_bytes(c.relink_preview.data(),
                                   c.relink_preview.size())
                      << "\n";
            } else {
              tfile << "FAILED: live dependency capture was incomplete\n";
            }
            tfile.close();
            if (!tfile)
              reports_ok = false;
          } else {
            reports_ok = false;
          }
          std::lock_guard<std::mutex> lk(print_mu);
          if (c.relink_succeeded)
            std::cout << "    [RELINK] " << c.display_name
                      << " captured in stopped epoch ("
                      << Utils::format_size(c.relink_size) << ")\n";
          else
            std::cout << "    [RELINK] Failed for " << c.display_name << "\n";
          std::cout.flush();
        }
      }

      candidate_outputs_ok = candidate_outputs_ok && reports_ok;
      if (!candidate_outputs_ok) {
        worker_failed.store(true);
        continue;
      }
      {
        std::lock_guard<std::mutex> lk(hash_mu);
        module_hash_by_key[cache_key] = h;
      }
      dumped_count.fetch_add(1);
    }
  };

  std::vector<std::thread> workers;
  workers.reserve(thread_count);
  for (size_t t = 0; t < thread_count; ++t)
    workers.emplace_back(worker);
  for (auto &th : workers)
    th.join();

  bool anonymous_analysis_incomplete = false;
  AnonymousDumpResult anonymous = dump_anonymous_regions(
      out, out_display, raw_dir, raw_display_dir, snapshot, all_func_addrs,
      opt.analysis, &runtime_mu, opt.analysis.limit, opt.capture.image_bytes,
      runtime_snapshot, &anonymous_analysis_incomplete);
  if (anonymous_analysis_incomplete)
    analysis_incomplete.store(true);
  if (!anonymous.artifacts_ok)
    worker_failed.store(true);
  if (anonymous.artifacts_ok && anonymous.regions > 0) {
    std::cout << "    [ANON] Captured " << anonymous.regions
              << " anonymous/heap region(s) -> anonymous_memory_s" << snapshot
              << ".txt\n";
    std::cout.flush();
  }

  int count = dumped_count.load();
  int unchanged = unchanged_count.load();
  if (count > 0 || unchanged > 0) {
    std::cout << "    Dumped " << count << " modules";
    if (unchanged > 0)
      std::cout << " (" << unchanged << " unchanged, skipped)";
    std::cout << "\n";
  }
  if (snapshot_incomplete || worker_failed.load()) {
    std::cout << "    [!] INCOMPLETE SNAPSHOT: refusing a successful status\n";
    return -1;
  }
  if (partial_result)
    *partial_result = runtime_snapshot.anonymous_truncated ||
                      analysis_incomplete.load();
  // Anonymous-only targets are a valid successful dump. Returning zero here
  // made cmd_dump retry until timeout and finally report failure even after it
  // had extracted a runtime DEX/ELF.
  return count + anonymous.regions;
}

// kill(pid, 0) reports EPERM -- not ESRCH -- for a live process owned by
// another uid, which is the normal case for an Android app. Treating that as
// "gone" would skip every target we do not own.
static bool process_alive(int pid) {
  if (kill(pid, 0) == 0)
    return true;
  return errno == EPERM;
}

static int open_verified_pidfd(pid_t pid) {
  int fd;
  do {
    fd = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return -1;
  int rc;
  do {
    rc = static_cast<int>(
        syscall(SYS_pidfd_send_signal, fd, 0, nullptr, 0));
  } while (rc < 0 && errno == EINTR);
  if (rc != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static bool pidfd_signal(int fd, int signal) {
  if (fd < 0)
    return false;
  int rc;
  do {
    rc = static_cast<int>(
        syscall(SYS_pidfd_send_signal, fd, signal, nullptr, 0));
  } while (rc < 0 && errno == EINTR);
  return rc == 0;
}

static void reap_child_bounded(pid_t pid,
                               std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    int status = 0;
    pid_t waited = waitpid(pid, &status, WNOHANG | __WALL);
    if (waited == pid || (waited < 0 && errno == ECHILD))
      return;
    if (waited < 0 && errno != EINTR)
      return;
    usleep(1000);
  }
}

static bool wait_child_exit_bounded(pid_t pid,
                                    std::chrono::milliseconds timeout,
                                    int *status_out) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    int status = 0;
    errno = 0;
    const pid_t waited = waitpid(pid, &status, WNOHANG | __WALL);
    if (waited == pid) {
      if (status_out)
        *status_out = status;
      return true;
    }
    if (waited < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    usleep(1000);
  }
  return false;
}

// Keep every signal handled by the global fatal path pending across
// fork -> pidfd_open -> atomic
// publication. Before publication the child is still our unreaped numeric PID;
// afterwards the global handler has an exact identity with which to terminate
// it. The launch path runs before analysis workers are created, so this mask
// closes the only pre-publication delivery window.
class LaunchPublishSignalBlock {
public:
  LaunchPublishSignalBlock() {
    sigemptyset(&blocked_);
    sigaddset(&blocked_, SIGINT);
    sigaddset(&blocked_, SIGTERM);
    sigaddset(&blocked_, SIGABRT);
    sigaddset(&blocked_, SIGSEGV);
    sigaddset(&blocked_, SIGBUS);
    active_ = sigprocmask(SIG_BLOCK, &blocked_, &previous_) == 0;
  }
  LaunchPublishSignalBlock(const LaunchPublishSignalBlock &) = delete;
  LaunchPublishSignalBlock &operator=(const LaunchPublishSignalBlock &) = delete;
  ~LaunchPublishSignalBlock() { restore(); }
  bool active() const { return active_; }
  const sigset_t *previous_mask() const { return active_ ? &previous_ : nullptr; }
  bool restore() {
    if (!active_)
      return true;
    if (sigprocmask(SIG_SETMASK, &previous_, nullptr) != 0)
      return false;
    active_ = false;
    return true;
  }

private:
  sigset_t blocked_{};
  sigset_t previous_{};
  bool active_ = false;
};

// RAII for the packed async-cleanup state. _exit() skips C++ destructors, so
// the signal handler closes the same control descriptor directly. The
// supervisor, not the analyzer, owns descendant enumeration and cannot lose a
// daemon merely because it changed process group or session.
class PublishedLaunchGuard {
public:
  PublishedLaunchGuard() = default;
  PublishedLaunchGuard(const PublishedLaunchGuard &) = delete;
  PublishedLaunchGuard &operator=(const PublishedLaunchGuard &) = delete;
  ~PublishedLaunchGuard() { terminate_and_reap(); }

  bool adopt(pid_t supervisor, int supervisor_pidfd, int control_fd) {
    if (active_ || supervisor <= 0 || supervisor_pidfd < 0 || control_fd < 0)
      return false;
    const uint64_t state = pack_launch_state(supervisor, control_fd);
    uint64_t expected = 0;
    if (!g_active_launch_state.compare_exchange_strong(
            expected, state, std::memory_order_acq_rel,
            std::memory_order_relaxed))
      return false;
    supervisor_ = supervisor;
    supervisor_pidfd_ = supervisor_pidfd;
    control_fd_ = control_fd;
    state_ = state;
    active_ = true;
    return true;
  }

  bool active() const { return active_; }

  bool terminate_and_reap() {
    if (!active_)
      return cleanup_ok_;
    uint64_t expected = state_;
    const bool claimed = g_active_launch_state.compare_exchange_strong(
        expected, kLaunchCleanupClaimed, std::memory_order_acq_rel,
        std::memory_order_relaxed);
    if (claimed) {
      close(control_fd_); // supervisor begins recursive pidfd teardown
      control_fd_ = -1;
    }

    int status = 0;
    const bool reaped = claimed &&
                        wait_child_exit_bounded(supervisor_,
                                                std::chrono::seconds(5),
                                                &status);
    cleanup_ok_ = reaped && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (claimed) {
      uint64_t owned = kLaunchCleanupClaimed;
      (void)g_active_launch_state.compare_exchange_strong(
          owned, 0, std::memory_order_acq_rel, std::memory_order_relaxed);
    }
    if (control_fd_ >= 0)
      close(control_fd_);
    if (supervisor_pidfd_ >= 0)
      close(supervisor_pidfd_);
    active_ = false;
    supervisor_ = -1;
    supervisor_pidfd_ = -1;
    control_fd_ = -1;
    state_ = 0;
    return cleanup_ok_;
  }

private:
  pid_t supervisor_ = -1;
  int supervisor_pidfd_ = -1;
  int control_fd_ = -1;
  uint64_t state_ = 0;
  bool active_ = false;
  bool cleanup_ok_ = true;
};

class DirectLaunchTarget;
static DirectLaunchTarget
open_direct_launch_target(const std::string &target);

static bool valid_direct_launch_elf(int fd, const struct stat &st) {
  if (fd < 0 || st.st_size < static_cast<off_t>(sizeof(Elf64_Ehdr)))
    return false;
  Elf64_Ehdr header {};
  ssize_t amount;
  do {
    amount = pread(fd, &header, sizeof(header), 0);
  } while (amount < 0 && errno == EINTR);
  if (amount != static_cast<ssize_t>(sizeof(header)) ||
      memcmp(header.e_ident, ELFMAG, SELFMAG) != 0 ||
      header.e_ident[EI_CLASS] != ELFCLASS64 ||
      header.e_ident[EI_DATA] != ELFDATA2LSB ||
      header.e_ident[EI_VERSION] != EV_CURRENT ||
      header.e_version != EV_CURRENT || header.e_machine != EM_AARCH64 ||
      (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
      header.e_phnum == 0 || header.e_phentsize != sizeof(Elf64_Phdr))
    return false;
  const uint64_t size = static_cast<uint64_t>(st.st_size);
  const uint64_t ph_size =
      static_cast<uint64_t>(header.e_phnum) * sizeof(Elf64_Phdr);
  return header.e_phoff <= size && ph_size <= size - header.e_phoff;
}

class DirectLaunchTarget {
public:
  DirectLaunchTarget() = default;
  DirectLaunchTarget(const DirectLaunchTarget &) = delete;
  DirectLaunchTarget &operator=(const DirectLaunchTarget &) = delete;
  DirectLaunchTarget(DirectLaunchTarget &&other) noexcept
      : fd_(other.fd_), stat_(other.stat_), path_(std::move(other.path_)),
        run_uid_(other.run_uid_), run_gid_(other.run_gid_) {
    other.fd_ = -1;
  }
  DirectLaunchTarget &operator=(DirectLaunchTarget &&other) noexcept {
    if (this == &other)
      return *this;
    if (fd_ >= 0)
      close(fd_);
    fd_ = other.fd_;
    stat_ = other.stat_;
    path_ = std::move(other.path_);
    run_uid_ = other.run_uid_;
    run_gid_ = other.run_gid_;
    other.fd_ = -1;
    return *this;
  }
  ~DirectLaunchTarget() {
    if (fd_ >= 0)
      close(fd_);
  }
  explicit operator bool() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  uid_t run_uid() const { return run_uid_; }
  gid_t run_gid() const { return run_gid_; }
  const std::string &path() const { return path_; }

private:
  friend DirectLaunchTarget
  open_direct_launch_target(const std::string &target);
  int fd_ = -1;
  struct stat stat_ {};
  std::string path_;
  uid_t run_uid_ = 0;
  gid_t run_gid_ = 0;
};

static DirectLaunchTarget
open_direct_launch_target(const std::string &target) {
  DirectLaunchTarget result;
  int fd = open(target.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd >= 0 && fd < 3) {
    const int moved = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    const int move_error = errno;
    close(fd);
    fd = moved;
    if (fd < 0)
      errno = move_error;
  }
  if (fd < 0) {
    std::cout << "[!] --launch requires an accessible, non-symlink executable "
                 "file; '"
              << target << "' could not be opened: " << strerror(errno)
              << "\n";
  } else {
    struct stat st {};
    if (fstat(fd, &st) != 0) {
      std::cout << "[!] could not verify --launch target '" << target
                << "': " << strerror(errno) << "\n";
    } else if (!S_ISREG(st.st_mode)) {
      std::cout << "[!] --launch requires a regular executable file; '"
                << target << "' is not one\n";
    } else if (!valid_direct_launch_elf(fd, st)) {
      std::cout << "[!] --launch requires a valid AArch64 ELF executable; '"
                << target << "' failed header/program-table validation\n";
    } else {
      uid_t run_uid = geteuid();
      gid_t run_gid = getegid();
      if (geteuid() == 0) {
        // Root-owned executables are deliberately run as Android's shell UID,
        // while an app-owned fixture is run as its owner. The analyzed program
        // never inherits the root analyzer identity.
        if (st.st_uid == 0) {
          // A root-owned file may carry a privileged Android group (for
          // example inet or a device-service GID). The filename's group is
          // metadata, not authority the untrusted target is allowed to
          // inherit; root-owned direct launches always use shell:shell.
          run_uid = static_cast<uid_t>(2000);
          run_gid = static_cast<gid_t>(2000);
        } else {
          run_uid = st.st_uid;
          // File group ownership can encode shared Android privileges and is
          // not proof of the owner's intended primary identity. Execute uses
          // the owner bit because run_uid matches st_uid, so a same-UID GID is
          // both sufficient and the least-authority choice.
          run_gid = run_uid;
        }
      }
      const mode_t execute_bit =
          run_uid == st.st_uid
              ? S_IXUSR
              : (run_gid == st.st_gid ? S_IXGRP : S_IXOTH);
      if ((st.st_mode & execute_bit) == 0) {
        std::cout << "[!] --launch target '" << target
                  << "' is not executable by its reduced-privilege identity\n";
      } else if (st.st_uid == 0 && (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        std::cout << "[!] refusing writable root-owned --launch target '"
                  << target << "'\n";
      } else {
        result.fd_ = fd;
        result.stat_ = st;
        result.path_ = target;
        result.run_uid_ = run_uid;
        result.run_gid_ = run_gid;
        return result;
      }
    }
    close(fd);
  }
  std::cout << "    Omit --launch to attach to a running package/process, or "
               "use --launch-cmd <shell-command>.\n";
  return result;
}

// These are Android process-contract values, not workspace/developer paths.
// Keep one minimal environment for both launch modes so the privilege boundary
// cannot drift between two duplicated lists.
static constexpr const char *kAndroidShellPath = "/system/bin/sh";
static char kChildPathEnv[] =
    "PATH=/system/bin:/system/xbin:/vendor/bin:/product/bin";
static char kAndroidRootEnv[] = "ANDROID_ROOT=/system";
static char kAndroidDataEnv[] = "ANDROID_DATA=/data";
static char *const kMinimalAndroidEnvironment[] = {
    kChildPathEnv, kAndroidRootEnv, kAndroidDataEnv, nullptr};

[[noreturn]] static void
exec_direct_launch_target(const DirectLaunchTarget &target) {
  // Make every inherited analyzer descriptor close on exec, including handles
  // a root caller deliberately left open. Then exempt only the already
  // validated executable descriptor used by execveat.
  int close_range_result;
  do {
    close_range_result = static_cast<int>(
        syscall(SYS_close_range, 3u, ~0u, CLOSE_RANGE_CLOEXEC));
  } while (close_range_result < 0 && errno == EINTR);
  if (close_range_result < 0) {
    if (errno != ENOSYS && errno != EINVAL)
      _exit(126);
    long open_max = sysconf(_SC_OPEN_MAX);
    if (open_max < 0 || open_max > 1048576)
      open_max = 1048576;
    for (int fd = 3; fd < open_max; fd++) {
      if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 && errno != EBADF)
        _exit(126);
    }
  }
  if (fcntl(target.fd(), F_SETFD, 0) != 0)
    _exit(126);
  int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (null_fd < 0)
    _exit(126);
  for (int standard_fd = 0; standard_fd < 3; standard_fd++)
    if (dup3(null_fd, standard_fd, 0) != standard_fd)
      _exit(126);
  close(null_fd);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    _exit(126);
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 &&
      errno != EINVAL)
    _exit(126);
  if (geteuid() == 0) {
    if (setgroups(0, nullptr) != 0 ||
        setresgid(target.run_gid(), target.run_gid(), target.run_gid()) != 0 ||
        setresuid(target.run_uid(), target.run_uid(), target.run_uid()) != 0)
      _exit(126);
  }
  // setuid clears permitted/effective capabilities but Linux deliberately
  // preserves the inheritable set. Drop all three sets explicitly so a root
  // caller with a non-default CapInh cannot pass latent authority to the
  // analyzed executable. no_new_privs prevents later file-capability gain;
  // the kernel bounding set may remain nonzero but is not itself active.
  struct __user_cap_header_struct cap_header {};
  cap_header.version = _LINUX_CAPABILITY_VERSION_3;
  cap_header.pid = 0;
  struct __user_cap_data_struct cap_data[2] {};
  if (syscall(SYS_capset, &cap_header, cap_data) != 0)
    _exit(126);
  char *const argv[] = {const_cast<char *>(target.path().c_str()), nullptr};
  // Never leak the root analyzer's environment (tokens, preload controls,
  // debug sockets, HOME, and toolchain paths) into an app/shell-UID target.
  // These fixed values are sufficient for an Android native executable and do
  // not grant the child authority over the analyzer.
  syscall(SYS_execveat, target.fd(), "", argv, kMinimalAndroidEnvironment,
          AT_EMPTY_PATH);
  _exit(127);
}

struct LaunchAnnouncement {
  int32_t status = 0;
  int32_t target_pid = -1;
};
static_assert(sizeof(LaunchAnnouncement) <= PIPE_BUF);

static bool set_cloexec(int fd) {
  return fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0;
}

static bool write_exact_fd(int fd, const void *data, size_t size) {
  // A gated child can die between publication and release. Block SIGPIPE only
  // for this protocol write so EPIPE becomes a verified launch failure instead
  // of terminating the analyzer. Restore the caller's original signal mask and
  // consume only a SIGPIPE generated by this thread.
  sigset_t pipe_mask {};
  sigset_t old_mask {};
  sigset_t pending_before {};
  sigemptyset(&pipe_mask);
  sigaddset(&pipe_mask, SIGPIPE);
  if (sigprocmask(SIG_BLOCK, &pipe_mask, &old_mask) != 0)
    return false;
  const bool had_pending =
      sigpending(&pending_before) == 0 &&
      sigismember(&pending_before, SIGPIPE) == 1;

  const uint8_t *cursor = static_cast<const uint8_t *>(data);
  size_t done = 0;
  bool success = true;
  while (done < size) {
    ssize_t amount = write(fd, cursor + done, size - done);
    if (amount < 0 && errno == EINTR)
      continue;
    if (amount <= 0) {
      success = false;
      break;
    }
    done += static_cast<size_t>(amount);
  }
  const int write_error = success ? 0 : errno;
  if (!success && write_error == EPIPE && !had_pending) {
    const struct timespec no_wait {};
    while (sigtimedwait(&pipe_mask, nullptr, &no_wait) < 0 && errno == EINTR) {
    }
  }
  const bool restored = sigprocmask(SIG_SETMASK, &old_mask, nullptr) == 0;
  if (!success)
    errno = write_error;
  return success && restored;
}

static bool read_exact_fd_until(int fd, void *data, size_t size,
                                std::chrono::milliseconds timeout) {
  uint8_t *cursor = static_cast<uint8_t *>(data);
  size_t done = 0;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (done < size && std::chrono::steady_clock::now() < deadline) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    struct pollfd pfd { fd, POLLIN | POLLHUP | POLLERR, 0 };
    int polled = poll(&pfd, 1,
                      static_cast<int>(std::max<int64_t>(
                          1, std::min<int64_t>(remaining.count(), 250))));
    if (polled < 0 && errno == EINTR)
      continue;
    if (polled <= 0 || (pfd.revents & (POLLERR | POLLNVAL)))
      continue;
    ssize_t amount = read(fd, cursor + done, size - done);
    if (amount < 0 && errno == EINTR)
      continue;
    if (amount <= 0)
      return false;
    done += static_cast<size_t>(amount);
  }
  return done == size;
}

static int read_proc_parent(pid_t pid) {
  char path[64];
  const int length = snprintf(path, sizeof(path), "/proc/%d/status", pid);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(path))
    return -1;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  char data[8192];
  ssize_t amount;
  do {
    amount = read(fd, data, sizeof(data) - 1);
  } while (amount < 0 && errno == EINTR);
  close(fd);
  if (amount <= 0)
    return -1;
  data[amount] = 0;
  const char *line = strstr(data, "\nPPid:");
  if (!line && strncmp(data, "PPid:", 5) == 0)
    line = data - 1;
  if (!line)
    return -1;
  line += 6;
  while (*line == ' ' || *line == '\t')
    line++;
  char *tail = nullptr;
  long value = strtol(line, &tail, 10);
  return tail != line && value > 0 && value <= INT_MAX
             ? static_cast<int>(value)
             : -1;
}

static bool read_direct_children(std::vector<pid_t> *children) {
  if (!children)
    return false;
  children->clear();
  char path[96];
  const pid_t self = getpid();
  const int length = snprintf(path, sizeof(path),
                              "/proc/self/task/%d/children", self);
  if (length <= 0 || static_cast<size_t>(length) >= sizeof(path))
    return false;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    // Android kernels commonly omit CONFIG_PROC_CHILDREN. Fall back to a
    // bounded /proc scan; callers still pidfd-open first and recheck PPid
    // afterwards, so a numeric PID observed here is never itself a kill sink.
    DIR *proc = opendir("/proc");
    if (!proc)
      return false;
    constexpr size_t kMaxProcEntries = 262144;
    size_t examined = 0;
    bool valid = true;
    const pid_t self = getpid();
    for (;;) {
      errno = 0;
      dirent *entry = readdir(proc);
      if (!entry) {
        if (errno != 0)
          valid = false;
        break;
      }
      if (++examined > kMaxProcEntries) {
        valid = false;
        break;
      }
      char *tail = nullptr;
      long value = strtol(entry->d_name, &tail, 10);
      if (!tail || *tail != 0 || value <= 0 || value > INT_MAX ||
          value == self)
        continue;
      const pid_t candidate = static_cast<pid_t>(value);
      if (read_proc_parent(candidate) == self)
        children->push_back(candidate);
    }
    closedir(proc);
    if (!valid)
      children->clear();
    return valid;
  }
  constexpr size_t kMaxChildListBytes = 1024 * 1024;
  constexpr size_t kMaxChildren = 65536;
  size_t consumed = 0;
  uint64_t value = 0;
  bool have_digit = false;
  bool valid = true;
  char buffer[4096];
  for (;;) {
    ssize_t amount = read(fd, buffer, sizeof(buffer));
    if (amount < 0 && errno == EINTR)
      continue;
    if (amount < 0) {
      valid = false;
      break;
    }
    if (amount == 0)
      break;
    consumed += static_cast<size_t>(amount);
    if (consumed > kMaxChildListBytes) {
      valid = false;
      break;
    }
    for (ssize_t i = 0; i < amount; i++) {
      const unsigned char c = static_cast<unsigned char>(buffer[i]);
      if (c >= '0' && c <= '9') {
        if (value > (static_cast<uint64_t>(INT_MAX) - (c - '0')) / 10) {
          valid = false;
          break;
        }
        value = value * 10 + (c - '0');
        have_digit = true;
      } else if (c == ' ' || c == '\n' || c == '\t') {
        if (have_digit) {
          if (value == 0 || children->size() >= kMaxChildren) {
            valid = false;
            break;
          }
          children->push_back(static_cast<pid_t>(value));
          value = 0;
          have_digit = false;
        }
      } else {
        valid = false;
        break;
      }
    }
    if (!valid)
      break;
  }
  close(fd);
  if (valid && have_digit) {
    if (value == 0 || children->size() >= kMaxChildren)
      valid = false;
    else
      children->push_back(static_cast<pid_t>(value));
  }
  if (!valid)
    children->clear();
  return valid;
}

static void reap_available_children() {
  for (;;) {
    int status = 0;
    errno = 0;
    const pid_t waited = waitpid(-1, &status, WNOHANG | __WALL);
    if (waited > 0)
      continue;
    if (waited < 0 && errno == EINTR)
      continue;
    return;
  }
}

// While analysis is live, deliberately leave the announced target as an
// unreaped zombie if it exits. That pins its numeric PID against reuse until
// the analyzer closes the control pipe, so later ptrace attempts can only fail
// against the original task rather than attach to a replacement. Other direct
// children adopted by the subreaper may still be reaped normally.
static void reap_adopted_children_except(pid_t retained_target) {
  std::vector<pid_t> children;
  if (!read_direct_children(&children))
    return;
  for (pid_t child : children) {
    if (child <= 0 || child == retained_target)
      continue;
    for (;;) {
      int status = 0;
      errno = 0;
      const pid_t waited = waitpid(child, &status, WNOHANG | __WALL);
      if (waited == child || (waited < 0 && errno == ECHILD))
        break;
      if (waited < 0 && errno == EINTR)
        continue;
      break;
    }
  }
}

[[noreturn]] static void run_launch_supervisor(
    int control_read, int announcement_write, int target_gate_read,
    int target_gate_write, const DirectLaunchTarget *direct_target,
    const std::string *launch_cmd, const sigset_t *child_signal_mask) {
  // This process is outside the analyzer's session so a terminal signal aimed
  // at Hayabusa cannot kill the only descendant owner. It remains root and is
  // the nearest subreaper; direct --launch targets are privilege-dropped only
  // in the target grandchild.
  if (setsid() < 0 || prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
    const LaunchAnnouncement failure{errno ? errno : EINVAL, -1};
    (void)write_exact_fd(announcement_write, &failure, sizeof(failure));
    _exit(125);
  }

  pid_t target = fork();
  if (target == 0) {
    close(control_read);
    close(announcement_write);
    close(target_gate_write);
    if (!child_signal_mask ||
        sigprocmask(SIG_SETMASK, child_signal_mask, nullptr) != 0)
      _exit(126);
    char release = 0;
    ssize_t amount;
    do {
      amount = read(target_gate_read, &release, 1);
    } while (amount < 0 && errno == EINTR);
    close(target_gate_read);
    if (amount != 1 || release != 1)
      _exit(126);

    if (launch_cmd && !launch_cmd->empty()) {
      // Shell launch is an explicit root-authority boundary, but it still must
      // not inherit unrelated analyzer descriptors or its secret environment.
      int rc;
      do {
        rc = static_cast<int>(
            syscall(SYS_close_range, 3u, ~0u, CLOSE_RANGE_CLOEXEC));
      } while (rc < 0 && errno == EINTR);
      if (rc < 0) {
        if (errno != ENOSYS && errno != EINVAL)
          _exit(126);
        long open_max = sysconf(_SC_OPEN_MAX);
        if (open_max < 0 || open_max > 1048576)
          open_max = 1048576;
        for (int fd = 3; fd < open_max; fd++) {
          if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0 && errno != EBADF)
            _exit(126);
        }
      }
      execle(kAndroidShellPath, "sh", "-c", launch_cmd->c_str(),
             (char *)nullptr, kMinimalAndroidEnvironment);
      _exit(127);
    }
    if (direct_target)
      exec_direct_launch_target(*direct_target);
    _exit(127);
  }

  close(target_gate_read);
  close(target_gate_write);
  if (target < 0) {
    const LaunchAnnouncement failure{errno ? errno : EAGAIN, -1};
    (void)write_exact_fd(announcement_write, &failure, sizeof(failure));
    _exit(125);
  }

  int target_pidfd = open_verified_pidfd(target);
  LaunchAnnouncement announcement;
  announcement.status = target_pidfd >= 0 ? 0 : (errno ? errno : EIO);
  announcement.target_pid = target_pidfd >= 0 ? target : -1;
  const bool announced =
      write_exact_fd(announcement_write, &announcement, sizeof(announcement));
  close(announcement_write);
  // The target retains its own copies. The supervisor is deliberately silent;
  // dropping the transport descriptors lets the analyzer return a verified
  // failure even if an unkillable descendant forces this containment process
  // to remain alive indefinitely.
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  if (!announced || target_pidfd < 0) {
    if (target_pidfd >= 0)
      (void)pidfd_signal(target_pidfd, SIGKILL);
  } else {
    // EOF, not a numeric signal, is the cleanup command. Reap zombies while
    // waiting so a target which exits early does not evade later descendant
    // adoption through a stale parent relationship.
    for (;;) {
      struct pollfd pfd { control_read, POLLIN | POLLHUP | POLLERR, 0 };
      int polled = poll(&pfd, 1, 250);
      if (polled < 0 && errno == EINTR)
        continue;
      reap_adopted_children_except(target);
      if (polled > 0 &&
          (pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
        if (pfd.revents & POLLNVAL)
          break;
        char discard[32];
        const ssize_t amount = read(control_read, discard, sizeof(discard));
        if (amount <= 0 || (pfd.revents & (POLLHUP | POLLERR)))
          break;
        // Any control byte also requests teardown; the current parent only
        // closes the pipe, but accepting a byte keeps the protocol fail-safe.
        break;
      }
      if (polled < 0)
        break;
    }
  }
  close(control_read);

  if (target_pidfd >= 0)
    (void)pidfd_signal(target_pidfd, SIGKILL);

  // Continue until the subreaper has no children. There is intentionally no
  // deadline here: exiting while an unkillable/D-state descendant remains
  // would release it to init. The analyzer waits only five seconds and reports
  // cleanup failure; this supervisor remains as the containment owner.
  unsigned empty_passes = 0;
  for (;;) {
    reap_available_children();
    std::vector<pid_t> children;
    if (!read_direct_children(&children)) {
      empty_passes = 0;
      usleep(10000);
      continue;
    }
    if (children.empty()) {
      errno = 0;
      int status = 0;
      const pid_t waited = waitpid(-1, &status, WNOHANG | __WALL);
      if (waited < 0 && errno == ECHILD) {
        if (++empty_passes >= 2)
          break;
      } else {
        empty_passes = 0;
      }
      usleep(10000);
      continue;
    }
    empty_passes = 0;
    const pid_t self = getpid();
    for (pid_t child : children) {
      int child_pidfd = open_verified_pidfd(child);
      if (child_pidfd < 0)
        continue;
      // pidfd_open binds first; the PPid recheck proves that the bound object
      // is still a descendant adopted by this exact supervisor.
      if (read_proc_parent(child) == self)
        (void)pidfd_signal(child_pidfd, SIGKILL);
      close(child_pidfd);
    }
    usleep(1000);
  }
  if (target_pidfd >= 0)
    close(target_pidfd);
  _exit(0);
}

class LaunchSupervisorHandle {
public:
  LaunchSupervisorHandle() = default;
  LaunchSupervisorHandle(const LaunchSupervisorHandle &) = delete;
  LaunchSupervisorHandle &operator=(const LaunchSupervisorHandle &) = delete;
  LaunchSupervisorHandle(LaunchSupervisorHandle &&other) noexcept
      : supervisor_(other.supervisor_), target_(other.target_),
        supervisor_pidfd_(other.supervisor_pidfd_),
        control_write_(other.control_write_), gate_write_(other.gate_write_),
        error_(std::move(other.error_)) {
    other.supervisor_ = -1;
    other.target_ = -1;
    other.supervisor_pidfd_ = -1;
    other.control_write_ = -1;
    other.gate_write_ = -1;
  }
  ~LaunchSupervisorHandle() {
    if (gate_write_ >= 0)
      close(gate_write_);
    if (control_write_ >= 0)
      close(control_write_);
    if (supervisor_ > 0)
      reap_child_bounded(supervisor_, std::chrono::seconds(5));
    if (supervisor_pidfd_ >= 0)
      close(supervisor_pidfd_);
  }
  explicit operator bool() const {
    return supervisor_ > 0 && target_ > 0 && supervisor_pidfd_ >= 0 &&
           control_write_ >= 0 && gate_write_ >= 0;
  }
  pid_t target() const { return target_; }
  const std::string &error() const { return error_; }
  bool publish(PublishedLaunchGuard *guard) {
    if (!guard || !*this ||
        !guard->adopt(supervisor_, supervisor_pidfd_, control_write_))
      return false;
    supervisor_ = -1;
    supervisor_pidfd_ = -1;
    control_write_ = -1;
    return true;
  }
  bool release_target() {
    if (gate_write_ < 0)
      return false;
    const char release = 1;
    const bool sent = write_exact_fd(gate_write_, &release, 1);
    close(gate_write_);
    gate_write_ = -1;
    return sent;
  }

  static LaunchSupervisorHandle start(
      const DirectLaunchTarget *direct_target, const std::string *launch_cmd,
      const sigset_t *child_signal_mask) {
    LaunchSupervisorHandle result;
    if ((!direct_target || !*direct_target) &&
        (!launch_cmd || launch_cmd->empty())) {
      result.error_ = "no launch target was supplied";
      return result;
    }
    // pipe()/pidfd_open() may legally allocate descriptors 0, 1, or 2 when a
    // caller starts Hayabusa with a standard stream closed. The supervisor
    // deliberately closes its standard streams after announcing the target;
    // reserve every missing slot first so that action can never destroy a
    // control pipe or exact-identity pidfd. The parent restores the caller's
    // original closed-FD state immediately after fork.
    bool reserved_standard[3] = {false, false, false};
    auto close_standard_reservations = [&]() {
      for (int fd = 0; fd < 3; fd++)
        if (reserved_standard[fd])
          close(fd);
    };
    for (int fd = 0; fd < 3; fd++) {
      errno = 0;
      if (fcntl(fd, F_GETFD) >= 0)
        continue;
      if (errno != EBADF) {
        result.error_ = "could not inspect launch standard descriptors";
        close_standard_reservations();
        return result;
      }
      int reserve = open("/dev/null", O_RDWR | O_CLOEXEC);
      if (reserve < 0) {
        result.error_ = "could not reserve closed launch descriptor: " +
                        std::string(strerror(errno));
        close_standard_reservations();
        return result;
      }
      if (reserve != fd) {
        if (dup3(reserve, fd, O_CLOEXEC) != fd) {
          const int saved_errno = errno;
          close(reserve);
          result.error_ = "could not reserve closed launch descriptor: " +
                          std::string(strerror(saved_errno));
          close_standard_reservations();
          return result;
        }
        close(reserve);
      }
      reserved_standard[fd] = true;
    }
    int control[2] = {-1, -1};
    int announcement[2] = {-1, -1};
    int gate[2] = {-1, -1};
    if (pipe(control) != 0 || pipe(announcement) != 0 || pipe(gate) != 0) {
      result.error_ = "could not create launch-supervisor pipes: " +
                      std::string(strerror(errno));
      for (int fd : {control[0], control[1], announcement[0],
                     announcement[1], gate[0], gate[1]})
        if (fd >= 0)
          close(fd);
      close_standard_reservations();
      return result;
    }
    for (int fd : {control[0], control[1], announcement[0],
                   announcement[1], gate[0], gate[1]}) {
      if (!set_cloexec(fd)) {
        result.error_ = "could not secure launch-supervisor descriptors";
        for (int close_fd : {control[0], control[1], announcement[0],
                             announcement[1], gate[0], gate[1]})
          close(close_fd);
        close_standard_reservations();
        return result;
      }
    }

    const pid_t supervisor = fork();
    if (supervisor == 0) {
      close(control[1]);
      close(announcement[0]);
      run_launch_supervisor(control[0], announcement[1], gate[0], gate[1],
                            direct_target, launch_cmd, child_signal_mask);
    }
    close_standard_reservations();
    close(control[0]);
    close(announcement[1]);
    close(gate[0]);
    if (supervisor < 0) {
      result.error_ = "could not fork launch supervisor: " +
                      std::string(strerror(errno));
      close(control[1]);
      close(announcement[0]);
      close(gate[1]);
      return result;
    }

    const int supervisor_pidfd = open_verified_pidfd(supervisor);
    LaunchAnnouncement announced;
    const bool got_announcement =
        read_exact_fd_until(announcement[0], &announced, sizeof(announced),
                            std::chrono::seconds(2));
    close(announcement[0]);
    if (supervisor_pidfd < 0 || !got_announcement || announced.status != 0 ||
        announced.target_pid <= 0 ||
        !pidfd_signal(supervisor_pidfd, 0)) {
      result.error_ = "launch supervisor failed before target publication";
      close(gate[1]);
      close(control[1]);
      reap_child_bounded(supervisor, std::chrono::seconds(5));
      if (supervisor_pidfd >= 0)
        close(supervisor_pidfd);
      return result;
    }
    result.supervisor_ = supervisor;
    result.target_ = announced.target_pid;
    result.supervisor_pidfd_ = supervisor_pidfd;
    result.control_write_ = control[1];
    result.gate_write_ = gate[1];
    return result;
  }

private:
  pid_t supervisor_ = -1;
  pid_t target_ = -1;
  int supervisor_pidfd_ = -1;
  int control_write_ = -1;
  int gate_write_ = -1;
  std::string error_;
};

// Deterministic unpack tracing.
//
// Snapshot polling is a guess: you dump every N milliseconds and hope the
// packer had finished. A packer, however, cannot execute code it produced
// without asking the kernel to make that memory executable, so mmap/mprotect
// are chokepoints it cannot avoid. Two design points make the observation
// deterministic rather than lucky:
//
//   * a launched target is held behind a pre-exec pipe gate, then seized before
//     that gate opens. TRACEEXEC catches its new image before the first target
//     instruction -- attaching later would lose loader/constructor activity;
//   * interception happens at the syscall boundary, not at libc entry points,
//     so a packer issuing `svc` directly is caught just the same.
//
// Multi-threaded targets are followed: PTRACE_O_TRACEFORK/TRACEVFORK/TRACECLONE
// pick up processes and threads as they are created, and the live-tid set below
// tracks them so the trace only ends when the last one is gone.
bool cmd_unpack(const std::string &pkg, int timeout_sec,
                bool launch, const std::string &launch_cmd, size_t limit,
                uint64_t region_limit) {
  const uint64_t SYS_MMAP = 222;
  const uint64_t SYS_MPROTECT = 226;
  using MonotonicClock = std::chrono::steady_clock;

  std::cout << "\n=== HAYABUSA UNPACK TRACE ===\n";
  std::cout << "Target: " << pkg << "\n\n";

  DirectLaunchTarget direct_target;
  if (launch && launch_cmd.empty()) {
    direct_target = open_direct_launch_target(pkg);
    if (!direct_target)
      return false;
  }

  SecureRunDirectory output = open_run_out_dir(pkg, "_unpack");
  if (!output) {
    std::cout << "[!] " << output.error() << "\n";
    return false;
  }
  const std::string out = output.io_path();
  const std::string out_display = output.display_path();

  int pid = -1;
  int launched_pidfd = -1;
  PublishedLaunchGuard launch_guard;
  bool we_started_it = false;
  if (launch || !launch_cmd.empty()) {
    std::cout << "[1] Starting target under trace (from first instruction)\n";
    std::cout.flush();

    LaunchPublishSignalBlock publish_block;
    if (!publish_block.active()) {
      std::cout << "[!] could not block launch signals\n";
      return false;
    }

    LaunchSupervisorHandle supervised = LaunchSupervisorHandle::start(
        launch_cmd.empty() ? &direct_target : nullptr,
        launch_cmd.empty() ? nullptr : &launch_cmd,
        publish_block.previous_mask());
    if (!supervised) {
      std::cout << "[!] " << supervised.error() << "\n";
      return false;
    }
    pid = supervised.target();
    launched_pidfd = open_verified_pidfd(pid);
    if (launched_pidfd < 0 || !pidfd_signal(launched_pidfd, 0)) {
      if (launched_pidfd >= 0)
        close(launched_pidfd);
      launched_pidfd = -1;
      std::cout << "[!] could not pin launched target identity\n";
      return false;
    }
    if (!supervised.publish(&launch_guard)) {
      close(launched_pidfd);
      launched_pidfd = -1;
      std::cout << "[!] another launched process tree is already active\n";
      return false;
    }
    if (!publish_block.restore()) {
      close(launched_pidfd);
      launched_pidfd = -1;
      std::cout << "[!] could not restore the launch signal mask\n";
      return false;
    }
    // The child cannot exec until this parent releases the pipe gate. Attach
    // with SEIZE/INTERRUPT first, while its entire pre-exec state is still
    // controlled; TRACEEXEC observes the first executable image and
    // TRACEFORK/VFORK/CLONE follows any real child a shell command creates.
    if (!ProcessTracer::attach(pid)) {
      close(launched_pidfd);
      launched_pidfd = -1;
      std::cout << "[!] failed to seize launched target\n";
      return false;
    }
    if (!pidfd_signal(launched_pidfd, 0)) {
      ProcessTracer::detach(pid);
      close(launched_pidfd);
      launched_pidfd = -1;
      std::cout << "[!] launched target identity changed while attaching\n";
      return false;
    }
    // Install fork/clone/exec options while the target is still pipe-gated;
    // releasing first leaves a scheduler-sized gap in which loader children
    // can escape before PTRACE_O_TRACE* is active.
    bool options_ok = true;
    for (int tid : ProcessTracer::list_threads(pid))
      options_ok = ProcessTracer::follow_children(tid) && options_ok;
    if (!options_ok || !supervised.release_target()) {
      std::cout << "[!] could not release launch handshake\n";
      ProcessTracer::detach(pid);
      close(launched_pidfd);
      launched_pidfd = -1;
      return false;
    }
    we_started_it = true;
    std::cout << "[2] Seized pid " << pid << " before exec\n";
  } else {
    auto emit = [](const std::string &m) { std::cout << m; };
    pid = wait_for_process(pkg, emit, timeout_sec);
    if (pid < 0)
      return false;
    if (!ProcessTracer::attach(pid)) {
      std::cout << "[!] Failed to attach to " << pid << "\n";
      return false;
    }
    std::cout << "    [i] Attached to a running process; anything unpacked "
                 "before now is already missed.\n";
  }
  std::cout.flush();

  std::ofstream log(out + "/unpack_trace.txt");
  if (!log) {
    std::cout << "[!] Could not create " << out_display
              << "/unpack_trace.txt\n";
    ProcessTracer::detach(pid);
    if (launched_pidfd >= 0)
      close(launched_pidfd);
    return false;
  }
  log << "=== DETERMINISTIC UNPACK TRACE ===\n"
      << "Every mmap/mprotect requesting PROT_EXEC, observed at the syscall "
         "boundary.\n\n";

  size_t events = 0, exec_events = 0, dumps = 0;
  struct PendingSyscall {
    uint64_t number = 0;
    uint64_t args[6] = {0};
  };
  struct PendingExecRegion {
    int tgid = -1;
    uint64_t addr = 0;
    uint64_t len = 0;
    std::string description;
  };
  std::map<int, PendingSyscall> pending;
  std::map<int, bool> fallback_at_exit;
  std::map<std::pair<int, uint64_t>, PendingExecRegion> pending_regions;
  bool output_ok = true;

  auto read_tgid = [](int tid) {
    std::ifstream status("/proc/" + std::to_string(tid) + "/status");
    std::string line;
    while (std::getline(status, line)) {
      if (line.rfind("Tgid:", 0) != 0)
        continue;
      const char *p = line.c_str() + 5;
      while (*p == ' ' || *p == '\t')
        p++;
      int tgid = atoi(p);
      return tgid > 0 ? tgid : tid;
    }
    return tid;
  };

  enum class CaptureResult {
    Captured,
    Empty,
    Unreadable,
    Skipped,
    OutputError,
  };
  auto capture_region = [&](int reader_tid, uint64_t addr, uint64_t len,
                            const std::string &description) {
    if ((region_limit != 0 && len > region_limit) || dumps >= limit)
      return CaptureResult::Skipped;
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    if (!ProcessTracer::read_memory(reader_tid, addr, buf.data(), buf.size()))
      return CaptureResult::Unreadable;
    if (std::all_of(buf.begin(), buf.end(),
                    [](uint8_t byte) { return byte == 0; }))
      return CaptureResult::Empty;

    std::ostringstream p;
    p << out << "/exec_" << dumps << "_0x" << std::hex << addr << std::dec
      << ".bin";
    std::ostringstream display_path;
    display_path << out_display << "/exec_" << dumps << "_0x" << std::hex
                 << addr << std::dec << ".bin";
    std::ofstream f(p.str(), std::ios::binary);
    if (!f) {
      output_ok = false;
      return CaptureResult::OutputError;
    }
    f.write(reinterpret_cast<const char *>(buf.data()), buf.size());
    if (!f) {
      output_ok = false;
      return CaptureResult::OutputError;
    }
    log << "    captured " << len << " bytes -> " << display_path.str()
        << " (" << description << ")\n";
    if (ElfParser::is_elf(buf))
      log << "    [!] region carries an ELF header\n";
    dumps++;
    return CaptureResult::Captured;
  };

  auto erase_pending_overlap = [&](int tgid, uint64_t addr, uint64_t len) {
    const uint64_t end =
        addr > std::numeric_limits<uint64_t>::max() - len
            ? std::numeric_limits<uint64_t>::max()
            : addr + len;
    for (auto it = pending_regions.begin(); it != pending_regions.end();) {
      const PendingExecRegion &region = it->second;
      const uint64_t region_end =
          region.addr > std::numeric_limits<uint64_t>::max() - region.len
              ? std::numeric_limits<uint64_t>::max()
              : region.addr + region.len;
      if (region.tgid == tgid && addr < region_end && region.addr < end)
        it = pending_regions.erase(it);
      else
        ++it;
    }
  };

  auto retry_pending_regions = [&](int stopped_tid) {
    int tgid = read_tgid(stopped_tid);
    for (auto it = pending_regions.begin(); it != pending_regions.end();) {
      PendingExecRegion &region = it->second;
      if (region.tgid != tgid) {
        ++it;
        continue;
      }
      CaptureResult result = capture_region(stopped_tid, region.addr,
                                            region.len, region.description);
      if (result == CaptureResult::Empty) {
        ++it;
        continue;
      }
      if (result == CaptureResult::Captured)
        log << "    pending RWX payload became non-empty\n";
      else if (result == CaptureResult::Unreadable)
        log << "    pending RWX region disappeared before capture\n";
      it = pending_regions.erase(it);
    }
  };

  auto capture_exec_mapping = [&](int tid, const PendingSyscall &call,
                                  int64_t result, bool is_error) {
    if (is_error)
      return;

    uint64_t addr = call.args[0];
    const uint64_t len = call.args[1];
    const uint64_t prot = call.args[2];
    if (call.number == SYS_MMAP) {
      if (result <= 0)
        return;
      addr = static_cast<uint64_t>(result);
    } else if (call.number == SYS_MPROTECT && result != 0) {
      return;
    }

    events++;
    if (!addr || !len || !(prot & PROT_EXEC))
      return;
    exec_events++;

    std::ostringstream ss;
    ss << (call.number == SYS_MMAP ? "mmap" : "mprotect") << "(0x"
       << std::hex << addr << ", 0x" << len << ", prot=0x" << prot << ")"
       << std::dec << "  [tid " << tid << "]";
    std::cout << "    [+] " << ss.str() << "\n";
    std::cout.flush();
    log << ss.str() << "\n";

    int tgid = read_tgid(tid);
    CaptureResult captured =
        capture_region(tid, addr, len, ss.str());
    if (captured == CaptureResult::Captured) {
      erase_pending_overlap(tgid, addr, len);
    } else if (captured == CaptureResult::Empty &&
               call.number == SYS_MMAP && (prot & PROT_WRITE)) {
      PendingExecRegion region;
      region.tgid = tgid;
      region.addr = addr;
      region.len = len;
      region.description = ss.str();
      pending_regions[{tgid, addr}] = std::move(region);
      log << "    RWX mapping is empty; capture deferred until a later stop\n";
    }
  };

  // Seed with every thread that already exists. When we attached to a running
  // process the target may have dozens; starting from just {pid} would end the
  // trace the moment the leader exited, while workers were still running.
  std::set<int> threads;
  for (int tid : ProcessTracer::list_threads(pid))
    threads.insert(tid);
  threads.insert(pid);
  std::set<int> group_threads = threads;
  std::set<int> separate_tracees;
  std::map<int, int> separate_tracee_tgids;
  size_t threads_seen = threads.size(); // high-water mark, for the summary
  std::set<int> needs_options;
  std::set<int> newborn_stops;
  std::set<int> early_newborn_stops;
  // GETEVENTMSG names an auto-attached child before its own initial event-stop
  // is necessarily available to waitpid. Ownership is claimed only after that
  // stop has been consumed, when TracerPid, Tgid and the descendant leader's
  // pidfd can be checked as one frozen identity.
  std::set<int> pending_ownership;
  std::set<int> stopped_for_shutdown = threads;
  bool trace_ok = true;
  bool preserved_group_stop = false;
  bool launched_exec_observed = !we_started_it;
  bool launched_failed_before_shutdown = false;
  int launched_exit_code = 0;

  auto record_new_tracee_ownership = [&](int child) {
    int child_tgid = 0;
    bool original_group = false;
    // Even after waitpid reports the initial stop, procfs publication can lag
    // briefly. The claim routine is idempotent and never publishes a bare
    // numeric worker TID, so a bounded retry is safe.
    for (int retry = 0; retry < 200; retry++) {
      if (ProcessTracer::claim_auto_attached_tracee(
              pid, child, &child_tgid, &original_group))
        break;
      usleep(1000);
    }
    if (child_tgid <= 0)
      return false;
    if (original_group) {
      group_threads.insert(child);
      return true;
    }
    separate_tracees.insert(child);
    separate_tracee_tgids[child] = child_tgid;
    return true;
  };

  auto forget_separate_tracee = [&](int tid) {
    auto owner = separate_tracee_tgids.find(tid);
    if (owner == separate_tracee_tgids.end())
      return;
    const int tgid = owner->second;
    ProcessTracer::forget_auto_attached_tracee(tgid, tid);
    separate_tracee_tgids.erase(owner);
    separate_tracees.erase(tid);
    const bool group_remains = std::any_of(
        separate_tracee_tgids.begin(), separate_tracee_tgids.end(),
        [&](const auto &entry) { return entry.second == tgid; });
    if (!group_remains)
      ProcessTracer::untrack_auto_attached_child(tgid);
  };

  // PTRACE options are per tracee. ProcessTracer::attach() stops every existing
  // TID, so configure each one before any is allowed to run.
  for (int tid : threads) {
    if (!ProcessTracer::follow_children(tid)) {
      std::cout << "[!] Could not enable syscall/child tracing for TID " << tid
                << "\n";
      log << "failed to set ptrace options on " << tid << "\n";
      trace_ok = false;
    }
  }
  if (trace_ok)
    std::cout << "    Following " << threads.size()
              << " existing thread(s) and future descendants\n";

  PatchSignalWindow signal_window;
  if (trace_ok && !signal_window.prepare()) {
    std::cout << "[!] Could not install the trace termination handler\n";
    trace_ok = false;
  }

  if (trace_ok) {
    for (int tid : threads) {
      if (!ProcessTracer::syscall_step(tid)) {
        std::cout << "[!] Could not start syscall tracing for TID " << tid
                  << "\n";
        log << "failed to resume " << tid << " with PTRACE_SYSCALL\n";
        trace_ok = false;
        break;
      }
      stopped_for_shutdown.erase(tid);
    }
  }
  if (trace_ok && !signal_window.unblock()) {
    std::cout << "[!] Could not enable cooperative termination signals\n";
    trace_ok = false;
  }

  auto deadline = timeout_sec > 0
                      ? MonotonicClock::now() +
                            std::chrono::seconds(timeout_sec)
                      : MonotonicClock::time_point::max();
  bool timed_out = false;
  bool interrupted = false;
  while (trace_ok && g_hook_running.load(std::memory_order_relaxed) &&
         !threads.empty()) {
    if (MonotonicClock::now() >= deadline) {
      timed_out = true;
      break;
    }

    int st = 0;
    // __WALL: without it waitpid ignores non-leader threads, so a packer that
    // does its work on a worker thread is never observed.
    // WNOHANG is equally important: a blocking wait makes --timeout advisory
    // when a compute-only tracee performs no further syscalls.
    pid_t w = waitpid(-1, &st, WNOHANG | __WALL);
    if (w == 0) {
      usleep(1000);
      continue;
    }
    if (w < 0) {
      if (errno == EINTR)
        continue;
      if (errno == ECHILD) {
        threads.clear();
        break;
      }
      std::cout << "[!] waitpid failed: " << strerror(errno) << "\n";
      log << "waitpid failed: " << strerror(errno) << "\n";
      trace_ok = false;
      break;
    }

    if (WIFEXITED(st) || WIFSIGNALED(st)) {
      if (we_started_it && w == pid) {
        if (WIFEXITED(st)) {
          launched_exit_code = WEXITSTATUS(st);
          launched_failed_before_shutdown = launched_exit_code != 0;
          log << "launched leader exited status=" << launched_exit_code
              << "\n";
        } else {
          launched_exit_code = 128 + WTERMSIG(st);
          launched_failed_before_shutdown = true;
          log << "launched leader terminated by signal=" << WTERMSIG(st)
              << "\n";
        }
      }
      threads.erase(w);
      stopped_for_shutdown.erase(w);
      pending.erase(w);
      fallback_at_exit.erase(w);
      needs_options.erase(w);
      newborn_stops.erase(w);
      early_newborn_stops.erase(w);
      pending_ownership.erase(w);
      group_threads.erase(w);
      forget_separate_tracee(w);
      if (threads.empty())
        log << "target exited\n";
      continue;
    }
    if (!WIFSTOPPED(st)) {
      continue;
    }
    const int event = (st >> 16) & 0xFF;
    if (threads.count(w) == 0) {
      if (event == 128) {
        // A seized auto-child's initial event-stop may beat the parent's
        // FORK/VFORK/CLONE report. Keep it stopped and unknown until
        // GETEVENTMSG proves both its identity and ownership class.
        early_newborn_stops.insert(w);
        stopped_for_shutdown.insert(w);
        log << "early child event-stop tid=" << w << "\n";
        continue;
      }
      std::cout << "[!] Unexpected stop from unknown TID " << w << "\n";
      log << "unknown tracee stop tid=" << w << " event=" << event << "\n";
      early_newborn_stops.insert(w);
      stopped_for_shutdown.insert(w);
      trace_ok = false;
      break;
    }
    stopped_for_shutdown.insert(w);
    retry_pending_regions(w);

    // A new thread or child: start tracing it too.
    if (event != 0)
      log << "ptrace event=" << event << " tid=" << w << "\n";
    if (event == 1 || event == 2 || event == 3) { // FORK / VFORK / CLONE
      int child = 0;
      if (ProcessTracer::event_child(w, &child) && child > 0) {
        if (threads.insert(child).second)
          threads_seen++;
        log << "new thread " << child << "\n";
        pending_ownership.insert(child);
        // The new tracee has its own initial stop. Configure and resume it when
        // waitpid reports that stop; doing so here races its creation.
        needs_options.insert(child);
        newborn_stops.insert(child);
        // On kernels without PTRACE_GET_SYSCALL_INFO the child resumes at the
        // exit side of the clone/fork syscall, unlike the fresh-exec leader.
        fallback_at_exit[child] = true;

        // If the child's event-stop arrived first, it is already safe to
        // configure and resume now that the parent event established identity.
        if (early_newborn_stops.erase(child) != 0) {
          if (pending_ownership.erase(child) == 0 ||
              !record_new_tracee_ownership(child)) {
            std::cout << "[!] Could not record ownership for new TID "
                      << child << "\n";
            log << "early new tracee ownership failed: " << child << "\n";
            ptrace(PTRACE_KILL, child, nullptr, nullptr);
            kill(pid, SIGKILL);
            trace_ok = false;
            break;
          }
          newborn_stops.erase(child);
          needs_options.erase(child);
          retry_pending_regions(child);
          if (!ProcessTracer::follow_children(child) ||
              !ProcessTracer::syscall_step(child)) {
            std::cout << "[!] Could not start tracing early child TID "
                      << child << "\n";
            log << "early child setup failed: " << child << "\n";
            trace_ok = false;
            break;
          }
          stopped_for_shutdown.erase(child);
        }
      } else {
        std::cout << "[!] Could not read new child event from TID " << w
                  << "\n";
        log << "failed child event lookup: " << w << "\n";
        trace_ok = false;
        break;
      }
      if (!trace_ok)
        break;
      if (!ProcessTracer::syscall_step(w)) {
        std::cout << "[!] Could not resume parent TID " << w
                  << " after child event\n";
        trace_ok = false;
        break;
      }
      stopped_for_shutdown.erase(w);
      continue;
    }
    if (event == 128 && newborn_stops.erase(w) != 0) {
      if (pending_ownership.erase(w) == 0 ||
          !record_new_tracee_ownership(w)) {
        std::cout << "[!] Could not record ownership for new TID " << w
                  << "\n";
        log << "new tracee ownership failed at event-stop: " << w << "\n";
        ptrace(PTRACE_KILL, w, nullptr, nullptr);
        kill(pid, SIGKILL);
        trace_ok = false;
        break;
      }
      if (needs_options.erase(w) != 0 &&
          !ProcessTracer::follow_children(w)) {
        std::cout << "[!] Could not enable child tracing for new TID " << w
                  << "\n";
        log << "failed to set ptrace options on new tracee " << w << "\n";
        trace_ok = false;
        break;
      }
      if (!ProcessTracer::syscall_step(w)) {
        std::cout << "[!] Could not resume new TID " << w
                  << " after its initial event-stop\n";
        log << "new tracee event-stop resume failed: " << w << "\n";
        trace_ok = false;
        break;
      }
      stopped_for_shutdown.erase(w);
      continue;
    }
    const bool deferred_sigstop_child =
        event == 0 && WSTOPSIG(st) == SIGSTOP &&
        newborn_stops.count(w) != 0;
    if (!deferred_sigstop_child && needs_options.erase(w) != 0 &&
        !ProcessTracer::follow_children(w)) {
      std::cout << "[!] Could not enable child tracing for new TID " << w
                << "\n";
      log << "failed to set ptrace options on new tracee " << w << "\n";
      trace_ok = false;
      break;
    }
    if (event == 4) { // EXEC
      if (we_started_it && w == pid) {
        launched_exec_observed = true;
        log << "launched leader exec observed tid=" << w << "\n";
      }
      pending.erase(w);
      fallback_at_exit.erase(w);
      if (!ProcessTracer::syscall_step(w)) {
        std::cout << "[!] Could not resume TID " << w << " after exec\n";
        trace_ok = false;
        break;
      }
      stopped_for_shutdown.erase(w);
      continue;
    }

    // PTRACE_O_TRACESYSGOOD makes syscall stops unambiguous. Forward genuine
    // target signals instead of accidentally toggling entry/exit state on
    // them. A plain SIGTRAP is a real target signal here: ptrace events were
    // handled above and syscall traps carry the 0x80 bit.
    int stop_signal = WSTOPSIG(st);
    if (stop_signal != (SIGTRAP | 0x80)) {
      log << "signal stop=" << stop_signal << " tid=" << w << "\n";
      bool newborn_stop =
          stop_signal == SIGSTOP && newborn_stops.erase(w) != 0;
      if (newborn_stop) {
        if (pending_ownership.erase(w) == 0 ||
            !record_new_tracee_ownership(w)) {
          std::cout << "[!] Could not record SIGSTOP child ownership for TID "
                    << w << "\n";
          log << "SIGSTOP child ownership failed: " << w << "\n";
          ptrace(PTRACE_KILL, w, nullptr, nullptr);
          kill(pid, SIGKILL);
          trace_ok = false;
          break;
        }
        if (needs_options.erase(w) != 0 &&
            !ProcessTracer::follow_children(w)) {
          std::cout << "[!] Could not enable child tracing for new TID " << w
                    << "\n";
          trace_ok = false;
          break;
        }
      }
      const bool job_control_signal =
          stop_signal == SIGSTOP || stop_signal == SIGTSTP ||
          stop_signal == SIGTTIN || stop_signal == SIGTTOU;
      if (!newborn_stop && job_control_signal) {
        SignalStopKind kind =
            ProcessTracer::classify_signal_stop(w, stop_signal, event);
        if (kind == SignalStopKind::GroupStop) {
          // The job-control signal has already taken effect. Keep this exact
          // TID ptrace-stopped and end tracing; detach with signal 0 below
          // preserves the owner's group-stop without re-delivery or SIGCONT.
          preserved_group_stop = true;
          log << "preserving target group-stop on tid=" << w << "\n";
          break;
        }
        if (kind == SignalStopKind::Unknown) {
          std::cout << "[!] Could not classify job-control stop for TID " << w
                    << "\n";
          trace_ok = false;
          break;
        }
      }
      // Only the kernel-generated initial stop of an auto-followed child is
      // synthetic.  A SIGSTOP sent by the target/user is real job-control
      // state and must be forwarded; swallowing every SIGSTOP silently woke a
      // process which its owner had explicitly stopped.
      int deliver = newborn_stop ? 0 : stop_signal;
      if (!ProcessTracer::syscall_step(w, deliver)) {
        std::cout << "[!] Could not resume TID " << w
                  << " after signal stop\n";
        trace_ok = false;
        break;
      }
      stopped_for_shutdown.erase(w);
      continue;
    }

    SyscallStopInfo info;
    if (ProcessTracer::get_syscall_stop(w, &info)) {
      if (info.kind == SyscallStopKind::Entry) {
        if (info.number == SYS_MMAP || info.number == SYS_MPROTECT) {
          PendingSyscall call;
          call.number = info.number;
          memcpy(call.args, info.args, sizeof(call.args));
          pending[w] = call;
        } else {
          pending.erase(w);
        }
      } else if (info.kind == SyscallStopKind::Exit) {
        auto it = pending.find(w);
        if (it != pending.end()) {
          capture_exec_mapping(w, it->second, info.return_value,
                               info.is_error);
          pending.erase(it);
        }
      }
    } else {
      // Kernel <5.3 fallback. TRACESYSGOOD still guarantees these alternate
      // entry/exit stops; signal-delivery stops were handled above. An
      // attach can land inside a syscall, however, so its first stop may be
      // either entry or exit. Guessing here corrupts the entire phase.
      if (!we_started_it) {
        std::cout
            << "[!] Kernel lacks PTRACE_GET_SYSCALL_INFO; attach-mode "
               "entry/exit phase is ambiguous. Re-run with --launch or "
               "--launch-cmd.\n";
        log << "attach-mode fallback refused: syscall phase is ambiguous\n";
        trace_ok = false;
        break;
      }
      uint64_t nr = 0, args[8] = {0};
      if (ProcessTracer::get_syscall(w, &nr, args, 8)) {
        bool &at_exit = fallback_at_exit[w];
        if (!at_exit) {
          at_exit = true;
          if (nr == SYS_MMAP || nr == SYS_MPROTECT) {
            PendingSyscall call;
            call.number = nr;
            memcpy(call.args, args, sizeof(call.args));
            pending[w] = call;
          } else {
            pending.erase(w);
          }
        } else {
          at_exit = false;
          auto it = pending.find(w);
          if (it != pending.end()) {
            int64_t result = static_cast<int64_t>(args[0]);
            bool is_error = result < 0 && result >= -4095;
            capture_exec_mapping(w, it->second, result, is_error);
            pending.erase(it);
          }
        }
      } else {
        std::cout << "[!] Could not read syscall registers for TID " << w
                  << "\n";
        log << "failed to read syscall registers for " << w << "\n";
        trace_ok = false;
        break;
      }
    }

    if (MonotonicClock::now() >= deadline) {
      timed_out = true;
      break;
    }
    if (!ProcessTracer::syscall_step(w)) {
      std::cout << "[!] Could not continue syscall tracing for TID " << w
                << "\n";
      log << "failed to resume syscall tracee " << w << "\n";
      trace_ok = false;
      break;
    }
    stopped_for_shutdown.erase(w);
  }

  if (!g_hook_running.load(std::memory_order_relaxed) && !threads.empty())
    interrupted = true;

  // Timeout/error can leave tracees running between syscall stops. Every
  // attached TID was seized, so PTRACE_INTERRUPT quiesces without injecting
  // SIGSTOP into the target's job-control state. A syscall/event/signal stop
  // that wins the race is equally sufficient and leaves no interrupt debt.
  std::set<int> shutdown_live = threads;
  std::set<int> interrupt_requested;
  std::map<int, int> shutdown_pending_signal;
  std::set<int> unknown_event_stops = early_newborn_stops;
  bool shutdown_ok = true;

  auto forget_shutdown_tid = [&](int tid) {
    shutdown_live.erase(tid);
    stopped_for_shutdown.erase(tid);
    interrupt_requested.erase(tid);
    shutdown_pending_signal.erase(tid);
    unknown_event_stops.erase(tid);
    newborn_stops.erase(tid);
    pending_ownership.erase(tid);
    forget_separate_tracee(tid);
  };
  auto shutdown_ready = [&]() {
    if (!interrupt_requested.empty() || !unknown_event_stops.empty())
      return false;
    for (int tid : shutdown_live) {
      if (stopped_for_shutdown.count(tid) == 0)
        return false;
    }
    return true;
  };
  auto remember_shutdown_signal = [&](int tid, int signal) {
    auto it = shutdown_pending_signal.find(tid);
    if (it != shutdown_pending_signal.end() && it->second != signal)
      return false;
    shutdown_pending_signal[tid] = signal;
    return true;
  };
  auto release_descendant = [&](int tid, int signal) {
    int tracee_tgid = 0;
    auto owner = separate_tracee_tgids.find(tid);
    if (owner != separate_tracee_tgids.end())
      tracee_tgid = owner->second;
    if (tracee_tgid <= 0)
      (void)ProcessTracer::read_thread_group_id(tid, &tracee_tgid);
    const size_t group_members = static_cast<size_t>(std::count_if(
        separate_tracee_tgids.begin(), separate_tracee_tgids.end(),
        [&](const auto &entry) { return entry.second == tracee_tgid; }));
    const bool release_group = tracee_tgid > 0 && group_members <= 1;
    if (ProcessTracer::release_auto_attached_child(
            tid, signal, tracee_tgid, release_group))
      return true;
    // A vfork parent cannot finish its own interrupt while an ambiguous
    // child remains tracer-held. Make termination pending before retrying the
    // ownership release; failure after this is terminal for the whole trace.
    ptrace(PTRACE_KILL, tid, nullptr, nullptr);
    return ProcessTracer::release_auto_attached_child(
        tid, 0, tracee_tgid, release_group);
  };

  // A descendant that was already stopped can be released immediately. This
  // is required before a vfork parent can reach its own interrupt stop.
  for (int tid : std::vector<int>(shutdown_live.begin(), shutdown_live.end())) {
    if (group_threads.count(tid) != 0 ||
        stopped_for_shutdown.count(tid) == 0)
      continue;
    retry_pending_regions(tid);
    int deliver = we_started_it ? SIGKILL : 0;
    auto pending_signal = shutdown_pending_signal.find(tid);
    if (!we_started_it && pending_signal != shutdown_pending_signal.end())
      deliver = pending_signal->second;
    if (!release_descendant(tid, deliver)) {
      shutdown_ok = false;
      log << "could not release stopped descendant tid=" << tid << "\n";
      kill(pid, SIGKILL);
    }
    forget_shutdown_tid(tid);
  }

  for (int tid : std::vector<int>(shutdown_live.begin(), shutdown_live.end())) {
    if (stopped_for_shutdown.count(tid) != 0)
      continue;
    errno = 0;
    const bool requested = ProcessTracer::interrupt(tid);
    const int request_errno = errno;
    if (requested) {
      interrupt_requested.insert(tid);
      log << "shutdown interrupt requested tid=" << tid << "\n";
    } else if (request_errno == EIO) {
      // A stop raced our userspace state and is already pending for waitpid.
      // It carries no interrupt debt, but still has to be consumed below.
      log << "shutdown tid already has a pending stop=" << tid << "\n";
    } else if (!process_alive(tid)) {
      forget_shutdown_tid(tid);
    } else {
      shutdown_ok = false;
      log << "failed to interrupt shutdown tid=" << tid
          << " errno=" << request_errno << "\n";
    }
  }

  auto shutdown_deadline =
      MonotonicClock::now() + std::chrono::seconds(2);
  while (!shutdown_ready() && MonotonicClock::now() < shutdown_deadline) {
    int st = 0;
    pid_t w = waitpid(-1, &st, WNOHANG | __WALL);
    if (w == 0) {
      usleep(1000);
      continue;
    }
    if (w < 0) {
      if (errno == EINTR)
        continue;
      if (errno != ECHILD)
        log << "shutdown waitpid failed: " << strerror(errno) << "\n";
      shutdown_ok = false;
      break;
    }
    if (WIFEXITED(st) || WIFSIGNALED(st)) {
      forget_shutdown_tid(w);
      continue;
    }
    if (!WIFSTOPPED(st))
      continue;

    const bool known_tid = shutdown_live.count(w) != 0;
    stopped_for_shutdown.insert(w);
    const int stop_signal = WSTOPSIG(st);
    const int event = (st >> 16) & 0xFF;
    log << "shutdown stop tid=" << w << " signal=" << stop_signal
        << " event=" << event
        << " interrupt-pending="
        << (interrupt_requested.count(w) != 0 ? 1 : 0) << "\n";

    // Linux may report a child's initial PTRACE_EVENT_STOP before the parent's
    // FORK/VFORK/CLONE event. Hold that unknown stop until GETEVENTMSG names
    // the child; never resume or detach an unproven tracee.
    if (!known_tid) {
      unknown_event_stops.insert(w);
      if (event == 128) {
        continue;
      }
      shutdown_ok = false;
      log << "unexpected shutdown stop from unknown tid=" << w
          << " event=" << event << "\n";
      break;
    }

    retry_pending_regions(w);

    // A newly auto-followed child already owns a kernel-generated event stop.
    // Release it before its vfork parent, without issuing another interrupt.
    const bool newborn_initial_stop =
        newborn_stops.count(w) != 0 &&
        (event == 128 || (event == 0 && stop_signal == SIGSTOP));
    if (newborn_initial_stop) {
      newborn_stops.erase(w);
      interrupt_requested.erase(w);
      if (pending_ownership.erase(w) == 0 ||
          !record_new_tracee_ownership(w)) {
        shutdown_ok = false;
        log << "shutdown new tracee ownership failed: " << w << "\n";
        ptrace(PTRACE_KILL, w, nullptr, nullptr);
        kill(pid, SIGKILL);
        break;
      }
      if (group_threads.count(w) != 0)
        continue;
      if (!release_descendant(w, we_started_it ? SIGKILL : 0)) {
        shutdown_ok = false;
        log << "newborn detach remained ambiguous: " << w << "\n";
        kill(pid, SIGKILL);
      }
      forget_shutdown_tid(w);
      continue;
    }

    if (event == 1 || event == 2 || event == 3) {
      int child = 0;
      if (!ProcessTracer::event_child(w, &child) || child <= 0) {
        shutdown_ok = false;
        log << "could not read shutdown child event from tid=" << w << "\n";
        break;
      }
      if (shutdown_live.insert(child).second) {
        threads_seen++;
        newborn_stops.insert(child);
        pending_ownership.insert(child);
      }

      // Reconcile the order-independent child stop. It is safe to release only
      // after the parent's event proves the relationship.
      if (unknown_event_stops.erase(child) != 0) {
        if (pending_ownership.erase(child) == 0 ||
            !record_new_tracee_ownership(child)) {
          shutdown_ok = false;
          log << "shutdown early child ownership failed: " << child << "\n";
          ptrace(PTRACE_KILL, child, nullptr, nullptr);
          kill(pid, SIGKILL);
          break;
        }
        newborn_stops.erase(child);
        retry_pending_regions(child);
        if (group_threads.count(child) != 0) {
          // A same-TGID clone was adopted into detach(pid)'s verified group.
          // Keep its already-reported event-stop for the final group detach.
        } else if (!release_descendant(child,
                                       we_started_it ? SIGKILL : 0)) {
          shutdown_ok = false;
          log << "early newborn detach remained ambiguous: " << child << "\n";
          kill(pid, SIGKILL);
          break;
        } else {
          forget_shutdown_tid(child);
        }
      }

      // The parent event-stop is already a complete quiescence boundary.
      // PTRACE_INTERRUPT is not a target-visible signal and has no debt after
      // detach, so do not resume solely to manufacture an event-128 stop.
      interrupt_requested.erase(w);
      continue;
    }

    if (event == 128) {
      interrupt_requested.erase(w);
      const bool job_control_signal =
          stop_signal == SIGSTOP || stop_signal == SIGTSTP ||
          stop_signal == SIGTTIN || stop_signal == SIGTTOU;
      if (stop_signal == SIGTRAP) {
        // Exact completion of our PTRACE_INTERRUPT request.
      } else if (job_control_signal) {
        SignalStopKind kind =
            ProcessTracer::classify_signal_stop(w, stop_signal, event);
        if (kind == SignalStopKind::Unknown) {
          shutdown_ok = false;
          log << "ambiguous event-stop job control tid=" << w << "\n";
          break;
        }
        // A SEIZE group-stop is itself a safe quiescent state. Detaching with
        // signal 0 preserves it, so no SIGCONT or re-delivery is appropriate.
        if (kind == SignalStopKind::GroupStop) {
          preserved_group_stop = true;
        }
      } else {
        shutdown_ok = false;
        log << "unexpected interrupt event signal=" << stop_signal
            << " tid=" << w << "\n";
        break;
      }

      if (group_threads.count(w) == 0) {
        int deliver = we_started_it ? SIGKILL : 0;
        auto pending_signal = shutdown_pending_signal.find(w);
        if (!we_started_it && pending_signal != shutdown_pending_signal.end())
          deliver = pending_signal->second;
        if (!release_descendant(w, deliver)) {
          shutdown_ok = false;
          log << "interrupted descendant detach failed: " << w << "\n";
          kill(pid, SIGKILL);
        }
        forget_shutdown_tid(w);
      }
      continue;
    }

    // Any ptrace stop is sufficient to quiesce a seized tracee. In
    // particular, a syscall stop can win the race after PTRACE_INTERRUPT has
    // returned success; the kernel need not subsequently emit event 128.
    interrupt_requested.erase(w);
    if (event != 0)
      continue;

    if (stop_signal == (SIGTRAP | 0x80))
      continue; // syscall boundary, no signal-delivery debt

    const bool job_control_signal =
        stop_signal == SIGSTOP || stop_signal == SIGTSTP ||
        stop_signal == SIGTTIN || stop_signal == SIGTTOU;
    if (job_control_signal) {
      SignalStopKind kind =
          ProcessTracer::classify_signal_stop(w, stop_signal, event);
      if (kind == SignalStopKind::Unknown) {
        shutdown_ok = false;
        log << "ambiguous shutdown job-control stop tid=" << w << "\n";
        break;
      }
      if (kind == SignalStopKind::GroupStop) {
        preserved_group_stop = true;
        continue;
      }
      if (!remember_shutdown_signal(w, stop_signal)) {
        shutdown_ok = false;
        log << "conflicting shutdown job-control stop tid=" << w << "\n";
        break;
      }
    } else if (!remember_shutdown_signal(w, stop_signal)) {
      shutdown_ok = false;
      log << "conflicting shutdown signal stop tid=" << w << "\n";
      break;
    }
  }

  if (!shutdown_ready()) {
    shutdown_ok = false;
    log << "shutdown interrupt drain incomplete; live=";
    for (int tid : shutdown_live)
      log << tid << ',';
    log << " stopped=";
    for (int tid : stopped_for_shutdown)
      log << tid << ',';
    log << " interrupts=";
    for (int tid : interrupt_requested)
      log << tid << ',';
    log << " unknown=";
    for (int tid : unknown_event_stops)
      log << tid << ',';
    log << "; killing ambiguous tracees\n";
    kill(pid, SIGKILL);
    for (int tid : shutdown_live)
      kill(tid, SIGKILL);
    for (int tid : unknown_event_stops)
      kill(tid, SIGKILL);
  }

  // Unknown early child stops are deliberately never detached while their
  // relationship is ambiguous. In the fail-closed path SIGKILL resolves that
  // ambiguity first; now release every remaining ptrace ownership explicitly.
  for (int tid : std::vector<int>(unknown_event_stops.begin(),
                                  unknown_event_stops.end())) {
    if (!release_descendant(tid, we_started_it ? SIGKILL : 0)) {
      shutdown_ok = false;
      log << "unknown stopped tracee release failed: " << tid << "\n";
    }
    unknown_event_stops.erase(tid);
    stopped_for_shutdown.erase(tid);
    newborn_stops.erase(tid);
  }

  // Release descendants first. In particular a vfork parent can remain
  // kernel-suspended until its separate child leaves ptrace ownership.
  for (int tid : std::vector<int>(shutdown_live.begin(), shutdown_live.end())) {
    if (group_threads.count(tid) != 0)
      continue;
    int deliver = we_started_it ? SIGKILL : 0;
    auto pending_signal = shutdown_pending_signal.find(tid);
    if (!we_started_it && pending_signal != shutdown_pending_signal.end())
      deliver = pending_signal->second;
    if (!release_descendant(tid, deliver)) {
      std::cout << "[!] Failed to detach descendant TID " << tid << "\n";
      log << "descendant detach failed: " << tid << "\n";
      shutdown_ok = false;
      kill(pid, SIGKILL);
    }
    forget_shutdown_tid(tid);
  }

  // Initial TIDs, including a pipe-gated launched target, are owned as one
  // ProcessTracer group. Deliver any temporarily suppressed job-control signal
  // to its exact TID before the remaining group detach.
  bool initial_live = false;
  for (int tid : group_threads)
    initial_live = initial_live || shutdown_live.count(tid) != 0;
  bool initial_detached = true;
  for (int tid : group_threads) {
    auto pending_signal = shutdown_pending_signal.find(tid);
    if (shutdown_live.count(tid) == 0)
      continue;
    if (!we_started_it && pending_signal == shutdown_pending_signal.end())
      continue;
    const int deliver = we_started_it ? SIGKILL : pending_signal->second;
    bool detached = ProcessTracer::detach_thread_with_signal(
        pid, tid, deliver);
    if (!detached) {
      shutdown_ok = false;
      initial_detached = false;
      kill(pid, SIGKILL);
      log << "initial signal-preserving detach failed: " << tid << "\n";
    } else {
      forget_shutdown_tid(tid);
    }
  }
  initial_detached = ProcessTracer::detach(pid) && initial_detached;
  if (initial_live && !initial_detached) {
    std::cout << "[!] Failed to detach one or more initial TIDs\n";
    log << "initial tracee detach failed\n";
    shutdown_ok = false;
  }
  // Do not broadcast SIGCONT: it would clear a genuine pre-existing group-stop.

  if (we_started_it) {
    // Every still-owned TID above was detached with SIGKILL. The target pidfd
    // is an exact-identity backstop; closing the supervisor control pipe then
    // recursively drains descendants which changed process group/session.
    (void)pidfd_signal(launched_pidfd, SIGKILL);
    if (launched_pidfd >= 0)
      close(launched_pidfd);
    launched_pidfd = -1;
    if (!launch_guard.terminate_and_reap()) {
      shutdown_ok = false;
      log << "launch supervisor could not prove descendant teardown\n";
    }
  }

  log << "\nthreads traced=" << threads_seen << "\n";
  log << "mmap/mprotect calls=" << events << "  PROT_EXEC=" << exec_events
      << "  captured=" << dumps
      << "  pending=" << pending_regions.size() << "\n";
  if (timed_out)
    log << "trace stopped at monotonic timeout\n";
  if (interrupted)
    log << "trace interrupted by signal\n";
  if (preserved_group_stop)
    log << "trace ended while preserving target job-control stop\n";
  if (we_started_it && !launched_exec_observed)
    log << "launch contract failed: no leader EXEC event\n";
  if (we_started_it && launched_failed_before_shutdown)
    log << "launch contract failed: leader exit=" << launched_exit_code
        << "\n";
  if (exec_events == 0)
    log << "no executable mmap/mprotect transition was observed\n";
  log.flush();
  output_ok = output_ok && static_cast<bool>(log);
  std::cout << "\n[3] " << events << " mmap/mprotect calls, " << exec_events
            << " with PROT_EXEC, " << dumps << " regions captured\n";
  std::cout << "Output: " << out_display << "/\n";
  const bool launch_ok = !we_started_it ||
                         (launched_exec_observed &&
                          !launched_failed_before_shutdown);
  bool ok = trace_ok && shutdown_ok && output_ok && launch_ok;
  std::cout << (ok ? "=== DONE ===\n" : "=== FAILED ===\n");
  return ok;
}


bool cmd_dump(const std::string &pkg, int timeout_sec,
              const DumpOptions &opt, bool launch,
              const std::string &launch_cmd, int snapshots, int interval_ms) {

  std::cout << "\n=== HAYABUSA DUMPER ===\n";
  std::cout << "Target: " << pkg << "\n";
  if (!opt.priority_files.empty()) {
    std::cout << "Priority list: ";
    for (size_t i = 0; i < opt.priority_files.size(); i++) {
      std::cout << opt.priority_files[i]
                << (i == opt.priority_files.size() - 1 ? "" : ", ");
    }
    std::cout << "\n";
  }
  if (!opt.only.empty()) {
    std::cout << "Only modules matching: ";
    for (size_t i = 0; i < opt.only.size(); i++)
      std::cout << opt.only[i] << (i + 1 == opt.only.size() ? "" : ", ");
    std::cout << "\n";
  }
  std::cout << "Threads: " << opt.threads << "\n";
  std::cout << "Mode: "
            << (opt.analysis.deep ? "deep" : "fast (string heuristics off)");
  if (opt.relink_cfg)
    std::cout << ", relink on (depth " << opt.relink_cfg->max_depth << ")";
  else
    std::cout << ", relink off";
  std::cout << (opt.analysis.trace_init ? ", init-trace on (invasive)" : "")
            << "\n";
  std::cout << "Budgets: Rizin=";
  if (rzb::analysis_level() == rzb::AnalysisLevel::None)
    std::cout << "off";
  else if (opt.analysis.rizin_timeout_seconds == 0)
    std::cout << "unlimited";
  else
    std::cout << opt.analysis.rizin_timeout_seconds << "s/module";
  std::cout << ", memory=";
  if (opt.capture.memory_bytes == 0)
    std::cout << "unlimited";
  else
    std::cout << (opt.capture.memory_bytes / (1024 * 1024)) << "MiB";
  std::cout << ", image=";
  if (opt.capture.image_bytes == 0)
    std::cout << "unlimited";
  else
    std::cout << (opt.capture.image_bytes / (1024 * 1024)) << "MiB";
  std::cout << ", strings=" << (opt.analysis.string_bytes / (1024 * 1024))
            << "MiB";
  if (opt.analysis.deobf) {
    std::cout << ", deobf=";
    if (opt.analysis.deobf_timeout_ms == 0)
      std::cout << "unlimited";
    else
      std::cout << (opt.analysis.deobf_timeout_ms / 1000) << "s";
  }
  std::cout << "\n";
  if (snapshots > 1)
    std::cout << "Snapshots: " << snapshots << " every " << interval_ms
              << "ms\n";
  std::cout << "\n";

  DirectLaunchTarget direct_target;
  if (launch && launch_cmd.empty()) {
    direct_target = open_direct_launch_target(pkg);
    if (!direct_target)
      return false;
  }

  SecureRunDirectory output = open_run_out_dir(pkg, "_analysis");
  if (!output) {
    std::cout << "[!] " << output.error() << "\n";
    return false;
  }
  const std::string out = output.io_path();
  const std::string out_display = output.display_path();

  int launched_pid = -1;
  bool supervised_launch = false;
  PublishedLaunchGuard launch_guard;
  if (launch || !launch_cmd.empty()) {
    LaunchPublishSignalBlock publish_block;
    if (!publish_block.active()) {
      std::cout << "[!] could not block launch signals\n";
      return false;
    }
    std::cout << "[1] Launching target...\n";
    std::cout.flush();
    LaunchSupervisorHandle supervised = LaunchSupervisorHandle::start(
        launch_cmd.empty() ? &direct_target : nullptr,
        launch_cmd.empty() ? nullptr : &launch_cmd,
        publish_block.previous_mask());
    if (!supervised) {
      std::cout << "[!] " << supervised.error() << "\n";
      return false;
    }
    launched_pid = launch_cmd.empty() ? supervised.target() : -1;
    if (!supervised.publish(&launch_guard)) {
      std::cout << "[!] another launched process tree is already active\n";
      return false;
    }
    supervised_launch = true;
    if (!publish_block.restore()) {
      std::cout << "[!] could not restore the launch signal mask\n";
      return false;
    }
    if (!supervised.release_target()) {
      std::cout << "[!] could not release supervised launch target\n";
      return false;
    }
    if (launched_pid > 0)
      std::cout << "    Forked pid " << launched_pid << "\n";
    else
      std::cout << "    Started shell command; scanning for the process\n";
    std::cout.flush();
  } else {
    std::cout << "[1] Waiting for process (launch the app yourself)...\n";
    if (timeout_sec == 0)
      std::cout << "    [i] No timeout set; waiting until first matching "
                   "process is captured.\n";
    std::cout.flush();
  }

  std::map<int, std::map<std::string, uint64_t>> raw_state_by_pid;
  std::map<int, std::map<std::string, uint64_t>> module_state_by_pid;
  std::set<int> seen_pids;
  // Announcing a pid is once-per-process; seen_pids is cleared and refilled
  // while waiting for the loader, so it cannot drive the message.
  std::set<int> announced_pids;
  bool dumped_any = false;
  bool dump_failed = false;
  bool partial_result = false;
  std::set<std::string> matched_only_patterns;
  auto any_alive = [](const std::set<int> &pids) {
    for (int p : pids)
      if (process_alive(p))
        return true;
    return false;
  };
  time_t start_time = time(nullptr);

  // Poll hard right after launching: the interesting state of a packer exists
  // for only a few milliseconds.
  const useconds_t poll_us =
      (launch || !launch_cmd.empty()) ? 2000 : 200000;

  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    if (launched_pid > 0 &&
        std::find(pids.begin(), pids.end(), launched_pid) == pids.end())
      pids.insert(pids.begin(), launched_pid);

    for (int pid : pids) {
      if (seen_pids.count(pid))
        continue;
      if (!process_alive(pid))
        continue;
      seen_pids.insert(pid);

      if (announced_pids.insert(pid).second) {
        std::cout << "\n[2] Captured PID: " << pid << "\n";
        std::cout.flush();
      }
      std::string out_pid = out + "/pid_" + std::to_string(pid);
      const std::string out_pid_display =
          out_display + "/pid_" + std::to_string(pid);
      mkdir_p(out_pid);

      int dumped_here = 0;
      size_t matched_containers_here = 0;
      for (int snap = 0; snap < snapshots; snap++) {
        if (snap > 0) {
          if (!process_alive(pid)) {
            std::cout << "    [!] Target process " << pid
                      << " died after snapshot " << (snap - 1)
                      << ". Partial results kept.\n"
                      << "        Common causes: anti-debug in the target, or "
                      "invasive options (--trace-init).\n";
            break;
          }
          usleep(static_cast<useconds_t>(interval_ms) * 1000);
        }
        std::cout << "\n[3] Dumping (snapshot " << snap << "/"
                  << (snapshots - 1) << ")...\n";
        std::cout.flush();
        size_t matched_containers = 0;
        bool snapshot_partial = false;
        int result = dump_analysis(
            pid, out_pid, out_pid_display, raw_state_by_pid[pid],
            module_state_by_pid[pid], opt, snap, &matched_containers,
            &snapshot_partial, &matched_only_patterns);
        if (result < 0) {
          dump_failed = true;
          break;
        }
        partial_result = partial_result || snapshot_partial;
        dumped_here += result;
        matched_containers_here += matched_containers;
      }

      if (dump_failed)
        break;

      // Nothing mapped yet. With --launch-cmd the poll is 2 ms, so a capture
      // routinely lands between execve and the loader mapping the first
      // library: the process is real, /proc/pid/maps holds the executable and
      // the linker and nothing else. Treating that as the answer ended the run
      // with an empty output directory and a COMPLETE line. Retry the same pid
      // until something shows up or the timeout ends the wait.
      const bool missing_requested_module =
          !opt.only.empty() && matched_containers_here == 0;
      if ((dumped_here == 0 || missing_requested_module) &&
          process_alive(pid) &&
          (timeout_sec == 0 || time(nullptr) - start_time < timeout_sec)) {
        seen_pids.erase(pid);
        usleep(50000);
        continue;
      }
      // Anonymous/heap captures are useful artifacts, but they cannot satisfy
      // an explicit --only request. In launch mode the first stop can occur
      // between execve and the loader mapping the requested library; treating
      // unrelated anonymous pages as success made that race print COMPLETE
      // with zero matching modules.
      dumped_any = dumped_any ||
                   (dumped_here > 0 && !missing_requested_module);
    }

    if (dumped_any || dump_failed)
      break;
    if (!seen_pids.empty() && !any_alive(seen_pids))
      break;
    if (timeout_sec > 0 && time(nullptr) - start_time >= timeout_sec) {
      std::cout << "[!] Timed out after " << timeout_sec
                << "s waiting for '" << pkg << "'\n";
      break;
    }
    usleep(poll_us);
  }

  if (supervised_launch && !launch_guard.terminate_and_reap()) {
    dump_failed = true;
    std::cout << "[!] launch supervisor could not prove descendant teardown\n";
  }

  if (dumped_any && !opt.only.empty()) {
    for (const auto &pattern : opt.only) {
      if (matched_only_patterns.count(pattern) != 0)
        continue;
      partial_result = true;
      std::cout << "[!] Requested module was not mapped/captured: " << pattern
                << "\n";
    }
  }
  if (dumped_any && partial_result && opt.require_complete) {
    dump_failed = true;
    std::cout << "[!] --require-complete rejected partial output\n";
  }

  if (dumped_any && !dump_failed) {
    std::cout << (partial_result
                      ? "\n=== COMPLETE WITH WARNINGS: PARTIAL RESULT ===\n"
                      : "\n=== COMPLETE ===\n");
    std::cout << "Output: " << out_display << "/\n";
  } else {
    std::cout << (dump_failed
                      ? "\n=== FAILED: incomplete process snapshot ===\n"
                      : "\n=== FAILED: no modules dumped ===\n");
  }
  return dumped_any && !dump_failed;
}

int main(int argc, char *argv[]) {
  // All analysis artifacts can contain raw application memory and recovered
  // keys. Make every subsequently created file private even if a helper uses
  // ordinary ofstream/mkdir defaults inside the descriptor-pinned tree.
  umask(0077);
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGSEGV, signal_handler);
  signal(SIGBUS, signal_handler);
  signal(SIGABRT, signal_handler);
  atexit(cleanup);

  if (const char *configured_root = getenv("HAYABUSA_OUTPUT_ROOT")) {
    if (*configured_root == 0) {
      std::cerr << "[!] HAYABUSA_OUTPUT_ROOT must not be empty\n";
      return 1;
    }
    g_output_root = configured_root;
  }

  if (argc < 3) {
    std::cout << USAGE;
    return 1;
  }

  std::string cmd = argv[1];
  std::string pkg = argv[2];
  int timeout_sec = 0;
  std::string extra_arg;

  if (cmd == "hook" || cmd == "stub" || cmd == "inject" ||
      cmd == "scan" || cmd == "extract") {
    int inst_count = 10;
    int max_depth = 8;
    size_t extract_size_limit = 512U * 1024U * 1024U;
    if (argc < 4) {
      std::cout << USAGE;
      return 1;
    }
    extra_arg = argv[3];
    for (int i = 4; i < argc; i++) {
      std::string arg = argv[i];
      if (arg == "--i" && i + 1 < argc && cmd == "hook") {
        inst_count = atoi(argv[++i]);
        if (inst_count < 1)
          inst_count = 1;
        if (inst_count > 200)
          inst_count = 200;
      } else if (arg == "--d" && i + 1 < argc && cmd == "extract") {
        max_depth = atoi(argv[++i]);
        if (max_depth < 1)
          max_depth = 1;
        if (max_depth > 32)
          max_depth = 32;
      } else if (arg == "--size-limit" && i + 1 < argc &&
                 cmd == "extract") {
        uint64_t bytes = 0;
        if (!parse_mib_argument(argv[++i], &bytes) || bytes == 0 ||
            bytes > std::numeric_limits<size_t>::max()) {
          std::cout << "--size-limit expects a positive addressable MiB count\n";
          return 1;
        }
        extract_size_limit = static_cast<size_t>(bytes);
      } else {
        std::cout << USAGE;
        return 1;
      }
    }
    if (cmd == "hook")
      return cmd_hook(pkg, extra_arg, inst_count) ? 0 : 2;
    else if (cmd == "stub")
      return cmd_stub(pkg, extra_arg) ? 0 : 2;
    else if (cmd == "inject")
      return cmd_inject(pkg, extra_arg) ? 0 : 2;
    else if (cmd == "scan")
      return cmd_scan(pkg, extra_arg) ? 0 : 2;
    else if (cmd == "extract")
      return cmd_extract(pkg, extra_arg, max_depth, extract_size_limit) ? 0 : 2;
  } else if (cmd == "unpack") {
    bool launch = false;
    bool launch_cmd_set = false;
    std::string launch_cmd;
    size_t limit = 64;
    uint64_t region_limit = 1024ull * 1024 * 1024;
    for (int i = 3; i < argc; i++) {
      std::string arg = argv[i];
      if (arg == "--launch") {
        launch = true;
      } else if (arg == "--launch-cmd" && i + 1 < argc) {
        launch_cmd_set = true;
        launch_cmd = argv[++i];
      } else if (arg == "--timeout" && i + 1 < argc) {
        timeout_sec = atoi(argv[++i]);
      } else if (arg == "--limit" && i + 1 < argc) {
        long v = strtol(argv[++i], nullptr, 10);
        limit = (size_t)std::clamp(v, 1L, 100000L);
      } else if (arg == "--memory-limit" && i + 1 < argc) {
        if (!parse_mib_argument(argv[++i], &region_limit)) {
          std::cout << "--memory-limit expects MiB (0 disables the policy limit)\n";
          return 1;
        }
      } else { std::cout << USAGE; return 1; }
    }
    if (launch && launch_cmd_set) {
      std::cout << "--launch and --launch-cmd are mutually exclusive\n";
      return 1;
    }
    if (launch_cmd_set && launch_cmd.empty()) {
      std::cout << "--launch-cmd requires a non-empty shell command\n";
      return 1;
    }
    return cmd_unpack(pkg, timeout_sec, launch, launch_cmd, limit,
                      region_limit)
               ? 0
               : 2;
  } else if (cmd == "dump") {
    DumpOptions opt;
    bool launch = false;
    bool launch_cmd_set = false;
    std::string launch_cmd;
    int snapshots = 1;
    int interval_ms = 500;
    RelinkConfig relink_cfg = make_default_relink_config();
    bool want_relink = false;
    size_t thread_count = default_worker_threads();
    for (int i = 3; i < argc; i++) {
      std::string arg = argv[i];
      if (arg == "--timeout" && i + 1 < argc) {
        timeout_sec = atoi(argv[++i]);
        if (timeout_sec < 0)
          timeout_sec = 0;
      } else if (arg == "--p" && i + 1 < argc) {
        opt.priority_files = split_string(argv[++i], ',');
      } else if (arg == "--only" && i + 1 < argc) {
        opt.only = split_string(argv[++i], ',');
      } else if (arg == "--fast") {
        opt.analysis.deep = false;
      } else if (arg == "--trace-init") {
        opt.analysis.trace_init = true;
      } else if (arg == "--listing" && i + 1 < argc) {
        long v = strtol(argv[++i], nullptr, 10);
        opt.analysis.listing = (size_t)std::clamp(v, 0L, 100000L);
      } else if (arg == "--deobf") {
        opt.analysis.deobf = true;
      } else if (arg == "--min-str" && i + 1 < argc) {
        long v = strtol(argv[++i], nullptr, 10);
        opt.analysis.min_str = (size_t)std::clamp(v, 3L, 256L);
      } else if (arg == "--limit" && i + 1 < argc) {
        long v = strtol(argv[++i], nullptr, 10);
        opt.analysis.limit = (size_t)std::clamp(v, 1L, 1000000L);
      } else if (arg == "--relink") {
        want_relink = true;
      } else if (arg == "--rd" && i + 1 < argc) {
        relink_cfg.max_depth = atoi(argv[++i]);
        if (relink_cfg.max_depth < 1)
          relink_cfg.max_depth = 1;
        if (relink_cfg.max_depth > 32)
          relink_cfg.max_depth = 32;
      } else if (arg == "--relink-limit" && i + 1 < argc) {
        uint64_t bytes = 0;
        if (!parse_mib_argument(argv[++i], &bytes) || bytes == 0 ||
            bytes > std::numeric_limits<size_t>::max()) {
          std::cout << "--relink-limit expects a positive addressable MiB count\n";
          return 1;
        }
        relink_cfg.max_total_size = static_cast<size_t>(bytes);
      } else if (arg == "--launch") {
        launch = true;
      } else if (arg == "--launch-cmd" && i + 1 < argc) {
        launch_cmd_set = true;
        launch_cmd = argv[++i];
      } else if (arg == "--snapshots" && i + 1 < argc) {
        snapshots = atoi(argv[++i]);
        if (snapshots < 1)
          snapshots = 1;
        if (snapshots > 64)
          snapshots = 64;
      } else if (arg == "--interval" && i + 1 < argc) {
        interval_ms = atoi(argv[++i]);
        if (interval_ms < 10)
          interval_ms = 10;
        if (interval_ms > 60000)
          interval_ms = 60000;
      } else if (arg == "--rz-analysis" && i + 1 < argc) {
        std::string lvl = argv[++i];
        if (lvl == "off")
          rzb::set_analysis_level(rzb::AnalysisLevel::None);
        else if (lvl == "basic")
          rzb::set_analysis_level(rzb::AnalysisLevel::Basic);
        else if (lvl == "full")
          rzb::set_analysis_level(rzb::AnalysisLevel::Full);
        else {
          std::cout << "--rz-analysis expects off, basic or full\n";
          return 1;
        }
      } else if (arg == "--analysis-timeout" && i + 1 < argc) {
        uint64_t seconds = 0;
        if (!parse_uint64_argument(argv[++i], &seconds) ||
            seconds > std::numeric_limits<uint32_t>::max()) {
          std::cout << "--analysis-timeout expects 0..4294967295 seconds\n";
          return 1;
        }
        opt.analysis.rizin_timeout_seconds = static_cast<uint32_t>(seconds);
      } else if (arg == "--deobf-timeout" && i + 1 < argc) {
        uint64_t seconds = 0;
        if (!parse_uint64_argument(argv[++i], &seconds) ||
            seconds > std::numeric_limits<uint64_t>::max() / 1000) {
          std::cout << "--deobf-timeout expects a non-negative second count\n";
          return 1;
        }
        opt.analysis.deobf_timeout_ms = seconds * 1000;
      } else if (arg == "--memory-limit" && i + 1 < argc) {
        if (!parse_mib_argument(argv[++i], &opt.capture.memory_bytes)) {
          std::cout << "--memory-limit expects MiB (0 disables the policy limit)\n";
          return 1;
        }
      } else if (arg == "--image-limit" && i + 1 < argc) {
        if (!parse_mib_argument(argv[++i], &opt.capture.image_bytes)) {
          std::cout << "--image-limit expects MiB (0 disables the policy limit)\n";
          return 1;
        }
      } else if (arg == "--string-limit" && i + 1 < argc) {
        uint64_t bytes = 0;
        if (!parse_mib_argument(argv[++i], &bytes) || bytes == 0 ||
            bytes > std::numeric_limits<size_t>::max()) {
          std::cout << "--string-limit expects a positive addressable MiB count\n";
          return 1;
        }
        opt.analysis.string_bytes = static_cast<size_t>(bytes);
        opt.analysis.deobf_input_bytes = static_cast<size_t>(bytes);
      } else if (arg == "--deobf-probes" && i + 1 < argc) {
        uint64_t probes = 0;
        if (!parse_uint64_argument(argv[++i], &probes) || probes == 0 ||
            probes > std::numeric_limits<size_t>::max()) {
          std::cout << "--deobf-probes expects a positive count\n";
          return 1;
        }
        opt.analysis.deobf_probes = static_cast<size_t>(probes);
        opt.analysis.deobf_candidates = static_cast<size_t>(probes);
      } else if (arg == "--require-complete") {
        opt.require_complete = true;
      } else if (arg == "--threads" && i + 1 < argc) {
        // An explicit count is honoured as given. The only ceiling is a sanity
        // bound against a typo like `--threads 100000` exhausting thread stacks
        // before any work starts.
        long v = strtol(argv[++i], nullptr, 10);
        if (v < 1)
          v = 1;
        if (v > 4096)
          v = 4096;
        thread_count = static_cast<size_t>(v);
      } else {
        std::cout << USAGE;
        return 1;
      }
    }
    if (launch && launch_cmd_set) {
      std::cout << "--launch and --launch-cmd are mutually exclusive\n";
      return 1;
    }
    if (launch_cmd_set && launch_cmd.empty()) {
      std::cout << "--launch-cmd requires a non-empty shell command\n";
      return 1;
    }
    opt.threads = thread_count;
    rzb::AnalysisLimits rizin_limits;
    rizin_limits.module_timeout_seconds =
        opt.analysis.rizin_timeout_seconds;
    rizin_limits.table_timeout_seconds =
        opt.analysis.rizin_timeout_seconds;
    rizin_limits.pointer_scan_bytes = opt.capture.image_bytes;
    rizin_limits.pointer_slots = opt.analysis.limit;
    rizin_limits.pointer_tables = opt.analysis.limit;
    rizin_limits.analysis_targets = opt.analysis.limit;
    rzb::set_analysis_limits(rizin_limits);
    // Static relinking does per-module remote ptrace work and only adds a hex
    // preview to the report, so it is opt-in rather than always-on.
    opt.relink_cfg = want_relink ? &relink_cfg : nullptr;
    return cmd_dump(pkg, timeout_sec, opt, launch, launch_cmd, snapshots,
                    interval_ms)
               ? 0
               : 2;
  } else {
    std::cout << USAGE;
    return 1;
  }

  return 0;
}
