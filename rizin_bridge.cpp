#include "rizin_bridge.h"
#include "sleigh_data.h"

#include <rz_analysis.h>
#include <rz_asm.h>
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_io.h>
#include <rz_util.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <limits>
#include <set>
#include <system_error>
#include <vector>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <atomic>
#include <mutex>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif

extern "C" {
// With CORELIB defined, rz-ghidra exports its plugin as an ordinary symbol
// instead of wrapping them in the RzLibStruct the dynamic loader looks for.
extern RzCorePlugin rz_core_plugin_ghidra;
extern RzAnnotatedCode *rz_ghidra_decompile_annotated_code(RzCore *core,
                                                           ut64 addr);
}

namespace rzb {
namespace {

bool write_all_fd(int fd, const void *data, size_t size) {
  if (size != 0 && !data)
    return false;
  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  size_t done = 0;
  while (done < size) {
    const ssize_t amount = write(fd, bytes + done, size - done);
    if (amount < 0 && errno == EINTR)
      continue;
    if (amount <= 0)
      return false;
    done += static_cast<size_t>(amount);
  }
  return true;
}

bool fsync_retry(int fd) {
  int result;
  do {
    result = fsync(fd);
  } while (result < 0 && errno == EINTR);
  return result == 0;
}

// rz_core_new() and the open transaction touch process-wide registries. The
// caller also serialises the complete report transaction because Rizin's
// console and break state are singletons even when RzCore objects differ.
std::mutex core_new_mu;

std::atomic<AnalysisLevel> g_level{AnalysisLevel::Full};

std::once_flag g_sleigh_once;
std::string g_sleigh_home;
std::mutex g_scratch_mu;
std::string g_scratch_directory = ".";

std::string scratch_directory() {
  std::lock_guard<std::mutex> lock(g_scratch_mu);
  return g_scratch_directory;
}

void unpack_sleigh() {
  const sleigh_data::File *files = sleigh_data::files();
  const size_t file_count = sleigh_data::file_count();

  // Include names, lengths and every byte. A count/total-size stamp aliases two
  // different Ghidra data sets whose files happen to keep their sizes.
  uint64_t content_hash = 1469598103934665603ULL;
  auto hash_bytes = [&](const void *ptr, size_t size) {
    const auto *p = static_cast<const uint8_t *>(ptr);
    for (size_t i = 0; i < size; i++) {
      content_hash ^= p[i];
      content_hash *= 1099511628211ULL;
    }
  };
  for (size_t i = 0; i < file_count; i++) {
    hash_bytes(files[i].name, strlen(files[i].name) + 1);
    hash_bytes(&files[i].size, sizeof(files[i].size));
    hash_bytes(files[i].bytes, files[i].size);
  }

  // Different Hayabusa versions never delete or truncate the files an older
  // process is actively using. Processes carrying the same set coordinate
  // through flock and publish each file with atomic rename.
  const std::string scratch = scratch_directory();
  struct stat scratch_st {};
  if (stat(scratch.c_str(), &scratch_st) != 0 ||
      !S_ISDIR(scratch_st.st_mode)) {
    fprintf(stderr, "[sleigh] invalid scratch directory %s\n",
            scratch.c_str());
    return;
  }
  char cache_leaf[96];
  snprintf(cache_leaf, sizeof(cache_leaf),
           ".hayabusa-sleigh-%lu-%016llx",
           static_cast<unsigned long>(geteuid()),
           static_cast<unsigned long long>(content_hash));
  const std::string dir = scratch + "/" + cache_leaf;
  if (mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
    fprintf(stderr, "[sleigh] mkdir %s: %s\n", dir.c_str(), strerror(errno));
    return;
  }
  struct stat dir_st {};
  if (lstat(dir.c_str(), &dir_st) != 0 || !S_ISDIR(dir_st.st_mode) ||
      dir_st.st_uid != geteuid() || (dir_st.st_mode & 077) != 0) {
    fprintf(stderr, "[sleigh] unsafe scratch directory %s\n", dir.c_str());
    return;
  }

  const std::string lock_path = dir + "/.lock";
  int lock_fd =
      open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (lock_fd < 0 || flock(lock_fd, LOCK_EX) != 0) {
    fprintf(stderr, "[sleigh] lock %s: %s\n", lock_path.c_str(),
            strerror(errno));
    if (lock_fd >= 0)
      close(lock_fd);
    return;
  }
  auto unlock = [&]() {
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
  };

  const std::string complete_path = dir + "/.complete";
  char want_buf[32];
  snprintf(want_buf, sizeof(want_buf), "%016llx",
           static_cast<unsigned long long>(content_hash));
  const std::string want = want_buf;
  {
    char have[32] = {};
    int fd = open(complete_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t rd = -1;
    if (fd >= 0) {
      do {
        rd = read(fd, have, sizeof(have));
      } while (rd < 0 && errno == EINTR);
    }
    if (fd >= 0)
      close(fd);
    if (rd == static_cast<ssize_t>(want.size()) &&
        std::string(have, static_cast<size_t>(rd)) == want) {
      unlock();
      g_sleigh_home = dir;
      return;
    }
  }

  // Remove only abandoned temporary publications inside this exact
  // content-addressed directory. Final files remain usable until their atomic
  // replacements land.
  if (DIR *d = opendir(dir.c_str())) {
    while (struct dirent *e = readdir(d)) {
      if (strstr(e->d_name, ".tmp.") != nullptr)
        unlink((dir + "/" + e->d_name).c_str());
    }
    closedir(d);
  }

  for (size_t i = 0; i < file_count; i++) {
    const std::string path = dir + "/" + files[i].name;
    const std::string temp =
        path + ".tmp." + std::to_string(static_cast<long long>(getpid()));
    int fd = open(temp.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
      fprintf(stderr, "[sleigh] open %s: %s\n", temp.c_str(),
              strerror(errno));
      unlock();
      return;
    }
    if (!write_all_fd(fd, files[i].bytes, files[i].size)) {
      const int write_errno = errno;
      fprintf(stderr, "[sleigh] write %s: %s\n", temp.c_str(),
              strerror(write_errno));
      close(fd);
      unlink(temp.c_str());
      unlock();
      return;
    }
    bool publish_ok = fsync_retry(fd);
    if (close(fd) != 0)
      publish_ok = false;
    if (publish_ok && rename(temp.c_str(), path.c_str()) != 0)
      publish_ok = false;
    if (!publish_ok) {
      fprintf(stderr, "[sleigh] publish %s: %s\n", path.c_str(),
              strerror(errno));
      unlink(temp.c_str());
      unlock();
      return;
    }
  }

  const std::string complete_temp =
      complete_path + ".tmp." +
      std::to_string(static_cast<long long>(getpid()));
  int sfd = open(complete_temp.c_str(),
                 O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  bool complete_ok = sfd >= 0;
  if (complete_ok && !write_all_fd(sfd, want.data(), want.size()))
    complete_ok = false;
  if (complete_ok && !fsync_retry(sfd))
    complete_ok = false;
  if (sfd >= 0 && close(sfd) != 0)
    complete_ok = false;
  if (complete_ok &&
      rename(complete_temp.c_str(), complete_path.c_str()) != 0)
    complete_ok = false;
  if (!complete_ok) {
    fprintf(stderr, "[sleigh] publish completion stamp: %s\n",
            strerror(errno));
    unlink(complete_temp.c_str());
    unlock();
    return;
  }

  unlock();
  g_sleigh_home = dir;
}

// rizin's plugin tables are per-RzCore, so registration happens per instance,
// but the Ghidra decompiler keeps process-wide state behind its own lock. Only
// the first RzCore pays the sleigh unpack.
void register_plugins(RzCore *core) {
  // Only the decompiler is taken from rz-ghidra. Its sleigh-based asm and
  // analysis plugins are left out: rizin's own AArch64 disassembler is already
  // complete, and the two sleigh plugins each compile their own copy of
  // SleighAsm.cpp, which collides at link time once the archives are pulled in
  // whole rather than loaded as separate shared objects.
  rz_core_plugin_add(core, &rz_core_plugin_ghidra);
}

// rz_list_foreach assigns `void *` straight into a typed pointer, which C
// permits and C++ does not. This walks the same links with an explicit cast.
template <typename T, typename F> void list_for_each(RzList *l, F fn) {
  if (!l)
    return;
  for (RzListIter *it = l->head; it; it = it->next) {
    if (T *v = static_cast<T *>(it->val))
      fn(v);
  }
}

InsnType map_type(uint32_t rz_type) {
  switch (rz_type & RZ_ANALYSIS_OP_TYPE_MASK) {
  case RZ_ANALYSIS_OP_TYPE_CALL:
  case RZ_ANALYSIS_OP_TYPE_UCALL:
  case RZ_ANALYSIS_OP_TYPE_RCALL:
  case RZ_ANALYSIS_OP_TYPE_ICALL:
  case RZ_ANALYSIS_OP_TYPE_IRCALL:
    return InsnType::Call;
  case RZ_ANALYSIS_OP_TYPE_RET:
    return InsnType::Return;
  case RZ_ANALYSIS_OP_TYPE_JMP:
  case RZ_ANALYSIS_OP_TYPE_UJMP:
  case RZ_ANALYSIS_OP_TYPE_RJMP:
  case RZ_ANALYSIS_OP_TYPE_IJMP:
  case RZ_ANALYSIS_OP_TYPE_MJMP:
    return InsnType::Branch;
  case RZ_ANALYSIS_OP_TYPE_CJMP:
  case RZ_ANALYSIS_OP_TYPE_UCJMP:
    return InsnType::ConditionalBranch;
  case RZ_ANALYSIS_OP_TYPE_LOAD:
    return InsnType::Load;
  case RZ_ANALYSIS_OP_TYPE_STORE:
    return InsnType::Store;
  case RZ_ANALYSIS_OP_TYPE_LEA:
    return InsnType::Adrp;
  case RZ_ANALYSIS_OP_TYPE_ADD:
    return InsnType::Add;
  default:
    return InsnType::Other;
  }
}

bool is_indirect_type(uint32_t rz_type) {
  switch (rz_type & RZ_ANALYSIS_OP_TYPE_MASK) {
  case RZ_ANALYSIS_OP_TYPE_UCALL:
  case RZ_ANALYSIS_OP_TYPE_RCALL:
  case RZ_ANALYSIS_OP_TYPE_ICALL:
  case RZ_ANALYSIS_OP_TYPE_IRCALL:
  case RZ_ANALYSIS_OP_TYPE_UJMP:
  case RZ_ANALYSIS_OP_TYPE_RJMP:
  case RZ_ANALYSIS_OP_TYPE_IJMP:
  case RZ_ANALYSIS_OP_TYPE_MJMP:
    return true;
  default:
    return false;
  }
}

void fill_insn(const RzAnalysisOp *op, const uint8_t *bytes, Insn *out) {
  out->addr = op->addr;
  out->raw = 0;
  if (bytes)
    memcpy(&out->raw, bytes, sizeof(out->raw));
  out->text = op->mnemonic ? op->mnemonic : "";
  out->type = map_type(static_cast<uint32_t>(op->type));
  out->target = op->jump != UT64_MAX ? op->jump : 0;
  out->is_call = out->type == InsnType::Call;
  out->is_return = out->type == InsnType::Return;
  out->is_indirect = is_indirect_type(static_cast<uint32_t>(op->type));
}

// Pull the displacement out of an `[x0, #N]` operand. rizin's generic
// RzAnalysisOp does not expose base-register + displacement in a form that is
// stable across architectures, and `this`-relative field recovery only cares
// about the one register, so the mnemonic is parsed directly.
bool parse_x0_disp(const char *mnemonic, uint64_t *disp) {
  if (!mnemonic)
    return false;
  const char *p = strstr(mnemonic, "[x0");
  if (!p)
    return false;
  p += 3;
  if (*p == ']') { // [x0] -- offset zero
    *disp = 0;
    return true;
  }
  if (strncmp(p, ", #", 3) != 0)
    return false;
  p += 3;
  char *end = nullptr;
  unsigned long long v = strtoull(p, &end, 0);
  if (end == p)
    return false;
  *disp = v;
  return true;
}

uint32_t access_width(const char *mnemonic) {
  if (!mnemonic)
    return 8;
  if (!strncmp(mnemonic, "ldrb", 4) || !strncmp(mnemonic, "strb", 4))
    return 1;
  if (!strncmp(mnemonic, "ldrh", 4) || !strncmp(mnemonic, "strh", 4))
    return 2;
  // `ldr w0, [...]` is a 32-bit access, `ldr x0, [...]` a 64-bit one.
  const char *sp = strchr(mnemonic, ' ');
  if (sp && sp[1] == 'w')
    return 4;
  return 8;
}

} // namespace

void set_analysis_level(AnalysisLevel level) {
  g_level.store(level, std::memory_order_relaxed);
}

AnalysisLevel analysis_level() {
  return g_level.load(std::memory_order_relaxed);
}

namespace {
std::atomic<uint32_t> g_module_timeout_seconds{60};
std::atomic<uint32_t> g_table_timeout_seconds{60};
std::atomic<uint64_t> g_pointer_scan_bytes{2048ull * 1024 * 1024};
std::atomic<size_t> g_pointer_slots{100000};
std::atomic<size_t> g_pointer_tables{100000};
std::atomic<size_t> g_analysis_targets{100000};
} // namespace

void set_analysis_limits(const AnalysisLimits &limits) {
  g_module_timeout_seconds.store(limits.module_timeout_seconds,
                                 std::memory_order_relaxed);
  g_table_timeout_seconds.store(limits.table_timeout_seconds,
                                std::memory_order_relaxed);
  g_pointer_scan_bytes.store(limits.pointer_scan_bytes,
                             std::memory_order_relaxed);
  g_pointer_slots.store(limits.pointer_slots, std::memory_order_relaxed);
  g_pointer_tables.store(limits.pointer_tables, std::memory_order_relaxed);
  g_analysis_targets.store(limits.analysis_targets,
                           std::memory_order_relaxed);
}

void set_scratch_directory(const std::string &directory) {
  if (directory.empty())
    return;
  std::lock_guard<std::mutex> lock(g_scratch_mu);
  if (!g_sleigh_home.empty())
    return;
  g_scratch_directory = directory;
  while (g_scratch_directory.size() > 1 &&
         g_scratch_directory.back() == '/')
    g_scratch_directory.pop_back();
}

const std::string &sleigh_home() {
  std::call_once(g_sleigh_once, unpack_sleigh);
  return g_sleigh_home;
}

struct Image::Impl {
  using Clock = std::chrono::steady_clock;
  std::once_flag rtti_once;
  RzCore *core = nullptr;
  uint64_t base = 0;
  AnalysisLevel level = AnalysisLevel::Full;
  AnalysisLimits limits;
  bool analyzed = false;
  bool analysis_failed = false;
  bool deadline_started = false;
  bool deadline_reported = false;
  Clock::time_point work_deadline = Clock::time_point::max();
  std::map<size_t, std::vector<Image::PointerRun>> function_table_cache;
  std::map<size_t, bool> function_table_truncated_cache;
  std::string decompiler_error;
  int tmp_fd = -1; // anonymous backing memfd held for Rizin's pathname view
  std::string tmp_path;

  void start_deadline() {
    if (deadline_started)
      return;
    deadline_started = true;
    if (limits.module_timeout_seconds != 0)
      work_deadline = Clock::now() +
                      std::chrono::seconds(limits.module_timeout_seconds);
  }

  uint32_t remaining_seconds() const {
    if (work_deadline == Clock::time_point::max())
      return 0;
    const auto now = Clock::now();
    if (now >= work_deadline)
      return 0;
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        work_deadline - now);
    const uint64_t rounded =
        (static_cast<uint64_t>(remaining.count()) + 999U) / 1000U;
    return static_cast<uint32_t>(std::min<uint64_t>(
        std::max<uint64_t>(rounded, 1U), UINT32_MAX));
  }

  ~Impl() {
    if (core)
      rz_core_free(core);
    if (tmp_fd >= 0)
      close(tmp_fd);
  }
};

Image::Image() : p(new Impl) {}
Image::~Image() = default;

std::unique_ptr<Image> Image::open(const std::vector<uint8_t> &data,
                                   uint64_t base) {
  if (data.size() < 64)
    return nullptr;

  std::unique_ptr<Image> img;
  img.reset(new Image);
  img->p->base = base;
  // The public contract says the setting applies to images opened afterwards.
  // Snapshot it here so a later global change cannot turn a parse-only image
  // into one that unexpectedly performs RTTI or function recovery.
  img->p->level = g_level.load(std::memory_order_relaxed);
  img->p->limits.module_timeout_seconds =
      g_module_timeout_seconds.load(std::memory_order_relaxed);
  img->p->limits.table_timeout_seconds =
      g_table_timeout_seconds.load(std::memory_order_relaxed);
  img->p->limits.pointer_scan_bytes =
      g_pointer_scan_bytes.load(std::memory_order_relaxed);
  img->p->limits.pointer_slots =
      g_pointer_slots.load(std::memory_order_relaxed);
  img->p->limits.pointer_tables =
      g_pointer_tables.load(std::memory_order_relaxed);
  img->p->limits.analysis_targets =
      g_analysis_targets.load(std::memory_order_relaxed);

  // Rizin's construction, plugin registration and file-open path all touch
  // process-wide registries/current-plugin state. Serialising only
  // rz_core_new() still let concurrent rz_core_file_open_load() calls cross
  // their filenames and report that a freshly-created temp image did not
  // exist. Keep the complete open transaction atomic; analysis after a
  // successful open remains per-core.
  std::lock_guard<std::mutex> open_lock(core_new_mu);
  img->p->core = rz_core_new();
  if (!img->p->core)
    return nullptr;

  register_plugins(img->p->core);

  // Point the Ghidra decompiler at the Sleigh data before its first request.
  // The core plugin resolves the target language lazily and cannot decompile
  // without the embedded language definition.
  const std::string &home = sleigh_home();
  if (!home.empty())
    rz_config_set(img->p->core->config, "ghidra.sleighhome", home.c_str());

  // Analysis output goes to hayabusa's own report writers, so rizin's console
  // must not print anything of its own.
  // Data cross-references are OFF by default in rizin. Without these three the
  // xref database only ever holds code references, which is why an earlier
  // attempt at binding string xrefs to rizin came back nearly empty.
  rz_config_set_b(img->p->core->config, "analysis.strings", true);
  rz_config_set_b(img->p->core->config, "analysis.datarefs", true);
  rz_config_set_b(img->p->core->config, "analysis.refstr", true);
  // The embedded API does not apply analysis.timeout when callers invoke the
  // analysis routines directly. Keep the config in sync with the explicit
  // non-signal break scope in Image::analyze() below so a hostile module
  // cannot turn one report into an unbounded whole-core analysis pass.
  rz_config_set_i(img->p->core->config, "analysis.timeout",
                  img->p->limits.module_timeout_seconds);

  rz_config_set_i(img->p->core->config, "scr.color", 0);
  rz_config_set_b(img->p->core->config, "scr.interactive", false);
  rz_config_set_b(img->p->core->config, "cfg.debug", false);

  // rz_core_notify_begin/done drive the "[ ] Analyze function calls" progress
  // lines straight to stderr, gated only on scr.prompt. With one worker per
  // core they interleave into unreadable soup, and hayabusa prints its own
  // progress anyway.
  rz_config_set_b(img->p->core->config, "scr.prompt", false);
  // Malformed/memory-lifted images routinely have no file entrypoint or a
  // partial section table. Rizin prints those expected parser diagnostics to
  // the user's terminal even when the load succeeds. Hayabusa reports every
  // actionable open/analysis/decompiler failure explicitly below, so suppress
  // the library's unstructured global log stream.
  rz_log_set_level(RZ_LOGLVL_NONE);

  // The image goes through a temp file rather than rz_io_open_buffer.
  // Opening a bare RzIODesc bypasses RzCore's file bookkeeping, and
  // rz_core_bin_load then has no RzCoreFile to attach the parsed binary to, so
  // it fails. rz_core_file_open_load does the whole sequence properly.
  auto write_temp = [](const std::vector<uint8_t> &bytes, int *out_fd,
                       std::string *out_path) -> bool {
    if (!out_fd || !out_path)
      return false;
    int fd = static_cast<int>(
        syscall(SYS_memfd_create, "hayabusa-rizin", MFD_CLOEXEC));
    if (fd < 0)
      return false;
    if (!write_all_fd(fd, bytes.data(), bytes.size())) {
      const int write_errno = errno;
      close(fd);
      errno = write_errno;
      return false;
    }
    *out_fd = fd;
    // ELF loads correctly through rizin's fd:// plugin, which consumes the
    // already-open descriptor directly. The DEX bin parser does not: it seeks
    // and reads at scattered absolute offsets (string/type/proto/field/method
    // id tables and every class_data item), and over the fd:// (or malloc://)
    // io buffer those random-access reads fail, so rz_bin_dex_new returns NULL,
    // no RzBinObject is built, and every class/method/decompilation is empty.
    // The identical bytes parse when the same memfd is opened through its
    // /proc/self/fd/N path, which rizin backs with a seekable file buffer; that
    // path stays valid for lazy reopens because *out_fd is kept open with the
    // Image. Route Dalvik there and leave the proven ELF path on fd://.
    const bool is_dalvik =
        bytes.size() >= 4 && memcmp(bytes.data(), "dex\n", 4) == 0;
    *out_path = is_dalvik ? "/proc/self/fd/" + std::to_string(fd)
                          : "fd://" + std::to_string(fd);
    return true;
  };

  if (!write_temp(data, &img->p->tmp_fd, &img->p->tmp_path)) {
    fprintf(stderr, "[rizin] 0x%llx: could not create the memfd image: %s\n",
            (unsigned long long)base, strerror(errno));
    return nullptr;
  }

  // Loaded once, at zero, and left there.
  //
  // rizin works in module-relative addresses throughout and the report adds the
  // load address on the way out; that is the one convention every consumer in
  // this file follows. This used to open at zero and then call rz_core_bin_load
  // a second time with the real base, which left both bin objects and both io
  // maps in place: `aaa` walked the image twice and every function, flag and
  // string came back in two copies -- one relative, one absolute -- and the
  // absolute copy then had the base added to it again on the way into the
  // report. Passing the base to rz_core_file_open_load instead does not rebase
  // a PIE at all, so the io map stayed at zero while the checks that compared
  // against relocated pointers expected otherwise.
  //
  // No retry with a stripped section table. That used to sit here, and it made
  // the failure invisible: rizin would load the weakened image, produce a
  // report with silently missing sections, and nothing said so. A load that
  // fails now fails.
  bool opened =
      rz_core_file_open_load(img->p->core, img->p->tmp_path.c_str(), 0,
                             RZ_PERM_R, false);
  if (!opened) {
    fprintf(stderr,
            "[rizin] 0x%llx: rz_core_file_open_load failed (%zu bytes); every "
            "rizin-backed analysis of this module will be empty\n",
            (unsigned long long)base, data.size());
    return nullptr;
  }
  // Keep the anonymous descriptor alive with the Image. Some Rizin consumers
  // reopen the recorded path lazily; /proc/self/fd/N remains valid without
  // leaving a filesystem artifact behind.
  return img;
}

void Image::analyze() {
  if (p->analyzed)
    return;
  p->analyzed = true;

  // Parse-only mode must not even install a cooperative analysis deadline:
  // Rizin's console break state is process-wide, and touching it here is an
  // observable analysis side effect despite running no pass.
  if (p->level == AnalysisLevel::None)
    return;
  p->start_deadline();
  if (budget_exhausted())
    return;

  // Rizin's normal CLI wrapper installs its own SIGINT handler while applying
  // analysis.timeout. Hayabusa must retain its fatal handler because it may be
  // supervising a launched process tree. A context break scope with `sig=false`
  // provides the same cooperative deadline without touching process signals.
  RzCons *cons = rz_cons_singleton();
  RzConsContext *context = cons ? cons->context : nullptr;
  if (context)
    rz_cons_context_break_push(context, nullptr, nullptr, false);
  const uint32_t remaining_seconds = p->remaining_seconds();
  if (p->work_deadline != Impl::Clock::time_point::max())
    rz_cons_break_timeout(remaining_seconds);
  switch (p->level) {
  case AnalysisLevel::None:
    break; // handled by the early return above
  case AnalysisLevel::Basic:
    // `aa`: functions only. Data cross-references stay empty at this level, so
    // string references and import correlation will be missing from the report.
    rz_core_analysis_all(p->core);
    break;
  case AnalysisLevel::Full:
    // `aaa`. No fall back to `aa` on failure: a half-analysed image that still
    // produces output is worse than one that says it failed, because the gap
    // shows up as missing findings rather than as an error.
    if (!rz_core_analysis_everything(p->core, false, nullptr)) {
      p->analysis_failed = true;
      fprintf(stderr, "[rizin] full analysis failed for this module; its "
                      "findings are incomplete\n");
    }
    break;
  }

  // Pointer-table recovery defines functions that nothing branches to, so it
  // has to run here rather than at the point the report asks for the tables:
  // by then FUNCTIONS, the function map and the decompiler targets have all
  // been chosen. The recursive call back into analyze() is a no-op, p->analyzed
  // is already set.
  if (!rz_cons_is_breaked())
    function_tables();

  if (rz_cons_is_breaked() || budget_exhausted()) {
    p->analysis_failed = true;
  }
  rz_cons_break_timeout(0);
  if (context)
    rz_cons_context_break_pop(context, false);
}

std::vector<Insn> Image::disassemble(uint64_t addr, size_t count,
                                    size_t max_bytes) {
  std::vector<Insn> out;
  if (count == 0 || count > (std::numeric_limits<size_t>::max() - 16) / 4)
    return out;
  out.reserve(count);
  std::vector<uint8_t> buf(count * 4 + 16);
  const int read_count =
      rz_io_nread_at(p->core->io, addr, buf.data(), buf.size());
  if (read_count <= 0)
    return out;
  // rz_io_nread_at deliberately stops at the first mapping boundary. Never
  // decode the zero-initialised tail of the vector as if it came from the
  // image; a short read is a short disassembly window.
  buf.resize(std::min(buf.size(), static_cast<size_t>(read_count)));

  uint64_t pc = addr;
  size_t off = 0;
  for (size_t i = 0; i < count && off + 4 <= buf.size(); i++) {
    if (max_bytes && (off >= max_bytes || max_bytes - off < 4))
      break;
    RzAnalysisOp op;
    rz_analysis_op_init(&op);
    int len = rz_analysis_op(p->core->analysis, &op, pc, buf.data() + off,
                             (int)(buf.size() - off), RZ_ANALYSIS_OP_MASK_DISASM);
    if (len <= 0) {
      rz_analysis_op_fini(&op);
      break;
    }
    Insn insn;
    fill_insn(&op, buf.data() + off, &insn);
    if (insn.text.empty()) {
      // RzAnalysisOp carries a mnemonic only for architectures whose analysis
      // plugin fills one in. Dalvik's does not -- the text comes from the RzAsm
      // layer -- so every Dalvik listing printed addresses and blank lines.
      RzAsmOp aop;
      rz_asm_op_init(&aop);
      rz_asm_set_pc(p->core->rasm, pc);
      if (rz_asm_disassemble(p->core->rasm, &aop, buf.data() + off,
                             (int)(buf.size() - off)) > 0) {
        if (const char *text = rz_asm_op_get_asm(&aop))
          insn.text = text;
      }
      rz_asm_op_fini(&aop);
    }
    out.push_back(std::move(insn));
    rz_analysis_op_fini(&op);
    pc += len;
    off += static_cast<size_t>(len);
  }
  return out;
}

std::string Image::decompile(uint64_t addr) {
  if (p->level == AnalysisLevel::None) {
    p->decompiler_error = "decompilation is disabled at analysis level none";
    return {};
  }
  analyze();
  p->decompiler_error.clear();
  if (budget_exhausted()) {
    p->decompiler_error = "shared analysis deadline exhausted";
    return {};
  }

  const std::string &home = sleigh_home();
  if (home.empty()) {
    p->decompiler_error = "could not unpack the embedded sleigh data";
    return {};
  }
  rz_config_set(p->core->config, "ghidra.sleighhome", home.c_str());
  // rz-ghidra colours its own output regardless of what was set at startup, and
  // these strings go into a plain text report.
  rz_config_set_i(p->core->config, "scr.color", 0);
  rz_config_set_b(p->core->config, "scr.html", false);

  RzCons *cons = rz_cons_singleton();
  RzConsContext *context = cons ? cons->context : nullptr;
  if (context)
    rz_cons_context_break_push(context, nullptr, nullptr, false);
  const uint32_t remaining = p->remaining_seconds();
  if (p->work_deadline != Impl::Clock::time_point::max())
    rz_cons_break_timeout(remaining);
  RzAnnotatedCode *code = rz_ghidra_decompile_annotated_code(p->core, addr);
  const bool interrupted = rz_cons_is_breaked();
  rz_cons_break_timeout(0);
  if (context)
    rz_cons_context_break_pop(context, false);
  if (interrupted || budget_exhausted()) {
    if (code)
      rz_annotated_code_free(code);
    p->analysis_failed = true;
    p->decompiler_error = "shared analysis deadline exhausted";
    return {};
  }
  if (!code || !code->code) {
    if (code)
      rz_annotated_code_free(code);
    p->decompiler_error = "decompiler produced no output";
    return {};
  }

  std::string out(code->code);
  rz_annotated_code_free(code);
  if (out.empty()) {
    p->decompiler_error = "decompiler produced no output";
    return {};
  }
  if (out.find("Ghidra Decompiler Error:") != std::string::npos) {
    const size_t end = out.find_first_of("\r\n");
    p->decompiler_error = out.substr(0, end);
    return {};
  }
  return out;
}

std::string Image::decompile_dex_method(uint64_t vaddr, uint64_t size) {
  if (p->level == AnalysisLevel::None) {
    p->decompiler_error = "decompilation is disabled at analysis level none";
    return {};
  }
  analyze();
  p->decompiler_error.clear();
  if (vaddr == 0 || size == 0) {
    p->decompiler_error = "DEX method has no concrete bytecode body";
    return {};
  }
  if (vaddr > UINT32_MAX || size > UINT32_MAX ||
      vaddr > UINT32_MAX - size) {
    p->decompiler_error =
        "DEX method is outside Dalvik's 32-bit decompiler address space; "
        "rebuild the pinned rizin dependency with "
        "cross/rizin-dex-32bit.patch";
    return {};
  }

  // `aa` legitimately skips some tiny constructors and wrappers. Ghidra only
  // needs a concrete Rizin function at the entry; it recovers the bytecode CFG
  // itself. Ask Rizin to analyze it first, then create the entry explicitly if
  // the architecture analyzer still declines it.
  RzAnalysisFunction *function =
      rz_analysis_get_function_at(p->core->analysis, vaddr);
  if (!function) {
    char name[48];
    snprintf(name, sizeof(name), "dex.method.%08llx",
             static_cast<unsigned long long>(vaddr));
    rz_core_analysis_function_add(p->core, name, vaddr, false);
    function = rz_analysis_get_function_at(p->core->analysis, vaddr);
    if (!function)
      function = rz_analysis_create_function(
          p->core->analysis, name, vaddr, RZ_ANALYSIS_FCN_TYPE_FCN);
  }
  if (!function) {
    p->decompiler_error = "could not define the DEX method for decompilation";
    return {};
  }
  return decompile(vaddr);
}

void Image::adopt_base(uint64_t base) {
  if (base && !p->base)
    p->base = base;
}

uint64_t Image::base() const { return p->base; }

bool Image::analysis_failed() const {
  (void)const_cast<Image *>(this)->budget_exhausted();
  return p->analysis_failed;
}

bool Image::budget_exhausted() {
  if (!p->deadline_started ||
      p->work_deadline == Impl::Clock::time_point::max() ||
      Impl::Clock::now() < p->work_deadline)
    return false;
  p->analysis_failed = true;
  if (!p->deadline_reported) {
    p->deadline_reported = true;
    fprintf(stderr,
            "[rizin] analysis exceeded its shared %u-second module budget; "
            "remaining findings are incomplete\n",
            p->limits.module_timeout_seconds);
  }
  return true;
}

const std::string &Image::decompiler_error() const {
  return p->decompiler_error;
}

std::vector<uint64_t> Image::functions() {
  if (p->level == AnalysisLevel::None)
    return {};
  analyze();
  if (budget_exhausted())
    return {};
  std::vector<uint64_t> out;
  list_for_each<RzAnalysisFunction>(
      rz_analysis_function_list(p->core->analysis),
      [&](RzAnalysisFunction *fcn) { out.push_back(fcn->addr); });
  return out;
}

uint64_t Image::function_size(uint64_t addr) {
  if (p->level == AnalysisLevel::None)
    return 0;
  analyze();
  RzAnalysisFunction *fcn = rz_analysis_get_function_at(p->core->analysis, addr);
  if (!fcn)
    fcn = rz_analysis_get_fcn_in(p->core->analysis, addr, 0);
  return fcn ? rz_analysis_function_linear_size(fcn) : 0;
}

std::string Image::name_at(uint64_t addr) {
  RzFlagItem *f = rz_flag_get_i(p->core->flags, addr);
  return f && f->name ? f->name : std::string();
}

std::vector<Call> Image::import_call_sites() {
  if (p->level == AnalysisLevel::None)
    return {};
  analyze();
  if (budget_exhausted())
    return {};
  std::vector<Call> out;
  RzBinObject *obj = rz_bin_cur_object(p->core->bin);
  if (!obj)
    return out;
  const RzPVector *imports = rz_bin_object_get_imports(obj);
  if (!imports)
    return out;

  void **iter = nullptr;
  rz_pvector_foreach(imports, iter) {
    if (budget_exhausted())
      break;
    RzBinImport *imp = static_cast<RzBinImport *>(*iter);
    if (!imp || !imp->name)
      continue;
    // An import has no address of its own; its PLT stub carries the flag that
    // call sites actually branch to.
    RzFlagItem *flag =
        rz_flag_get(p->core->flags, ("sym.imp." + std::string(imp->name)).c_str());
    if (!flag)
      flag = rz_flag_get(p->core->flags,
                         ("reloc." + std::string(imp->name)).c_str());
    if (!flag)
      continue;
    RzList *xrefs = rz_analysis_xrefs_get_to(p->core->analysis, flag->offset);
    if (!xrefs)
      continue;
    list_for_each<RzAnalysisXRef>(xrefs, [&](RzAnalysisXRef *xref) {
      if (xref->type != RZ_ANALYSIS_XREF_TYPE_CALL)
        return;
      Call c;
      c.site = xref->from;
      c.target = flag->offset;
      c.symbol = imp->name;
      out.push_back(std::move(c));
    });
    rz_list_free(xrefs);
  }
  return out;
}

std::vector<Image::RttiClass> Image::rtti_classes() {
  // RTTI recovery mutates both the analysis database and the class-vtable
  // store. Parse-only mode must expose only bin-plugin metadata, never trigger
  // this recovery pass implicitly through a report query.
  if (p->level == AnalysisLevel::None)
    return {};
  analyze();
  if (budget_exhausted())
    return {};
  // `aaa` recovers the classes but not their vtable addresses; that is a
  // separate pass (rizin's `avrr`). Without it every class came back with no
  // vtable, which is the one field the runtime instance scan needs.
  std::call_once(p->rtti_once, [&] {
    RzCons *cons = rz_cons_singleton();
    RzConsContext *context = cons ? cons->context : nullptr;
    if (context)
      rz_cons_context_break_push(context, nullptr, nullptr, false);
    const uint32_t remaining = p->remaining_seconds();
    if (p->work_deadline != Impl::Clock::time_point::max())
      rz_cons_break_timeout(remaining);
    rz_analysis_rtti_recover_all(p->core->analysis);
    const bool interrupted = rz_cons_is_breaked();
    rz_cons_break_timeout(0);
    if (context)
      rz_cons_context_break_pop(context, false);
    if (interrupted)
      p->analysis_failed = true;
  });
  if (budget_exhausted() || p->analysis_failed)
    return {};
  std::vector<RttiClass> out;
  RzBinObject *obj = rz_bin_cur_object(p->core->bin);
  if (!obj)
    return out;
  const RzPVector *classes = rz_bin_object_get_classes(obj);
  if (!classes)
    return out;

  void **iter = nullptr;
  rz_pvector_foreach(classes, iter) {
    if (budget_exhausted())
      break;
    RzBinClass *cls = static_cast<RzBinClass *>(*iter);
    if (!cls || !cls->name)
      continue;
    RttiClass rc;
    rc.name = cls->name;
    // RzBinClass::addr is UT64_MAX for a class recovered from C++ RTTI -- the
    // bin layer has no address to give, the vtable is found by analysis. Taking
    // it verbatim reported every vtable at base-1 and left the runtime instance
    // scan with nothing to search for.
    rc.vtable_vaddr = cls->addr == UT64_MAX ? 0 : cls->addr;
    rc.typeinfo_vaddr = 0;
    if (RzVector *vts =
            rz_analysis_class_vtable_get_all(p->core->analysis, cls->name)) {
      void *vt_it;
      rz_vector_foreach (vts, vt_it) {
        RzAnalysisVTable *vt = static_cast<RzAnalysisVTable *>(vt_it);
        if (vt && vt->addr && vt->addr != UT64_MAX) {
          rc.vtable_vaddr = vt->addr;
          break;
        }
      }
      rz_vector_free(vts);
    }
    list_for_each<RzBinSymbol>(cls->methods, [&](RzBinSymbol *sym) {
      rc.vfuncs.push_back(sym->vaddr);
    });
    out.push_back(std::move(rc));
  }
  return out;
}

std::vector<Image::BinClass> Image::bin_classes() {
  std::vector<BinClass> out;
  RzBinObject *obj = rz_bin_cur_object(p->core->bin);
  if (!obj)
    return out;
  const RzPVector *classes = rz_bin_object_get_classes(obj);
  if (!classes)
    return out;

  void **iter = nullptr;
  rz_pvector_foreach (classes, iter) {
    RzBinClass *cls = static_cast<RzBinClass *>(*iter);
    if (!cls || !cls->name)
      continue;
    BinClass bc;
    bc.name = cls->name;
    bc.super = cls->super ? cls->super : "";
    list_for_each<RzBinSymbol>(cls->methods, [&](RzBinSymbol *sym) {
      if (sym->name)
        bc.methods.push_back({sym->name, sym->paddr, sym->vaddr, sym->size});
    });
    list_for_each<RzBinClassField>(cls->fields, [&](RzBinClassField *fld) {
      if (fld->name)
        bc.fields.push_back(fld->name);
    });
    out.push_back(std::move(bc));
  }
  return out;
}

uint64_t Image::offset_to_vaddr(uint64_t file_offset) {
  RzBinObject *obj = rz_bin_cur_object(p->core->bin);
  if (!obj) {
    p->analysis_failed = true;
    return UINT64_MAX;
  }
  ut64 va = rz_bin_object_p2v(obj, file_offset);
  if (va == UT64_MAX) {
    p->analysis_failed = true;
    return UINT64_MAX;
  }
  return va;
}

uint64_t Image::vaddr_to_offset(uint64_t vaddr) {
  RzBinObject *obj = rz_bin_cur_object(p->core->bin);
  if (!obj) {
    p->analysis_failed = true;
    return UINT64_MAX;
  }
  ut64 pa = rz_bin_object_v2p(obj, vaddr);
  if (pa == UT64_MAX) {
    p->analysis_failed = true;
    return UINT64_MAX;
  }
  return pa;
}

std::vector<Image::Str> Image::strings(size_t max_results,
                                      size_t max_retained_bytes) {
  std::vector<Str> out;
  RzBinObject *obj = rz_bin_cur_object(p->core->bin);
  if (!obj)
    return out;
  const RzPVector *strs = rz_bin_object_get_strings(obj);
  if (!strs)
    return out;
  void **iter = nullptr;
  size_t retained_bytes = 0;
  rz_pvector_foreach(strs, iter) {
    if (out.size() >= max_results)
      break;
    RzBinString *bs = static_cast<RzBinString *>(*iter);
    if (!bs || !bs->string)
      continue;
    const size_t length = strnlen(bs->string, 64U * 1024U + 1U);
    if (length > 64U * 1024U || length > max_retained_bytes -
                                             std::min(max_retained_bytes,
                                                      retained_bytes))
      continue;
    Str s;
    s.paddr = bs->paddr;
    s.vaddr = bs->vaddr;
    s.text.assign(bs->string, length);
    retained_bytes += length;
    out.push_back(std::move(s));
  }
  return out;
}

std::vector<uint64_t> Image::xrefs_to(uint64_t target, size_t max_results,
                                      size_t *examined_remaining,
                                      bool *truncated) {
  if (p->level == AnalysisLevel::None) {
    if (truncated)
      *truncated = p->analysis_failed;
    return {};
  }
  analyze();
  if (budget_exhausted()) {
    if (truncated)
      *truncated = true;
    return {};
  }
  if (truncated)
    *truncated = p->analysis_failed;
  if (target == UINT64_MAX) {
    p->analysis_failed = true;
    if (truncated)
      *truncated = true;
    return {};
  }
  std::set<uint64_t> unique;
  RzList *xrefs = rz_analysis_xrefs_get_to(p->core->analysis, target);
  if (!xrefs)
    return {};
  for (RzListIter *it = xrefs->head; it; it = it->next) {
    if (budget_exhausted()) {
      if (truncated)
        *truncated = true;
      break;
    }
    if (examined_remaining && *examined_remaining == 0) {
      if (truncated)
        *truncated = true;
      break;
    }
    if (examined_remaining)
      --*examined_remaining;
    auto *x = static_cast<RzAnalysisXRef *>(it->val);
    if (!x)
      continue;
    if (x->type == RZ_ANALYSIS_XREF_TYPE_STRING ||
        x->type == RZ_ANALYSIS_XREF_TYPE_DATA ||
        x->type == RZ_ANALYSIS_XREF_TYPE_CODE) {
      if (unique.count(x->from) != 0)
        continue;
      if (unique.size() >= max_results) {
        if (truncated)
          *truncated = true;
        break;
      }
      unique.insert(x->from);
    }
  }
  rz_list_free(xrefs);
  return {unique.begin(), unique.end()};
}

bool Image::signature(uint64_t addr, size_t length,
                      std::vector<uint8_t> *bytes, std::vector<bool> *mask) {
  if (!bytes || !mask || !length || addr == UINT64_MAX ||
      length > static_cast<size_t>(std::numeric_limits<int>::max()))
    return false;
  bytes->assign(length, 0);
  const int read_count =
      rz_io_nread_at(p->core->io, addr, bytes->data(), length);
  // A signature claims every emitted byte came from the requested function.
  // Reject a mapping-boundary short read instead of signing the vector's
  // zero-filled suffix.
  if (read_count < 0 || static_cast<size_t>(read_count) != length) {
    bytes->clear();
    mask->clear();
    return false;
  }
  mask->assign(length, false);

  uint64_t pc = addr;
  size_t off = 0;
  while (off + 4 <= length) {
    RzAnalysisOp op;
    rz_analysis_op_init(&op);
    int len = rz_analysis_op(p->core->analysis, &op, pc, bytes->data() + off,
                             (int)(length - off), RZ_ANALYSIS_OP_MASK_BASIC);
    if (len <= 0) {
      rz_analysis_op_fini(&op);
      break;
    }
    // Anything carrying a target or a memory pointer moves when the image is
    // relocated, so those bytes cannot be part of a stable pattern.
    bool relocatable = (op.jump != UT64_MAX && op.jump != 0) || op.ptr != 0;
    if (relocatable) {
      for (int i = 0; i < len && off + i < length; i++)
        (*mask)[off + i] = true;
    }
    rz_analysis_op_fini(&op);
    pc += len;
    off += static_cast<size_t>(len);
  }
  return true;
}

std::vector<Image::Import> Image::imports() {
  std::vector<Import> out;
  RzBinObject *obj = rz_bin_cur_object(p->core->bin);
  if (!obj || !obj->relocs)
    return out;

  // target_vaddr is what the old hand-written PLT scanner was reconstructing by
  // decoding `adrp x16 / ldr x17 / br x17` stubs: rizin resolves it from the
  // relocation itself, so there is no instruction pattern to keep in step with.
  for (size_t i = 0; i < obj->relocs->relocs_count; i++) {
    RzBinReloc *rel = obj->relocs->relocs[i];
    if (!rel)
      continue;
    const char *name = nullptr;
    if (rel->import && rel->import->name)
      name = rel->import->name;
    else if (rel->symbol && rel->symbol->name)
      name = rel->symbol->name;
    if (!name || !*name)
      continue;
    Import imp;
    imp.got_vaddr = rel->vaddr;
    imp.stub_vaddr = rel->target_vaddr;
    imp.symbol = name;
    out.push_back(std::move(imp));
  }
  return out;
}

std::vector<Image::PointerRun> Image::function_tables(size_t min_run,
                                                      bool *truncated) {
  if (truncated)
    *truncated = false;
  // Besides scanning, this query defines every accepted target as a function.
  // Returning before analyze() is therefore required for genuinely parse-only
  // operation, not merely an optimisation.
  if (p->level == AnalysisLevel::None)
    return {};
  analyze();
  if (budget_exhausted()) {
    if (truncated)
      *truncated = true;
    return {};
  }
  auto cached = p->function_table_cache.find(min_run);
  if (cached != p->function_table_cache.end()) {
    if (truncated)
      *truncated = p->analysis_failed ||
                   p->function_table_truncated_cache[min_run];
    return cached->second;
  }
  std::vector<PointerRun> out;
  constexpr size_t kPointerTableReadBlockBytes = 256U * 1024U;
  constexpr size_t kDeadlineCheckSlots = 4096;
  const uint64_t max_scan_bytes = p->limits.pointer_scan_bytes == 0
                                      ? std::numeric_limits<uint64_t>::max()
                                      : p->limits.pointer_scan_bytes;
  const size_t max_slots = p->limits.pointer_slots;
  const size_t max_tables = p->limits.pointer_tables;
  const size_t max_targets = p->limits.analysis_targets;
  bool was_truncated = p->analysis_failed;

  // A run is accepted on the strength of where the pointers land, not on
  // whether analysis already named them.
  //
  // Requiring every slot to be an already-recovered function made the whole
  // section circular: a static helper reached only through a dispatch table has
  // nothing branching to it, so analysis never finds it, so the table holding
  // it is never recognised, so the helper is never found. Aiming at executable
  // memory at instruction alignment is enough to identify the run, and the
  // targets are handed to analysis afterwards.
  std::vector<std::pair<uint64_t, uint64_t>> exec_ranges;
  if (RzBinObject *obj = rz_bin_cur_object(p->core->bin)) {
    if (RzPVector *segs = rz_bin_object_get_segments(obj)) {
      void **it;
      rz_pvector_foreach (segs, it) {
        RzBinSection *sec = static_cast<RzBinSection *>(*it);
        if (!sec || !(sec->perm & RZ_PERM_X))
          continue;
        const uint64_t backed = std::min<uint64_t>(sec->vsize, sec->size);
        if (backed && sec->vaddr <= UINT64_MAX - backed)
          exec_ranges.push_back({sec->vaddr, sec->vaddr + backed});
      }
      rz_pvector_free(segs);
    }
  }
  if (exec_ranges.empty()) {
    p->function_table_truncated_cache[min_run] = was_truncated;
    if (truncated)
      *truncated = was_truncated;
    return p->function_table_cache.emplace(min_run, out).first->second;
  }

  std::sort(exec_ranges.begin(), exec_ranges.end());
  std::vector<std::pair<uint64_t, uint64_t>> merged_exec_ranges;
  for (const auto &range : exec_ranges) {
    if (merged_exec_ranges.empty() ||
        range.first > merged_exec_ranges.back().second) {
      merged_exec_ranges.push_back(range);
    } else {
      merged_exec_ranges.back().second =
          std::max(merged_exec_ranges.back().second, range.second);
    }
  }

  auto points_at_code = [&](uint64_t a) {
    if (a & 3) // AArch64 instructions are 4-byte aligned
      return false;
    auto it = std::upper_bound(
        merged_exec_ranges.begin(), merged_exec_ranges.end(), a,
        [](uint64_t value, const auto &range) { return value < range.first; });
    if (it == merged_exec_ranges.begin())
      return false;
    --it;
    return a >= it->first && a < it->second;
  };

  // Scanned over the binary's own segments, not over rizin's io maps.
  //
  // A dumped library loads with one io map per section that has file backing,
  // which leaves .data.rel.ro -- where a const table of function pointers
  // actually lives -- outside every map. Walking segments covers it, and
  // rz_io_nread_at resolves the address either way.
  std::vector<std::pair<uint64_t, uint64_t>> scan_ranges;
  if (RzBinObject *obj = rz_bin_cur_object(p->core->bin)) {
    if (RzPVector *segs = rz_bin_object_get_segments(obj)) {
      void **it;
      rz_pvector_foreach (segs, it) {
        RzBinSection *sec = static_cast<RzBinSection *>(*it);
        if (!sec || (sec->perm & RZ_PERM_X))
          continue;
        const uint64_t backed = std::min<uint64_t>(sec->vsize, sec->size);
        if (backed && sec->vaddr <= UINT64_MAX - backed)
          scan_ranges.push_back({sec->vaddr, sec->vaddr + backed});
      }
      rz_pvector_free(segs);
    }
  }

  std::sort(scan_ranges.begin(), scan_ranges.end());
  std::vector<std::pair<uint64_t, uint64_t>> merged_ranges;
  for (const auto &range : scan_ranges) {
    if (merged_ranges.empty() || range.first > merged_ranges.back().second) {
      merged_ranges.push_back(range);
    } else {
      merged_ranges.back().second =
          std::max(merged_ranges.back().second, range.second);
    }
  }

  std::vector<uint64_t> targets;
  std::set<uint64_t> seen_runs;
  std::vector<uint8_t> read_block(kPointerTableReadBlockBytes);
  uint64_t scan_work_bytes = 0;
  size_t retained_slots = 0;
  bool stop_scan = false;
  auto scan_deadline = p->work_deadline;
  if (p->limits.table_timeout_seconds != 0)
    scan_deadline = std::min(
        scan_deadline, std::chrono::steady_clock::now() +
                           std::chrono::seconds(
                               p->limits.table_timeout_seconds));
  for (const auto &range : merged_ranges) {
    if (stop_scan)
      break;
    uint64_t run_start = 0;
    size_t run = 0;
    std::vector<uint64_t> run_targets;
    auto close_run = [&]() {
      // PT_LOAD and PT_GNU_RELRO describe the same bytes, so the same table is
      // reached twice; keep the first sighting.
      if (run >= min_run && seen_runs.insert(run_start).second) {
        const size_t available = max_slots - retained_slots;
        const size_t keep = std::min(available, run_targets.size());
        if (keep != 0 && out.size() < max_tables) {
          run_targets.resize(keep);
          out.push_back({run_start, keep, run_targets});
          targets.insert(targets.end(), run_targets.begin(), run_targets.end());
          retained_slots += keep;
        }
        if (keep < run || out.size() >= max_tables ||
            retained_slots >= max_slots) {
          was_truncated = true;
          stop_scan = true;
        }
      }
      run = 0;
      run_targets.clear();
    };

    uint64_t cursor = range.first;
    while (cursor < range.second && !stop_scan) {
      if (scan_work_bytes >= max_scan_bytes ||
          rz_cons_is_breaked() ||
          std::chrono::steady_clock::now() >= scan_deadline) {
        was_truncated = true;
        stop_scan = true;
        break;
      }

      const uint64_t range_remaining = range.second - cursor;
      const uint64_t work_remaining =
          max_scan_bytes - scan_work_bytes;
      size_t request = static_cast<size_t>(std::min<uint64_t>(
          std::min<uint64_t>(range_remaining, work_remaining),
          read_block.size()));
      // Pointer candidates use the same eight-byte lattice as the old scanner.
      // A final sub-slot tail cannot contain a complete pointer.
      request -= request % sizeof(uint64_t);
      if (request < sizeof(uint64_t)) {
        if (range_remaining >= sizeof(uint64_t) ||
            work_remaining < sizeof(uint64_t))
          was_truncated = true;
        break;
      }

      const int read_count =
          rz_io_nread_at(p->core->io, cursor, read_block.data(), request);
      scan_work_bytes += request;
      const size_t actual = read_count > 0
                                ? std::min(request,
                                           static_cast<size_t>(read_count))
                                : 0;
      if (read_count < 0 || actual != request)
        was_truncated = true;

      const size_t complete = actual - actual % sizeof(uint64_t);
      size_t deadline_slots = 0;
      for (size_t off = 0; off < complete && !stop_scan;
           off += sizeof(uint64_t)) {
        if (++deadline_slots >= kDeadlineCheckSlots) {
          deadline_slots = 0;
          if (rz_cons_is_breaked() ||
              std::chrono::steady_clock::now() >= scan_deadline) {
            was_truncated = true;
            stop_scan = true;
            break;
          }
        }

        uint64_t ptr = 0;
        memcpy(&ptr, read_block.data() + off, sizeof(ptr));
        // The image was lifted after the loader applied R_AARCH64_RELATIVE, so
        // the slots hold live addresses while rizin holds the module at zero.
        if (ptr && p->base && ptr >= p->base)
          ptr -= p->base;
        if (ptr && points_at_code(ptr)) {
          if (run == 0)
            run_start = cursor + off;
          run++;
          run_targets.push_back(ptr);
          if (retained_slots + run_targets.size() >=
              max_slots) {
            was_truncated = true;
            stop_scan = true;
          }
          continue;
        }
        close_run();
      }

      // A short block leaves a gap in a segment Rizin claimed was backed.
      // Preserve the valid prefix, close any run at the gap, and advance by the
      // attempted block so later mapped data can still be recovered with the
      // global result explicitly marked incomplete.
      if (actual != request) {
        close_run();
      }
      cursor += request;
    }
    close_run();
  }
  // Everything a table points at is a function entry, whether or not anything
  // branches to it. Defining them here is what makes a table-dispatched helper
  // show up in FUNCTIONS and get decompiled.
  std::set<uint64_t> analyzed_targets;
  auto analysis_deadline = p->work_deadline;
  if (p->limits.table_timeout_seconds != 0)
    analysis_deadline = std::min(
        analysis_deadline, std::chrono::steady_clock::now() +
                               std::chrono::seconds(
                                   p->limits.table_timeout_seconds));
  for (uint64_t t : targets) {
    if (!analyzed_targets.insert(t).second)
      continue;
    if (analyzed_targets.size() > max_targets ||
        rz_cons_is_breaked() ||
        std::chrono::steady_clock::now() >= analysis_deadline) {
      was_truncated = true;
      break;
    }
    if (rz_analysis_get_function_at(p->core->analysis, t))
      continue;
    (void)rz_core_analysis_fcn(p->core, t, UT64_MAX,
                               RZ_ANALYSIS_XREF_TYPE_NULL, 1);
  }

  p->function_table_cache[min_run] = out;
  p->function_table_truncated_cache[min_run] = was_truncated;
  if (truncated)
    *truncated = was_truncated;
  return out;
}

std::vector<uint64_t>
Image::materialised_constants(uint64_t func_addr, size_t max_insns) {
  if (p->level == AnalysisLevel::None)
    return {};
  analyze();
  if (budget_exhausted())
    return {};
  std::vector<uint64_t> out;

  if (max_insns == 0 ||
      max_insns > std::numeric_limits<size_t>::max() / 4)
    return out;
  std::vector<uint8_t> code(max_insns * 4);
  const int read_count =
      rz_io_nread_at(p->core->io, func_addr, code.data(), code.size());
  if (read_count <= 0)
    return out;
  code.resize(std::min(code.size(), static_cast<size_t>(read_count)));

  uint64_t reg[32] = {};
  bool live[32] = {};
  auto parse_mnemonic_number = [](const char *text, uint64_t *value) {
    if (!text || !value)
      return false;
    while (isspace(static_cast<unsigned char>(*text)))
      ++text;
    int base = 10;
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
      base = 16;
      text += 2;
    }
    const char *end = text;
    while ((base == 16 && isxdigit(static_cast<unsigned char>(*end))) ||
           (base == 10 && isdigit(static_cast<unsigned char>(*end))))
      ++end;
    if (end == text)
      return false;
    const auto parsed = std::from_chars(text, end, *value, base);
    return parsed.ec == std::errc() && parsed.ptr == end;
  };

  uint64_t pc = func_addr;
  size_t off = 0;
  while (off + 4 <= code.size()) {
    if (budget_exhausted())
      break;
    RzAnalysisOp op;
    rz_analysis_op_init(&op);
    int len = rz_analysis_op(p->core->analysis, &op, pc, code.data() + off,
                             (int)(code.size() - off), RZ_ANALYSIS_OP_MASK_DISASM);
    if (len <= 0) {
      rz_analysis_op_fini(&op);
      break;
    }
    const char *m = op.mnemonic;
    // movz xN, 0xIMM[, lsl S]   starts a new constant
    // movk xN, 0xIMM, lsl S     merges into the one already in xN
    if (m && (!strncmp(m, "movz", 4) || !strncmp(m, "movk", 4) ||
              !strncmp(m, "mov ", 4))) {
      const char *r = strpbrk(m, "xw");
      if (r && r[1] >= '0' && r[1] <= '9') {
        uint64_t parsed_idx = 0;
        const char *imm = strchr(m, '#');
        if (!imm)
          imm = strstr(m, ", 0x");
        uint64_t value = 0;
        uint64_t shift = 0;
        const char *ls = strstr(m, "lsl");
        if (imm && parse_mnemonic_number(r + 1, &parsed_idx) &&
            parsed_idx < 32 &&
            parse_mnemonic_number(imm + (*imm == '#' ? 1 : 2), &value) &&
            (!ls || parse_mnemonic_number(ls + 3, &shift)) && shift < 64) {
          const unsigned idx = static_cast<unsigned>(parsed_idx);
          if (!strncmp(m, "movk", 4) && live[idx])
            reg[idx] |= value << shift;
          else
            reg[idx] = value << shift;
          live[idx] = true;
        }
      }
    } else if (m) {
      // A store or a call is where an assembled constant gets used, so that is
      // the point at which it is worth recording.
      InsnType t = map_type(static_cast<uint32_t>(op.type));
      if (t == InsnType::Store || t == InsnType::Call) {
        for (unsigned i = 0; i < 32; i++) {
          if (live[i] && reg[i] > 0xFF && reg[i] != UINT64_MAX) {
            out.push_back(reg[i]);
            live[i] = false;
          }
        }
      }
    }
    rz_analysis_op_fini(&op);
    pc += len;
    off += static_cast<size_t>(len);
  }

  // Anything still held at the end of the window counts too.
  for (unsigned i = 0; i < 32; i++)
    if (live[i] && reg[i] > 0xFF && reg[i] != UINT64_MAX)
      out.push_back(reg[i]);
  return out;
}

std::vector<Image::RegValue> Image::emulate(uint64_t func_addr,
                                            size_t max_steps) {
  if (p->level == AnalysisLevel::None)
    return {};
  analyze();
  if (budget_exhausted())
    return {};
  std::vector<RegValue> out;

  if (!rz_analysis_il_vm_setup(p->core->analysis)) {
    fprintf(stderr, "[il] no IL lifter available for this architecture\n");
    return out;
  }

  RzAnalysisILVM *vm = rz_analysis_il_vm_new(p->core->analysis, nullptr);
  if (!vm) {
    fprintf(stderr, "[il] could not create the IL vm\n");
    return out;
  }

  // Start at the function entry. Anything the code reads that was not written
  // during the run reads as zero, which is the right default here: a
  // constructor that builds a constant does not depend on incoming state.
  rz_bv_free(vm->vm->pc);
  vm->vm->pc = rz_bv_new_from_ut64(64, func_addr);

  size_t steps = 0;
  for (; steps < max_steps; steps++) {
    if (budget_exhausted())
      break;
    RzAnalysisILStepResult r =
        rz_analysis_il_vm_step(p->core->analysis, vm, nullptr);
    if (r == RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS)
      continue;
    // Report where the run stopped. A single unlifted instruction ends
    // emulation, and without this the caller cannot tell that from a function
    // that genuinely computed nothing.
    const char *why = r == RZ_ANALYSIS_IL_STEP_RESULT_NOT_SET_UP ? "not set up"
                      : r == RZ_ANALYSIS_IL_STEP_IL_RUNTIME_ERROR ? "runtime error"
                      : r == RZ_ANALYSIS_IL_STEP_UNIMPLEMENTED_IL ? "unimplemented il"
                                                                  : "invalid op";
    fprintf(stderr, "[il] 0x%llx: stopped after %zu steps: %s\n",
            (unsigned long long)func_addr, steps, why);
    break;
  }

  // x0..x30 hold anything the function assembled.
  for (int i = 0; i <= 30; i++) {
    std::string name = "x" + std::to_string(i);
    RzILVal *v = rz_il_vm_get_var_value(vm->vm, RZ_IL_VAR_KIND_GLOBAL,
                                        name.c_str());
    if (!v || v->type != RZ_IL_TYPE_PURE_BITVECTOR || !v->data.bv)
      continue;
    uint64_t raw = rz_bv_to_ut64(v->data.bv);
    if (raw)
      out.push_back({name, raw});
  }

  fprintf(stderr, "[il] 0x%llx: %zu steps, %zu live registers\n",
          (unsigned long long)func_addr, steps, out.size());
  rz_analysis_il_vm_free(vm);
  return out;
}

std::vector<Image::FieldAccess> Image::field_accesses(uint64_t func_addr) {
  if (p->level == AnalysisLevel::None)
    return {};
  analyze();
  if (budget_exhausted())
    return {};
  std::vector<FieldAccess> out;
  uint64_t size = function_size(func_addr);
  if (!size || size > 1u << 20)
    return out;

  std::vector<uint8_t> code(size);
  const int read_count =
      rz_io_nread_at(p->core->io, func_addr, code.data(), code.size());
  if (read_count <= 0)
    return out;
  code.resize(std::min(code.size(), static_cast<size_t>(read_count)));

  std::map<uint64_t, FieldAccess> by_offset;
  uint64_t pc = func_addr;
  size_t off = 0;
  while (off + 4 <= code.size()) {
    if (budget_exhausted())
      break;
    RzAnalysisOp op;
    rz_analysis_op_init(&op);
    int len = rz_analysis_op(p->core->analysis, &op, pc, code.data() + off,
                             (int)(code.size() - off), RZ_ANALYSIS_OP_MASK_DISASM);
    if (len <= 0) {
      rz_analysis_op_fini(&op);
      break;
    }
    InsnType t = map_type(static_cast<uint32_t>(op.type));
    uint64_t disp = 0;
    if ((t == InsnType::Load || t == InsnType::Store) &&
        parse_x0_disp(op.mnemonic, &disp)) {
      FieldAccess &fa = by_offset[disp];
      fa.offset = disp;
      fa.width = std::max(fa.width, access_width(op.mnemonic));
      fa.read = fa.read || t == InsnType::Load;
      fa.written = fa.written || t == InsnType::Store;
      fa.hits++;
    }
    rz_analysis_op_fini(&op);
    pc += len;
    off += static_cast<size_t>(len);
  }

  out.reserve(by_offset.size());
  for (const auto &kv : by_offset)
    out.push_back(kv.second);
  return out;
}

namespace {

uint64_t image_fingerprint(const std::vector<uint8_t> &data) {
  // A worker reuses its vector allocation for consecutive modules. Pointer and
  // size are therefore not an identity: two same-sized modules can occupy the
  // same address. Hash the bytes so a reused allocation cannot return the
  // previous module's RzCore.
  uint64_t h = 1469598103934665603ULL;
  for (uint8_t b : data) {
    h ^= b;
    h *= 1099511628211ULL;
  }
  return h;
}

struct ThreadSession {
  size_t size = 0;
  uint64_t fingerprint = 0;
  bool attempted = false;
  std::unique_ptr<Image> image;
};

thread_local ThreadSession g_thread_session;

} // namespace

Image *shared_image(const std::vector<uint8_t> &data, uint64_t base) {
  const uint64_t fingerprint = image_fingerprint(data);
  if (g_thread_session.attempted && g_thread_session.size == data.size() &&
      g_thread_session.fingerprint == fingerprint) {
    if (g_thread_session.image)
      g_thread_session.image->adopt_base(base);
    return g_thread_session.image.get();
  }

  // A process-wide four-entry cache returned raw pointers after dropping its
  // lock. The fifth concurrent module evicted an entry that another worker was
  // still using, unlinked its backing file and freed its RzCore. Keeping the
  // current module in worker-local storage makes its lifetime exactly match the
  // report calls on that worker and removes the cross-thread eviction race.
  g_thread_session.image.reset();
  g_thread_session.size = data.size();
  g_thread_session.fingerprint = fingerprint;
  g_thread_session.attempted = true;
  g_thread_session.image = Image::open(data, base);
  return g_thread_session.image.get();
}

void release_shared_image() {
  g_thread_session.image.reset();
  g_thread_session.size = 0;
  g_thread_session.fingerprint = 0;
  g_thread_session.attempted = false;
}

bool decode_one(const uint8_t *bytes, size_t len, uint64_t addr, Insn *out) {
  if (!bytes || len < 4 || !out)
    return false;

  // A throwaway RzAnalysis rather than a full RzCore: this path runs on bytes
  // read out of a live process, where there is no image to load and no analysis
  // to reuse.
  static std::once_flag once;
  static RzAnalysis *analysis = nullptr;
  std::call_once(once, [] {
    analysis = rz_analysis_new(nullptr);
    if (analysis) {
      rz_analysis_use(analysis, "arm");
      rz_analysis_set_bits(analysis, 64);
    }
  });
  if (!analysis)
    return false;

  // rz_analysis_op mutates shared decoder state, so this one instance is
  // serialised. Callers decode a handful of instructions at a time.
  static std::mutex mu;
  std::lock_guard<std::mutex> lock(mu);

  RzAnalysisOp op;
  rz_analysis_op_init(&op);
  int n = rz_analysis_op(analysis, &op, addr, bytes, (int)len,
                         RZ_ANALYSIS_OP_MASK_DISASM);
  if (n <= 0) {
    rz_analysis_op_fini(&op);
    return false;
  }
  fill_insn(&op, bytes, out);
  rz_analysis_op_fini(&op);
  return true;
}

} // namespace rzb
