#include "memory.h"
#include "tracer.h"
#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

int g_pid = -1;
std::atomic<const char *> g_current_module{nullptr};
std::atomic<const char *> g_current_step{nullptr};
struct ModuleState {
  uint64_t hash = 0;
  uint64_t snapshot_id = 0;
  std::vector<uint8_t> prev_data;
  bool has_prev = false;
  bool init_traced = false;
};

static constexpr const char *USAGE =
    "Usage:\n"
    "  hayabusa dump    <package> --mode <arm32|arm64> [--timeout <sec>] [--p "
    "<files>] [--rd <depth>] [--threads <n>]\n"
    "  hayabusa hook    <package> <function> --mode <arm32|arm64> [--i "
    "<count>]\n"
    "  hayabusa inject  <package> <so_path>  --mode <arm32|arm64>\n"
    "  hayabusa scan    <package> <pattern>  --mode <arm32|arm64>\n"
    "  hayabusa extract <package> <function> --mode <arm32|arm64> [--d "
    "<depth>]\n";

static volatile bool g_hook_running = false;

void cleanup() { ZygoteTracer::cleanup_all_attached(); }

void signal_handler(int sig) {
  const char *msg = "\n[!] Signal received: ";
  write(STDOUT_FILENO, msg, strlen(msg));
  char buf[16];
  snprintf(buf, sizeof(buf), "%d", sig);
  write(STDOUT_FILENO, buf, strlen(buf));
  const char *module = g_current_module.load(std::memory_order_relaxed);
  const char *step = g_current_step.load(std::memory_order_relaxed);
  if (module) {
    write(STDOUT_FILENO, " at ", 4);
    write(STDOUT_FILENO, module, strlen(module));
  }
  if (step) {
    write(STDOUT_FILENO, " [", 2);
    write(STDOUT_FILENO, step, strlen(step));
    write(STDOUT_FILENO, "]", 1);
  }
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

RelinkConfig make_default_relink_config() {
  RelinkConfig cfg{};
  cfg.max_depth = 8;
  cfg.max_total_size = 64 * 1024 * 1024;
  cfg.fix_relocations = true;
  cfg.inline_plt_calls = true;
  return cfg;
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

template <typename Ehdr, typename Phdr>
static bool read_elf_image_impl(int mem_fd, uint64_t base,
                                std::vector<uint8_t> &out,
                                uint64_t &image_size) {
  Ehdr ehdr;
  if (!read_exact(mem_fd, &ehdr, sizeof(ehdr), base))
    return false;
  if (ehdr.e_phoff == 0 || ehdr.e_phnum == 0 ||
      ehdr.e_phentsize != sizeof(Phdr))
    return false;
  size_t ph_size = ehdr.e_phnum * sizeof(Phdr);
  std::vector<Phdr> phdrs(ehdr.e_phnum);
  if (!read_exact(mem_fd, phdrs.data(), ph_size, base + ehdr.e_phoff))
    return false;

  for (const auto &ph : phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
      continue;
    uint64_t end = static_cast<uint64_t>(ph.p_offset) + ph.p_filesz;
    if (end > image_size)
      image_size = end;
  }
  if (image_size == 0 || image_size > std::numeric_limits<size_t>::max())
    return false;

  out.assign(static_cast<size_t>(image_size), 0);

  for (const auto &ph : phdrs) {
    if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
      continue;
    uint64_t src = base + ph.p_vaddr;
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
      if (rd < 0)
        memset(dest + page_off, 0, len);
      else if ((size_t)rd < len)
        memset(dest + page_off + rd, 0, len - rd);
    }
  }
  return true;
}

bool read_elf_image(int mem_fd, uint64_t base, std::vector<uint8_t> &out,
                    uint64_t &image_size) {
  unsigned char ident[EI_NIDENT] = {0};
  if (!read_exact(mem_fd, ident, EI_NIDENT, base))
    return false;
  if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F')
    return false;

  image_size = 0;
  if (ident[EI_CLASS] == ELFCLASS32)
    return read_elf_image_impl<Elf32_Ehdr, Elf32_Phdr>(mem_fd, base, out,
                                                       image_size);
  if (ident[EI_CLASS] == ELFCLASS64)
    return read_elf_image_impl<Elf64_Ehdr, Elf64_Phdr>(mem_fd, base, out,
                                                       image_size);
  return false;
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

void analyze_to_txt(const std::vector<uint8_t> &data, const std::string &path,
                    uint64_t base, const std::string &name,
                    const std::vector<uint8_t> *prev_data, int pid,
                    ModuleState *module_state, std::mutex *runtime_mutex) {
  thread_local std::string current_name;
  current_name = name;
  g_current_module.store(current_name.c_str(), std::memory_order_relaxed);

  std::ofstream f(path);
  if (!f)
    return;

  f << "=== ELF MEMORY ANALYSIS ===\n";
  f << "Module: " << name << "\n";
  f << "Base: 0x" << std::hex << base << std::dec << "\n";
  f << "Size: " << data.size() << " bytes\n";

  std::vector<ElfSymbol> vtables;

  g_current_step.store("symbols", std::memory_order_relaxed);
  size_t symbol_count = ElfParser::count_symbols(data);
  f << "=== SYMBOLS (" << symbol_count << ") ===\n";
  ElfParser::write_symbols(f, data, &vtables);

  g_current_step.store("functions", std::memory_order_relaxed);
  auto symbols = ElfParser::get_symbols(data);
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
    for (const auto &s : func_syms) {
      uint64_t addr = base ? base + s.offset : s.offset;
      f << "0x" << std::hex << addr << std::dec << " "
        << ElfParser::demangle_symbol(s.name);
      if (s.size)
        f << " (" << s.size << ")";
      f << "\n";
    }
  }

  g_current_step.store("objc", std::memory_order_relaxed);
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
      for (const auto &m : objc_methods)
        f << m.first << " -> " << m.second << "\n";
    }
  }

  if (!obj_syms.empty()) {
    f << "\n=== OBJECTS (" << obj_syms.size() << ") ===\n";
    for (const auto &s : obj_syms) {
      uint64_t addr = base ? base + s.offset : s.offset;
      f << "0x" << std::hex << addr << std::dec << " "
        << ElfParser::demangle_symbol(s.name);
      if (s.size)
        f << " (" << s.size << ")";
      f << "\n";
    }
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
    for (const auto &cls : classes) {
      size_t m = class_methods[cls].size();
      size_t fld = class_fields[cls].size();
      f << cls << " methods=" << m << " fields=" << fld << "\n";
    }
  }

  size_t method_total = 0;
  for (const auto &kv : class_methods)
    method_total += kv.second.size();
  if (method_total > 0) {
    f << "\n=== METHODS (" << method_total << ") ===\n";
    for (const auto &kv : class_methods) {
      for (const auto &line : kv.second)
        f << line << "\n";
    }
  }

  size_t field_total = 0;
  for (const auto &kv : class_fields)
    field_total += kv.second.size();
  if (field_total > 0) {
    f << "\n=== FIELDS (" << field_total << ") ===\n";
    for (const auto &kv : class_fields) {
      for (const auto &line : kv.second)
        f << line << "\n";
    }
  }

  g_current_step.store("rtti", std::memory_order_relaxed);
  std::sort(vtables.begin(), vtables.end(),
            [](const ElfSymbol &a, const ElfSymbol &b) {
              return a.offset < b.offset;
            });
  if (!vtables.empty())
    ElfParser::write_rtti(f, data, base, vtables);

  g_current_step.store("strings", std::memory_order_relaxed);
  try {
    size_t strings_count = ElfParser::count_strings(data, 6);
    f << "\n=== STRINGS (" << strings_count << ") ===\n";
    ElfParser::write_strings(f, data, 6);
  } catch (...) {
    f << "\n=== STRINGS (error) ===\n";
  }

  g_current_step.store("xrefs", std::memory_order_relaxed);
  auto xref_map = ElfParser::build_string_xref_map(data, base);
  if (!xref_map.empty()) {
    f << "\n=== STRING_XREFS (" << xref_map.size() << ") ===\n";
    for (const auto &kv : xref_map) {
      uint64_t addr = base ? base + kv.first : kv.first;
      f << "0x" << std::hex << addr << std::dec << " refs=" << kv.second.size()
        << "\n";
      for (auto ref : kv.second) {
        uint64_t raddr = base ? base + ref : ref;
        f << "  0x" << std::hex << raddr << std::dec << "\n";
      }
    }
  }

  g_current_step.store("security", std::memory_order_relaxed);
  bool relro = ElfParser::has_relro(data);
  bool full_relro = ElfParser::has_full_relro(data);
  f << "\n=== SECURITY ===\n";
  f << "RELRO: " << (relro ? "yes" : "no") << "\n";
  f << "FULL_RELRO: " << (full_relro ? "yes" : "no") << "\n";

  g_current_step.store("init_fini", std::memory_order_relaxed);
  auto init_funcs = ElfParser::get_init_array(data);
  auto fini_funcs = ElfParser::get_fini_array(data);
  auto to_runtime_addr = [&](uint64_t v) -> uint64_t {
    if (base == 0)
      return v;
    // Values coming from dumped runtime may already be absolute addresses.
    if (v >= base && v < base + data.size() + 0x1000)
      return v;
    // Static ELF values are typically relative to module base.
    if (v < data.size())
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
  for (auto fn : init_runtime) {
    f << "0x" << std::hex << fn << std::dec << "\n";
  }
  f << "\n=== FINI_ARRAY (" << fini_funcs.size() << ") ===\n";
  for (auto fn : fini_runtime) {
    f << "0x" << std::hex << fn << std::dec << "\n";
  }

  g_current_step.store("trace_init", std::memory_order_relaxed);
  bool already_traced = module_state && module_state->init_traced;
  if (pid > 0 && !init_runtime.empty() && !already_traced) {
    std::unique_lock<std::mutex> runtime_lock;
    if (runtime_mutex)
      runtime_lock = std::unique_lock<std::mutex>(*runtime_mutex);
    try {
      bool traced = RuntimeAnalyzer::trace_init_array(pid, base, init_runtime);
      f << "\n=== INIT_ARRAY_TRACE ===\n";
      if (traced) {
        f << "Traced " << init_runtime.size()
          << " init functions (memory effects logged)\n";
      } else {
        f << "Trace attempt completed with no captured breakpoints\n";
      }
    } catch (...) {
      f << "\n=== INIT_ARRAY_TRACE ===\n";
      f << "Trace failed with runtime exception\n";
    }
    if (module_state)
      module_state->init_traced = true;
  } else if (pid > 0 && !init_runtime.empty() && already_traced) {
    f << "\n=== INIT_ARRAY_TRACE ===\n";
    f << "Skipped (already traced earlier for this module)\n";
  }

  g_current_step.store("entropy", std::memory_order_relaxed);
  auto entropy = ElfParser::find_high_entropy_regions(data);
  if (!entropy.empty()) {
    f << "\n=== HIGH_ENTROPY (" << entropy.size() << ") ===\n";
    for (const auto &e : entropy) {
      uint64_t addr = base ? base + e.offset : e.offset;
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

  g_current_step.store("deobf_scan", std::memory_order_relaxed);
  auto enc_strings = ElfParser::find_encrypted_strings(data);
  if (!enc_strings.empty()) {
    ensure_deobf_header();
    f << "[ENCRYPTED_STRINGS] count=" << enc_strings.size() << "\n";
    for (const auto &s : enc_strings)
      f << "  " << s << "\n";
  }

  g_current_step.store("decrypt", std::memory_order_relaxed);
  std::vector<DecryptResult> decrypted = ElfParser::auto_decrypt_strings(data);
  std::set<std::pair<uint64_t, std::string>> dec_seen;

  auto add_decrypted = [&](const std::vector<DecryptResult> &extra) {
    for (const auto &r : extra) {
      std::pair<uint64_t, std::string> key = {r.offset, r.method};
      if (dec_seen.insert(key).second)
        decrypted.push_back(r);
    }
  };

  auto dump_diff = [&](const std::vector<uint8_t> &other,
                       const std::string &title) {
    std::vector<std::pair<size_t, size_t>> diff_regions;
    size_t n = std::min(other.size(), data.size());
    size_t start = 0;
    bool in_diff = false;
    for (size_t i = 0; i < n; i++) {
      bool differs = data[i] != other[i] && other[i] != 0;
      if (differs && !in_diff) {
        start = i;
        in_diff = true;
      } else if (!differs && in_diff) {
        if (i - start >= 16)
          diff_regions.push_back({start, i - start});
        in_diff = false;
      }
    }
    if (in_diff && n - start >= 16)
      diff_regions.push_back({start, n - start});

    if (!diff_regions.empty()) {
      ensure_deobf_header();
      f << "[" << title << "] count=" << diff_regions.size() << "\n";
      for (const auto &r : diff_regions) {
        uint64_t addr = base ? base + r.first : r.first;
        f << "  0x" << std::hex << addr << std::dec << " (" << r.second
          << ")\n";
        size_t span = std::min(r.second, (size_t)1024);
        auto extra = ElfParser::try_decrypt(data, r.first, span);
        if (!extra.empty())
          add_decrypted(extra);
      }
    }
  };

  std::vector<uint8_t> disk_data;
  if (read_file_prefix(name, data.size(), disk_data))
    dump_diff(disk_data, "RUNTIME_DIFF_DISK");
  if (prev_data && !prev_data->empty())
    dump_diff(*prev_data, "RUNTIME_DIFF_PREV");

  if (!entropy.empty()) {
    for (const auto &e : entropy) {
      if (!e.likely_encrypted)
        continue;
      size_t span = std::min(e.size, (size_t)1024);
      auto extra = ElfParser::try_decrypt(data, e.offset, span);
      if (!extra.empty())
        add_decrypted(extra);
    }
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
    for (const auto &r : decrypted) {
      uint64_t addr = base ? base + r.offset : r.offset;
      f << "  0x" << std::hex << addr << std::dec << " " << r.method;
      if (r.key_size)
        f << " keylen=" << r.key_size;
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

  g_current_step.store("crypto_scan", std::memory_order_relaxed);
  auto aes_keys = ElfParser::detect_aes_keys(data);
  if (!aes_keys.empty()) {
    ensure_crypto_header();
    f << "[AES_KEYS] count=" << aes_keys.size() << "\n";
    for (const auto &k : aes_keys) {
      uint64_t addr = base ? base + k.offset : k.offset;
      f << "  0x" << std::hex << addr << std::dec << " size=" << k.key_size
        << " conf=" << std::fixed << std::setprecision(2) << k.confidence << " "
        << k.detection_method << "\n";
      f << "    " << hex_bytes(k.key, k.key_size) << "\n";
    }
  }

  g_current_step.store("plt", std::memory_order_relaxed);
  try {
    auto plt = ElfParser::get_plt_entries(data);
    if (!plt.empty()) {
      f << "\n=== PLT (" << plt.size() << ") ===\n";
      for (const auto &e : plt) {
        uint64_t addr = base ? base + e.offset : e.offset;
        f << "0x" << std::hex << addr << std::dec;
        if (!e.symbol_name.empty())
          f << " " << ElfParser::demangle_symbol(e.symbol_name);
        f << "\n";
      }
    }
  } catch (...) {
  }

  g_current_step.store("got_dump", std::memory_order_relaxed);
  if (pid > 0) {
    std::unique_lock<std::mutex> runtime_lock;
    if (runtime_mutex)
      runtime_lock = std::unique_lock<std::mutex>(*runtime_mutex);
    try {
      auto got_entries = MemoryInjector::dump_got(pid, base, data);
      if (!got_entries.empty()) {
        f << "\n=== GOT (" << got_entries.size() << ") ===\n";
        for (const auto &e : got_entries) {
          f << "0x" << std::hex << e.second << std::dec;
          if (!e.first.empty())
            f << " " << ElfParser::demangle_symbol(e.first);
          f << "\n";
        }
      }
    } catch (...) {
    }
  }

  g_current_step.store("signatures", std::memory_order_relaxed);
  try {
    auto &sig_src = func_syms.empty() ? symbols : func_syms;
    size_t sig_count = std::min(sig_src.size(), (size_t)200);
    if (sig_count > 0) {
      f << "\n=== SIGNATURES (" << sig_count << ") ===\n";
      for (size_t i = 0; i < sig_count; i++) {
        const auto &s = sig_src[i];
        if (s.offset > 0 && s.offset + 32 < data.size()) {
          std::string sig = ElfParser::generate_signature(data, s.offset, 32);
          if (!sig.empty()) {
            uint64_t addr = base ? base + s.offset : s.offset;
            f << "0x" << std::hex << addr << std::dec << " "
              << ElfParser::demangle_symbol(s.name) << "\n  " << sig << "\n";
          }
        }
      }
    }
  } catch (...) {
  }

  g_current_step.store("enc_key", std::memory_order_relaxed);
  try {
    auto enc_key = ElfParser::find_encryption_key(data);
    if (!enc_key.empty()) {
      ensure_crypto_header();
      f << "[ENCRYPTION_KEY] size=" << enc_key.size() << " bytes\n";
      f << "  " << hex_bytes(enc_key.data(), enc_key.size()) << "\n";
    }
  } catch (...) {
  }

  g_current_step.store("crypto_scan", std::memory_order_relaxed);
  try {
    auto crypto_keys = CryptoAnalyzer::scan_for_keys(data, base);
    if (!crypto_keys.empty()) {
      ensure_crypto_header();
      f << "[CRYPTO_KEYS] count=" << crypto_keys.size() << "\n";
      for (const auto &k : crypto_keys) {
        f << "  0x" << std::hex << k.key_addr << std::dec << " " << k.algorithm
          << " conf=" << std::fixed << std::setprecision(2) << k.confidence
          << " " << k.source << "\n";
        if (!k.key_data.empty())
          f << "    " << hex_bytes(k.key_data.data(), k.key_data.size())
            << "\n";
      }
    }
  } catch (...) {
  }

  g_current_step.store("runtime_diff", std::memory_order_relaxed);
  if (pid > 0) {
    std::unique_lock<std::mutex> runtime_lock;
    if (runtime_mutex)
      runtime_lock = std::unique_lock<std::mutex>(*runtime_mutex);
    try {
      std::vector<uint8_t> disk_copy;
      if (read_file_prefix(name, data.size(), disk_copy) &&
          !disk_copy.empty()) {
        auto regions =
            RuntimeAnalyzer::find_decrypted_regions(pid, base, disk_copy);
        if (!regions.empty()) {
          ensure_deobf_header();
          f << "[RUNTIME_DECRYPTED] count=" << regions.size() << "\n";
          for (const auto &r : regions) {
            f << "  0x" << std::hex << r.first << std::dec << " (" << r.second
              << " bytes)\n";
          }
        }
      }
    } catch (...) {
    }
  }

  g_current_step.store("vtable_instances", std::memory_order_relaxed);
  if (pid > 0 && !vtables.empty()) {
    std::unique_lock<std::mutex> runtime_lock;
    if (runtime_mutex)
      runtime_lock = std::unique_lock<std::mutex>(*runtime_mutex);
    try {
      size_t vt_scan = std::min(vtables.size(), (size_t)10);
      std::vector<std::pair<uint64_t, std::vector<uint64_t>>> instances;
      for (size_t i = 0; i < vt_scan; i++) {
        uint64_t vt_addr = base ? base + vtables[i].offset : vtables[i].offset;
        auto found = RuntimeAnalyzer::find_instances_by_vtable(pid, vt_addr);
        if (!found.empty())
          instances.push_back({vt_addr, found});
      }
      if (!instances.empty()) {
        f << "\n=== VTABLE_INSTANCES ===\n";
        for (const auto &kv : instances) {
          f << "VT 0x" << std::hex << kv.first << std::dec
            << " instances=" << kv.second.size() << "\n";
          for (auto a : kv.second)
            f << "  0x" << std::hex << a << std::dec << "\n";
        }
      }
    } catch (...) {
    }
  }

  f.close();
}

void hook_signal_handler(int) { g_hook_running = false; }

void cmd_hook(const std::string &pkg, const std::string &func_name,
              ArchMode arch, int inst_count) {
  ProcessTracer::set_arch(arch);

  std::string out_dir = "/data/local/tmp/" + pkg + "_analysis";
  mkdir_p(out_dir);
  std::string log_path = out_dir + "/hook_" + func_name + ".txt";
  std::ofstream log(log_path);

  auto emit = [&](const std::string &msg) {
    std::cout << msg;
    if (log)
      log << msg;
  };

  emit("\n=== HAYABUSA FUNCTION HOOK ===\n");
  emit("Target: " + pkg + "\n");
  emit("Function: " + func_name + "\n");
  emit("Instructions: " + std::to_string(inst_count) + "\n\n");

  emit("[1] Waiting for process...\n");
  std::cout.flush();
  int pid = -1;
  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    if (!pids.empty()) {
      pid = pids[0];
      break;
    }
    usleep(100000);
  }
  emit("[2] Found PID: " + std::to_string(pid) + "\n");

  emit("[3] Attaching...\n");
  if (!ProcessTracer::attach(pid)) {
    emit("[!] Failed to attach to " + std::to_string(pid) + "\n");
    return;
  }

  emit("[4] Bypassing seccomp...\n");
  SeccompBypass::disable_seccomp(pid);

  emit("[5] Searching for function '" + func_name + "'...\n");
  auto ranges = ProcessTracer::get_library_ranges(pid);
  uint64_t func_addr = 0;
  std::string found_lib;

  for (const auto &r : ranges) {
    if (r.name.empty() || r.name.find(".so") == std::string::npos)
      continue;
    std::string lib = r.name;
    size_t slash = lib.rfind('/');
    if (slash != std::string::npos)
      lib = lib.substr(slash + 1);
    size_t dot = lib.find(".so");
    if (dot == std::string::npos)
      continue;

    uint64_t a = FunctionHooker::find_remote_symbol(pid, lib, func_name);
    if (a != 0) {
      func_addr = a;
      found_lib = r.name;
      break;
    }
  }

  if (func_addr == 0) {
    emit("[!] Function '" + func_name + "' not found\n");
    ProcessTracer::detach(pid);
    return;
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
      for (size_t i = 0; i < count; i++) {
        uint32_t raw;
        memcpy(&raw, code_buf.data() + i * inst_size, 4);
        uint64_t addr = func_addr + i * inst_size;
        auto decoded = InstructionDecoder::decode(raw, addr, arch);
        ss << "    0x" << std::hex << addr << ": ";
        ss << hex_bytes(code_buf.data() + i * inst_size, 4) << " ";
        if (decoded.is_return)
          ss << "RET";
        else if (decoded.is_call)
          ss << "BL 0x" << decoded.target_address;
        else if (decoded.type == InstructionType::Branch)
          ss << "B 0x" << decoded.target_address;
        else if (decoded.type == InstructionType::Adrp)
          ss << "ADRP x" << std::dec << (int)decoded.rd << ", #0x" << std::hex
             << decoded.immediate;
        else if (decoded.type == InstructionType::Load)
          ss << "LDR";
        else if (decoded.type == InstructionType::Store)
          ss << "STR";
        else if (decoded.type == InstructionType::Add)
          ss << "ADD";
        else
          ss << "???";
        ss << std::dec << "\n";
      }
      emit(ss.str());
    }
  }

  uint32_t original_bytes = 0;
  ProcessTracer::read_memory(pid, func_addr, &original_bytes, 4);
  {
    std::ostringstream ss;
    ss << "    Original bytes: " << hex_bytes((uint8_t *)&original_bytes, 4)
       << "\n";
    emit(ss.str());
  }

  uint32_t ret_inst = (arch == ArchMode::ARM64) ? 0xD65F03C0 : 0xE12FFF1E;
  if (!ProcessTracer::write_memory(pid, func_addr, &ret_inst, 4)) {
    emit("[!] Failed to write hook\n");
    ProcessTracer::detach(pid);
    return;
  }

  emit("[6] Function hooked (NOP'd with RET)\n");

  // Auto-hook all crypto functions
  emit("[7] Scanning for crypto functions...\n");
  {
    uint64_t orig_enc = 0, orig_dec = 0;
    bool enc_ok = CryptoAnalyzer::hook_aes_encrypt(pid, &orig_enc);
    bool dec_ok = CryptoAnalyzer::hook_aes_decrypt(pid, &orig_dec);
    if (enc_ok) {
      std::ostringstream ss;
      ss << "    [+] AES encrypt hooked (orig=0x" << std::hex << orig_enc
         << std::dec << ")\n";
      emit(ss.str());
    }
    if (dec_ok) {
      std::ostringstream ss;
      ss << "    [+] AES decrypt hooked (orig=0x" << std::hex << orig_dec
         << std::dec << ")\n";
      emit(ss.str());
    }
    if (!enc_ok && !dec_ok)
      emit("    [!] No crypto functions found to hook\n");
  }

  emit("    Press Ctrl+C to unhook and exit\n");
  std::cout.flush();

  g_hook_running = true;
  struct sigaction sa = {};
  sa.sa_handler = hook_signal_handler;
  sigaction(SIGINT, &sa, nullptr);

  ProcessTracer::detach(pid);

  while (g_hook_running)
    usleep(500000);

  emit("\n[8] Restoring original function...\n");
  if (ProcessTracer::attach(pid)) {
    ProcessTracer::write_memory(pid, func_addr, &original_bytes, 4);
    size_t restored_crypto = CryptoAnalyzer::restore_aes_hooks(pid);
    ProcessTracer::detach(pid);
    emit("    Restored\n");
    if (restored_crypto > 0) {
      emit("    Restored " + std::to_string(restored_crypto) +
           " AES hook(s)\n");
    }
  } else {
    emit("    [!] Could not re-attach to restore (process may have exited)\n");
  }

  emit("=== DONE ===\n");
  if (log) {
    log.close();
    std::cout << "Log saved: " << log_path << "\n";
  }
}

void cmd_inject(const std::string &pkg, const std::string &so_path,
                ArchMode arch) {
  ProcessTracer::set_arch(arch);
  std::cout << "\n=== HAYABUSA LIBRARY INJECTION ===\n";
  std::cout << "Target: " << pkg << "\n";
  std::cout << "Library: " << so_path << "\n\n";

  std::cout << "[1] Waiting for process...\n";
  std::cout.flush();
  int pid = -1;
  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    if (!pids.empty()) {
      pid = pids[0];
      break;
    }
    usleep(100000);
  }
  std::cout << "[2] Found PID: " << pid << "\n";

  std::cout << "[3] Attaching...\n";
  if (!ProcessTracer::attach(pid)) {
    std::cout << "[!] Failed to attach to " << pid << "\n";
    return;
  }

  std::cout << "[4] Bypassing seccomp...\n";
  SeccompBypass::disable_seccomp(pid);

  std::cout << "[5] Injecting library...\n";
  bool ok = FunctionHooker::inject_library(pid, so_path);

  if (ok) {
    std::cout << "    [+] Library injected successfully\n";
  } else {
    std::cout << "    [!] Injection failed\n";
    std::string err = MemoryInjector::remote_dlerror(pid);
    if (!err.empty())
      std::cout << "    dlerror: " << err << "\n";
  }

  ProcessTracer::detach(pid);
  std::cout << "=== DONE ===\n";
}

void cmd_scan(const std::string &pkg, const std::string &pattern,
              ArchMode arch) {
  ProcessTracer::set_arch(arch);
  std::cout << "\n=== HAYABUSA PATTERN SCAN ===\n";
  std::cout << "Target: " << pkg << "\n";
  std::cout << "Pattern: " << pattern << "\n\n";

  std::cout << "[1] Waiting for process...\n";
  std::cout.flush();
  int pid = -1;
  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    if (!pids.empty()) {
      pid = pids[0];
      break;
    }
    usleep(100000);
  }
  std::cout << "[2] Found PID: " << pid << "\n";

  auto ranges = ProcessTracer::get_library_ranges(pid);
  int total_matches = 0;

  for (const auto &r : ranges) {
    if (r.name.empty() || r.name.find(".so") == std::string::npos)
      continue;

    size_t lib_size = r.end - r.start;
    if (lib_size > 64 * 1024 * 1024)
      continue;

    std::vector<uint8_t> mem(lib_size);
    int mem_fd =
        open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
    if (mem_fd < 0)
      continue;
    bool ok = read_exact(mem_fd, mem.data(), lib_size, r.start);
    close(mem_fd);
    if (!ok || !ElfParser::is_elf(mem))
      continue;

    auto matches = ElfParser::pattern_scan(mem, pattern);
    if (!matches.empty()) {
      std::string lib = r.name;
      size_t slash = lib.rfind('/');
      if (slash != std::string::npos)
        lib = lib.substr(slash + 1);
      std::cout << "\n  [" << lib << "] " << matches.size() << " match(es):\n";
      for (const auto &m : matches) {
        uint64_t addr = r.start + m.offset;
        std::cout << "    0x" << std::hex << addr << std::dec << " offset=0x"
                  << std::hex << m.offset << std::dec << "\n";
        total_matches++;
      }
    }
  }

  if (total_matches == 0)
    std::cout << "[!] No matches found\n";
  else
    std::cout << "\nTotal: " << total_matches << " match(es)\n";

  std::cout << "=== DONE ===\n";
}

void cmd_extract(const std::string &pkg, const std::string &func_name,
                 ArchMode arch, int max_depth) {
  ProcessTracer::set_arch(arch);
  std::cout << "\n=== HAYABUSA FUNCTION EXTRACT ===\n";
  std::cout << "Target: " << pkg << "\n";
  std::cout << "Function: " << func_name << "\n";
  std::cout << "Max depth: " << max_depth << "\n\n";

  std::cout << "[1] Waiting for process...\n";
  std::cout.flush();
  int pid = -1;
  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    if (!pids.empty()) {
      pid = pids[0];
      break;
    }
    usleep(100000);
  }
  std::cout << "[2] Found PID: " << pid << "\n";

  std::cout << "[3] Attaching...\n";
  if (!ProcessTracer::attach(pid)) {
    std::cout << "[!] Failed to attach to " << pid << "\n";
    return;
  }

  std::cout << "[4] Bypassing seccomp...\n";
  SeccompBypass::disable_seccomp(pid);

  std::cout << "[5] Searching for function '" << func_name << "'...\n";
  auto ranges = ProcessTracer::get_library_ranges(pid);
  uint64_t func_addr = 0;
  std::string found_lib;

  for (const auto &r : ranges) {
    if (r.name.empty() || r.name.find(".so") == std::string::npos)
      continue;
    std::string lib = r.name;
    size_t slash = lib.rfind('/');
    if (slash != std::string::npos)
      lib = lib.substr(slash + 1);
    size_t dot = lib.find(".so");
    if (dot == std::string::npos)
      continue;

    uint64_t a = FunctionHooker::find_remote_symbol(pid, lib, func_name);
    if (a != 0) {
      func_addr = a;
      found_lib = r.name;
      break;
    }
  }

  if (func_addr == 0) {
    std::cout << "[!] Function '" << func_name << "' not found\n";
    ProcessTracer::detach(pid);
    return;
  }

  std::cout << "    Found at 0x" << std::hex << func_addr << std::dec << " in "
            << found_lib << "\n";

  std::cout << "[6] Extracting function with dependencies (depth=" << max_depth
            << ")...\n";
  auto result =
      StaticRelinkerEx::extract_function_with_deps(pid, func_addr, max_depth);

  if (result.empty()) {
    std::cout << "[!] Extraction failed\n";
    ProcessTracer::detach(pid);
    return;
  }

  std::string out_dir = "/data/local/tmp/hayabusa_extract";
  mkdir_p(out_dir);
  std::string out_path = out_dir + "/" + func_name + ".bin";
  std::ofstream out(out_path, std::ios::binary);
  out.write(reinterpret_cast<const char *>(result.data()), result.size());
  out.close();

  std::cout << "    [+] Extracted " << result.size() << " bytes to " << out_path
            << "\n";

  ProcessTracer::detach(pid);
  std::cout << "=== DONE ===\n";
}

struct Region {
  uint64_t start, end;
  uint64_t offset;
  std::string perms, name;
};

struct Candidate {
  uint64_t base;
  std::string name;
  std::string display_name;
  std::string safe_name;
};

std::string make_display_name(const std::string &name) {
  if (name.find('/') != std::string::npos)
    return name.substr(name.rfind('/') + 1);
  return name;
}

std::string make_safe_name(const std::string &name) {
  std::string safe = name;
  std::replace(safe.begin(), safe.end(), '/', '_');
  std::replace(safe.begin(), safe.end(), '@', '_');
  std::replace(safe.begin(), safe.end(), ':', '_');
  std::replace(safe.begin(), safe.end(), ' ', '_');
  return safe;
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
  std::string safe_ext = make_safe_name(ext);
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

std::vector<Region> get_regions(int pid) {
  std::vector<Region> r;
  std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(f, line)) {
    unsigned long s, e;
    unsigned long o = 0;
    char p[5] = {0}, n[512] = {0};
    int parsed = sscanf(line.c_str(), "%lx-%lx %4s %lx %*s %*d %511[^\n]", &s,
                        &e, p, &o, n);
    if (parsed >= 4) {
      Region x;
      x.start = s;
      x.end = e;
      x.offset = o;
      x.perms = p;
      x.name = n;
      while (!x.name.empty() && x.name[0] == ' ')
        x.name = x.name.substr(1);
      r.push_back(x);
    }
  }
  return r;
}

int dump_analysis(int pid, const std::string &out,
                  std::map<std::string, uint64_t> &raw_hash_by_key,
                  const std::vector<std::string> &priority_files,
                  const RelinkConfig *relink_cfg, size_t thread_count) {
  auto regions = get_regions(pid);

  int mem_fd =
      open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
  if (mem_fd < 0) {
    std::cout << "    [!] Failed to open /proc/" << pid << "/mem\n";
    return 0;
  }
  std::string raw_dir = out + "/raw";
  mkdir_p(raw_dir);

  // Handle RAW dump for priority files that are NOT ELFs (like
  // global-metadata.dat)
  for (const auto &p_file : priority_files) {
    bool found_mapping = false;
    bool dumped_raw = false;
    bool saw_elf = false;
    bool unchanged_raw = false;

    for (const auto &r : regions) {
      if (r.perms.find('r') == std::string::npos)
        continue;
      if (r.name.find(p_file) != std::string::npos) {
        found_mapping = true;
        // Only treat as non-ELF if magic check fails
        unsigned char magic[4] = {0};
        ssize_t magic_rd = pread(mem_fd, magic, sizeof(magic), r.start);
        if (magic_rd != (ssize_t)sizeof(magic))
          continue;
        if (magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' ||
            magic[3] != 'F') {
          size_t size = r.end - r.start;
          if (size > 0 && size < 512 * 1024 * 1024) { // 512MB limit for RAW
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
              raw_hash_by_key[raw_key] = raw_hash;

              std::string dump_path =
                  make_raw_dump_path(raw_dir, p_file, r.start, r.offset, true);

              std::ofstream fout(dump_path, std::ios::binary);
              fout.write(reinterpret_cast<const char *>(data.data()),
                         data.size());
              fout.close();
              std::cout << "    [PRIORITY] " << p_file << " ("
                        << Utils::format_size(size) << ") (RAW dump) -> "
                        << dump_path << "\n";
              std::cout.flush();
              dumped_raw = true;
            }
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

  std::set<uint64_t> seen_local;
  std::set<std::string> seen_priority_display;

  for (const auto &r : regions) {
    if (r.offset != 0)
      continue;
    if (r.perms.find('r') == std::string::npos)
      continue;
    if (seen_local.count(r.start))
      continue;

    std::string name = r.name;
    if (name.find(" (deleted)") != std::string::npos)
      name = name.substr(0, name.find(" (deleted)"));

    bool is_priority_elf = false;
    for (const auto &p : priority_files) {
      if (name.find(p) != std::string::npos) {
        is_priority_elf = true;
        break;
      }
    }
    std::string display_name = make_display_name(name);
    if (is_priority_elf) {
      if (seen_priority_display.count(display_name))
        continue;
      seen_priority_display.insert(display_name);
    }

    if (name.empty() || (!is_shared_object_name(name) && !is_priority_elf))
      continue;

    unsigned char magic[4] = {0};
    ssize_t rd = pread(mem_fd, magic, sizeof(magic), r.start);
    if (rd != (ssize_t)sizeof(magic) || magic[0] != 0x7f || magic[1] != 'E' ||
        magic[2] != 'L' || magic[3] != 'F') {
      continue;
    }

    Candidate c;
    c.base = r.start;
    c.name = name;
    c.display_name = display_name;
    c.safe_name = make_safe_name(name);
    candidates.push_back(c);
    seen_local.insert(r.start);
  }

  if (candidates.empty()) {
    close(mem_fd);
    return 0;
  }

  // If priority mode, sort candidates by their order in priority_files
  if (!priority_files.empty()) {
    std::stable_sort(
        candidates.begin(), candidates.end(),
        [&](const Candidate &a, const Candidate &b) {
          int idx_a = -1, idx_b = -1;
          for (size_t i = 0; i < priority_files.size(); ++i) {
            if (a.name.find(priority_files[i]) != std::string::npos) {
              idx_a = (int)i;
              break;
            }
          }
          for (size_t i = 0; i < priority_files.size(); ++i) {
            if (b.name.find(priority_files[i]) != std::string::npos) {
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
  if (thread_count == 0)
    thread_count = 1;
  thread_count = std::min(thread_count, total);
  if (thread_count == 0)
    thread_count = 1;
  const size_t bar_width = 20;
  std::cout << "    [Scan 1] Found " << candidates.size()
            << " ELF modules in mappings\n";
  std::cout << "    [i] Worker threads: " << thread_count << "\n";
  std::cout.flush();

  std::mutex print_mu;
  std::mutex hash_mu;
  std::mutex runtime_mu;
  std::map<std::string, std::set<uint64_t>> seen_hashes_by_name;
  std::atomic<size_t> next_index{0};
  std::atomic<size_t> progress_done{0};
  std::atomic<int> dumped_count{0};

  auto is_priority_name = [&](const std::string &name) -> bool {
    for (const auto &p : priority_files) {
      if (name.find(p) != std::string::npos)
        return true;
    }
    return false;
  };

  auto worker = [&]() {
    std::vector<uint8_t> data;
    for (;;) {
      size_t i = next_index.fetch_add(1);
      if (i >= candidates.size())
        break;
      const Candidate c = candidates[i];

      uint64_t image_size = 0;
      try {
        if (!read_elf_image(mem_fd, c.base, data, image_size))
          continue;
      } catch (...) {
        continue;
      }

      // Always keep untouched bytes for offline inspection.
      {
        std::string raw_path =
            make_raw_dump_path(raw_dir, c.name, c.base, 0, false);
        std::ofstream raw_file(raw_path, std::ios::binary);
        if (raw_file) {
          raw_file.write(reinterpret_cast<const char *>(data.data()),
                         data.size());
        }
      }

      try {
        std::vector<uint8_t> fixed = SoFixer::repair(data, c.base);
        if (!fixed.empty() && ElfParser::is_elf(fixed) && !is_garbage(fixed)) {
          data.swap(fixed);
        }
      } catch (...) {
      }
      const std::vector<uint8_t> &analysis_data = data;
      if (analysis_data.empty() || is_garbage(analysis_data) ||
          !ElfParser::is_elf(analysis_data)) {
        continue;
      }

      uint64_t h = hash_data(analysis_data);
      {
        std::lock_guard<std::mutex> lk(hash_mu);
        auto &seen_hashes = seen_hashes_by_name[c.display_name];
        if (seen_hashes.count(h))
          continue;
        seen_hashes.insert(h);
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
           << "_s0.txt";
      std::string analysis_txt_path = path.str();
      ModuleState module_state;
      analyze_to_txt(analysis_data, analysis_txt_path, c.base, c.name, nullptr,
                     pid, &module_state, &runtime_mu);

      if (relink_cfg) {
        try {
          auto relinked = StaticRelinkerEx::relink_full(analysis_data, pid,
                                                        c.base, *relink_cfg);
          if (!relinked.empty()) {
            std::ofstream tfile(analysis_txt_path, std::ios::app);
            if (tfile) {
              size_t preview_len = std::min<size_t>(relinked.size(), 512);
              tfile << "\n=== RELINK ===\n";
              tfile << "size=" << relinked.size() << " bytes\n";
              tfile << "hash=0x" << std::hex << hash_data(relinked) << std::dec
                    << "\n";
              if (preview_len > 0) {
                tfile << "preview[" << preview_len
                      << "]=" << hex_bytes(relinked.data(), preview_len)
                      << "\n";
              }
            }
            std::lock_guard<std::mutex> lk(print_mu);
            std::cout << "    [RELINK] " << c.display_name
                      << " embedded in txt ("
                      << Utils::format_size(relinked.size()) << ")\n";
            std::cout.flush();
          }
        } catch (...) {
          std::lock_guard<std::mutex> lk(print_mu);
          std::cout << "    [RELINK] Failed for " << c.display_name << "\n";
          std::cout.flush();
        }
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

  close(mem_fd);
  int count = dumped_count.load();
  if (count > 0)
    std::cout << "    Dumped " << count << " modules\n";
  return count;
}

void cmd_dump(const std::string &pkg, ArchMode arch, int timeout_sec,
              const std::vector<std::string> &priority_files,
              const RelinkConfig *relink_cfg, size_t thread_count) {
  ProcessTracer::set_arch(arch);

  std::cout << "\n=== HAYABUSA DUMPER ===\n";
  std::cout << "Target: " << pkg << "\n";
  if (!priority_files.empty()) {
    std::cout << "Priority list: ";
    for (size_t i = 0; i < priority_files.size(); i++) {
      std::cout << priority_files[i]
                << (i == priority_files.size() - 1 ? "" : ", ");
    }
    std::cout << "\n";
  }
  std::cout << "Threads: " << thread_count << "\n";
  std::cout << "\n";

  std::cout << "[1] Waiting for process (launch app)...\n";
  if (timeout_sec == 0) {
    std::cout << "    [i] No timeout set; waiting until first matching process "
                 "is captured.\n";
  }
  std::cout.flush();

  std::string out = "/data/local/tmp/" + pkg + "_analysis";
  mkdir_p(out);

  std::map<int, std::map<std::string, uint64_t>> raw_state_by_pid;
  std::set<int> dumped_pids;
  time_t start_time = time(nullptr);

  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    for (int pid : pids) {
      if (dumped_pids.count(pid))
        continue;
      std::cout << "\n[2] Captured PID: " << pid << "\n";
      std::cout << "\n[3] Dumping...\n";
      std::cout.flush();
      g_pid = pid;
      std::string out_pid = out + "/pid_" + std::to_string(pid);
      mkdir_p(out_pid);
      dump_analysis(pid, out_pid, raw_state_by_pid[pid], priority_files,
                    relink_cfg, thread_count);
      g_pid = -1;
      dumped_pids.insert(pid);
    }
    if (!dumped_pids.empty())
      break;
    if (timeout_sec > 0) {
      if (time(nullptr) - start_time >= timeout_sec)
        break;
    }
    usleep(200000);
  }

  std::cout << "\n=== COMPLETE ===\n";
  std::cout << "Output: " << out << "/\n";
}

int main(int argc, char *argv[]) {
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);
  signal(SIGSEGV, signal_handler);
  signal(SIGBUS, signal_handler);
  signal(SIGABRT, signal_handler);
  atexit(cleanup);

  if (argc < 3) {
    std::cout << USAGE;
    return 1;
  }

  std::string cmd = argv[1];
  std::string pkg = argv[2];

  ArchMode arch = ArchMode::ARM64;
  bool have_mode = false;
  int timeout_sec = 0;
  std::string extra_arg;

  if (cmd == "hook" || cmd == "inject" || cmd == "scan" || cmd == "extract") {
    int inst_count = 10;
    int max_depth = 8;
    if (argc < 4) {
      std::cout << USAGE;
      return 1;
    }
    extra_arg = argv[3];
    for (int i = 4; i < argc; i++) {
      std::string arg = argv[i];
      if (arg == "--mode" && i + 1 < argc) {
        std::string mode_value = argv[++i];
        if (mode_value == "arm32")
          arch = ArchMode::ARM32;
        else if (mode_value == "arm64")
          arch = ArchMode::ARM64;
        else {
          std::cout << USAGE;
          return 1;
        }
        have_mode = true;
      } else if (arg == "--i" && i + 1 < argc && cmd == "hook") {
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
      } else {
        std::cout << USAGE;
        return 1;
      }
    }
    if (!have_mode) {
      std::cout << USAGE;
      return 1;
    }
    if (cmd == "hook")
      cmd_hook(pkg, extra_arg, arch, inst_count);
    else if (cmd == "inject")
      cmd_inject(pkg, extra_arg, arch);
    else if (cmd == "scan")
      cmd_scan(pkg, extra_arg, arch);
    else if (cmd == "extract")
      cmd_extract(pkg, extra_arg, arch, max_depth);
  } else if (cmd == "dump") {
    std::vector<std::string> priority_files;
    RelinkConfig relink_cfg = make_default_relink_config();
    size_t thread_count = std::thread::hardware_concurrency();
    if (thread_count == 0)
      thread_count = 4;
    if (thread_count > 16)
      thread_count = 16;
    for (int i = 3; i < argc; i++) {
      std::string arg = argv[i];
      if (arg == "--mode" && i + 1 < argc) {
        std::string mode_value = argv[++i];
        if (mode_value == "arm32")
          arch = ArchMode::ARM32;
        else if (mode_value == "arm64")
          arch = ArchMode::ARM64;
        else {
          std::cout << USAGE;
          return 1;
        }
        have_mode = true;
      } else if (arg == "--timeout" && i + 1 < argc) {
        timeout_sec = atoi(argv[++i]);
        if (timeout_sec < 0)
          timeout_sec = 0;
      } else if (arg == "--p" && i + 1 < argc) {
        priority_files = split_string(argv[++i], ',');
      } else if (arg == "--rd" && i + 1 < argc) {
        relink_cfg.max_depth = atoi(argv[++i]);
        if (relink_cfg.max_depth < 1)
          relink_cfg.max_depth = 1;
        if (relink_cfg.max_depth > 32)
          relink_cfg.max_depth = 32;
      } else if (arg == "--threads" && i + 1 < argc) {
        long v = strtol(argv[++i], nullptr, 10);
        if (v < 1)
          v = 1;
        if (v > 64)
          v = 64;
        thread_count = static_cast<size_t>(v);
      } else {
        std::cout << USAGE;
        return 1;
      }
    }
    if (!have_mode) {
      std::cout << USAGE;
      return 1;
    }
    cmd_dump(pkg, arch, timeout_sec, priority_files, &relink_cfg, thread_count);
  } else {
    std::cout << USAGE;
    return 1;
  }

  return 0;
}
