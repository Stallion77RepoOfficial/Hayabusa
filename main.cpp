#include "memory.h"
#include "tracer.h"
#include <algorithm>
#include <ctime>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <sstream>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

int g_pid = -1;
const char *g_current_module = nullptr;
const char *g_current_step = nullptr;

static constexpr const char *USAGE =
    "Usage: hayabusa dump <package> --mode <arm32|arm64> [--timeout <sec>]\n";

void cleanup() { ZygoteTracer::cleanup_all_attached(); }

void signal_handler(int sig) {
  const char *msg = "\n[!] Signal received: ";
  write(STDOUT_FILENO, msg, strlen(msg));
  char buf[16];
  snprintf(buf, sizeof(buf), "%d", sig);
  write(STDOUT_FILENO, buf, strlen(buf));
  if (g_current_module) {
    write(STDOUT_FILENO, " at ", 4);
    write(STDOUT_FILENO, g_current_module, strlen(g_current_module));
  }
  if (g_current_step) {
    write(STDOUT_FILENO, " [", 2);
    write(STDOUT_FILENO, g_current_step, strlen(g_current_step));
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
  if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' ||
      ident[3] != 'F')
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
                    const std::vector<uint8_t> *prev_data) {
  static std::string current_name;
  current_name = name;
  g_current_module = current_name.c_str();

  std::ofstream f(path);
  if (!f)
    return;

  f << "=== ELF MEMORY ANALYSIS ===\n";
  f << "Module: " << name << "\n";
  f << "Base: 0x" << std::hex << base << std::dec << "\n";
  f << "Size: " << data.size() << " bytes\n";

  std::vector<ElfSymbol> vtables;

  g_current_step = "symbols";
  size_t symbol_count = ElfParser::count_symbols(data);
  f << "=== SYMBOLS (" << symbol_count << ") ===\n";
  ElfParser::write_symbols(f, data, &vtables);

  g_current_step = "functions";
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
  } else {
    auto funcs = ElfParser::find_functions_stripped(data, base);
    f << "\n=== FUNCTIONS (" << funcs.size() << ") ===\n";
    for (const auto &fn : funcs) {
      f << "0x" << std::hex << fn.start_addr << "-0x" << fn.end_addr
        << std::dec << " (" << fn.size << ")\n";
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

  g_current_step = "rtti";
  std::sort(vtables.begin(), vtables.end(),
            [](const ElfSymbol &a, const ElfSymbol &b) {
              return a.offset < b.offset;
            });
  if (!vtables.empty()) {
    ElfParser::write_rtti(f, data, base, vtables);
  } else {
    auto stripped = ElfParser::scan_vtables_stripped(data, base);
    f << "\n=== VTABLE/RTTI (" << stripped.size() << ") ===\n";
    for (const auto &info : stripped) {
      f << "VTABLE 0x" << std::hex << info.vtable_addr << std::dec << " "
        << info.demangled_name << "\n";
      if (!info.virtual_functions.empty()) {
        f << "  virtuals (" << info.virtual_functions.size() << "):";
        for (auto fn : info.virtual_functions) {
          f << " 0x" << std::hex << fn;
        }
        f << std::dec << "\n";
      }
    }
  }

  g_current_step = "strings";
  try {
    size_t strings_count = ElfParser::count_strings(data, 6);
    f << "\n=== STRINGS (" << strings_count << ") ===\n";
    ElfParser::write_strings(f, data, 6);
  } catch (...) {
    f << "\n=== STRINGS (error) ===\n";
  }

  g_current_step = "xrefs";
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

  g_current_step = "security";
  bool relro = ElfParser::has_relro(data);
  bool full_relro = ElfParser::has_full_relro(data);
  auto tls = ElfParser::get_tls_range(data);
  f << "\n=== SECURITY ===\n";
  f << "RELRO: " << (relro ? "yes" : "no") << "\n";
  f << "FULL_RELRO: " << (full_relro ? "yes" : "no") << "\n";
  f << "TLS: 0x" << std::hex << tls.first << "-0x" << tls.second << std::dec
    << "\n";

  g_current_step = "init_fini";
  auto init_funcs = ElfParser::get_init_array(data);
  auto fini_funcs = ElfParser::get_fini_array(data);
  f << "\n=== INIT_ARRAY (" << init_funcs.size() << ") ===\n";
  for (auto fn : init_funcs) {
    uint64_t addr = base ? base + fn : fn;
    f << "0x" << std::hex << addr << std::dec << "\n";
  }
  f << "\n=== FINI_ARRAY (" << fini_funcs.size() << ") ===\n";
  for (auto fn : fini_funcs) {
    uint64_t addr = base ? base + fn : fn;
    f << "0x" << std::hex << addr << std::dec << "\n";
  }

  g_current_step = "entropy";
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

  g_current_step = "aes_keys";
  auto aes_keys = ElfParser::detect_aes_keys(data);
  if (!aes_keys.empty()) {
    f << "\n=== AES_KEYS (" << aes_keys.size() << ") ===\n";
    for (const auto &k : aes_keys) {
      uint64_t addr = base ? base + k.offset : k.offset;
      f << "0x" << std::hex << addr << std::dec << " size=" << k.key_size
        << " conf=" << std::fixed << std::setprecision(2) << k.confidence
        << " " << k.detection_method << "\n";
      f << "  " << hex_bytes(k.key, k.key_size) << "\n";
    }
  }

  g_current_step = "encrypted_strings";
  auto enc_strings = ElfParser::find_encrypted_strings(data);
  if (!enc_strings.empty()) {
    f << "\n=== ENCRYPTED_STRINGS (" << enc_strings.size() << ") ===\n";
    for (const auto &s : enc_strings)
      f << s << "\n";
  }

  g_current_step = "decrypt";
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
      f << "\n=== " << title << " (" << diff_regions.size() << ") ===\n";
      for (const auto &r : diff_regions) {
        uint64_t addr = base ? base + r.first : r.first;
        f << "0x" << std::hex << addr << std::dec << " (" << r.second << ")\n";
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
    f << "\n=== DECRYPTED (" << decrypted.size() << ") ===\n";
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
      f << "0x" << std::hex << addr << std::dec << " " << r.method;
      if (r.key_size)
        f << " keylen=" << r.key_size;
      f << "\n";
      std::string text = preview(r.decrypted);
      if (!text.empty())
        f << "  " << text << "\n";
    }
  }
  f.close();
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

struct ModuleState {
  uint64_t hash = 0;
  uint64_t snapshot_id = 0;
  std::vector<uint8_t> prev_data;
  bool has_prev = false;
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
                  std::map<uint64_t, ModuleState> &state_by_base) {
  auto regions = get_regions(pid);

  int mem_fd = open(("/proc/" + std::to_string(pid) + "/mem").c_str(),
                    O_RDONLY);
  if (mem_fd < 0) {
    std::cout << "    [!] Failed to open /proc/" << pid << "/mem\n";
    return 0;
  }

  std::vector<Candidate> candidates;
  candidates.reserve(regions.size());

  std::set<uint64_t> seen_local;

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
    if (name.empty() || !is_shared_object_name(name))
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
    c.display_name = make_display_name(name);
    c.safe_name = make_safe_name(name);
    candidates.push_back(c);
    seen_local.insert(r.start);
  }

  if (candidates.empty()) {
    close(mem_fd);
    return 0;
  }

  std::vector<uint8_t> data;
  int count = 0;
  size_t total = candidates.size();
  const size_t bar_width = 20;
  bool printed = false;

  for (size_t i = 0; i < candidates.size(); i++) {
    const auto &c = candidates[i];

    uint64_t image_size = 0;
    try {
      if (!read_elf_image(mem_fd, c.base, data, image_size)) {
        continue;
      }
    } catch (...) {
      continue;
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

    int percent =
        total == 0 ? 100 : (int)(((i + 1) * 100) / static_cast<int>(total));
    size_t filled = (percent * bar_width) / 100;
    std::string bar(filled, '#');
    bar.append(bar_width - filled, '.');
    ModuleState &st = state_by_base[c.base];
    uint64_t h = hash_data(analysis_data);
    bool changed = !st.has_prev || st.hash != h;
    if (!changed)
      continue;

    if (!printed) {
      std::cout << "    Found " << candidates.size()
                << " ELF .so binaries in mappings\n";
      std::cout.flush();
      printed = true;
    }

    count++;
    std::cout << "    [" << (i + 1) << "/" << total << "] [" << bar << "] "
              << percent << "% " << c.display_name << " ("
              << Utils::format_size(analysis_data.size()) << ")\n";
    std::cout.flush();

    uint64_t snap_id = st.has_prev ? (st.snapshot_id + 1) : 0;
    std::ostringstream path;
    path << out << "/" << c.safe_name << "_0x" << std::hex << c.base << "_s"
         << std::dec << snap_id << ".txt";

    const std::vector<uint8_t> *prev = st.has_prev ? &st.prev_data : nullptr;
    analyze_to_txt(analysis_data, path.str(), c.base, c.name, prev);

    st.prev_data = analysis_data;
    st.hash = h;
    st.snapshot_id = snap_id;
    st.has_prev = true;
  }

  close(mem_fd);

  if (count > 0)
    std::cout << "    Analyzed " << count << " modules\n";
  return count;
}

void cmd_dump(const std::string &pkg, ArchMode arch, int timeout_sec) {
  ProcessTracer::set_arch(arch);

  std::cout << "\n=== HAYABUSA ELF ANALYZER ===\n";
  std::cout << "Target: " << pkg << "\n\n";

  std::cout << "[1] Waiting for process (launch app)...\n";
  std::cout.flush();

  std::string out = "/data/local/tmp/" + pkg + "_analysis";
  mkdir_p(out);

  std::map<int, std::map<uint64_t, ModuleState>> state_by_pid;
  std::set<int> announced;
  bool saw_any = false;
  time_t start_time = time(nullptr);
  time_t last_new = start_time;

  for (;;) {
    auto pids = find_pids_by_prefix_all(pkg);
    if (!pids.empty())
      saw_any = true;
    if (saw_any && pids.empty())
      break;

    for (int pid : pids) {
      if (!announced.count(pid)) {
        std::cout << "\n[2] Captured PID: " << pid << "\n";
        std::cout << "\n[3] Analyzing...\n";
        std::cout.flush();
        announced.insert(pid);
      }
      g_pid = pid;
      std::string out_pid = out + "/pid_" + std::to_string(pid);
      mkdir_p(out_pid);
      int found = dump_analysis(pid, out_pid, state_by_pid[pid]);
      if (found > 0)
        last_new = time(nullptr);
      g_pid = -1;
    }
    if (timeout_sec > 0) {
      time_t now = time(nullptr);
      if (now - last_new >= timeout_sec)
        break;
      if (!saw_any && now - start_time >= timeout_sec)
        break;
    }
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

  if (argc < 5) {
    std::cout << USAGE;
    return 1;
  }

  std::string cmd = argv[1];
  std::string pkg = argv[2];
  if (cmd != "dump") {
    std::cout << USAGE;
    return 1;
  }

  ArchMode arch = ArchMode::ARM64;
  bool have_mode = false;
  int timeout_sec = 0;

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
    } else {
      std::cout << USAGE;
      return 1;
    }
  }

  if (!have_mode) {
    std::cout << USAGE;
    return 1;
  }

  cmd_dump(pkg, arch, timeout_sec);
  return 0;
}
