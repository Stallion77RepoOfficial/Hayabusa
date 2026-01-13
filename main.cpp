#include "memory.h"
#include "tracer.h"
#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

bool is_zip(const std::vector<uint8_t> &data) {
  return data.size() >= 4 && data[0] == 'P' && data[1] == 'K' &&
         data[2] == 0x03 && data[3] == 0x04;
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

void write_file(const std::string &path, const std::vector<uint8_t> &data) {
  int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return;
  size_t written = 0;
  while (written < data.size()) {
    ssize_t r = write(fd, data.data() + written, data.size() - written);
    if (r <= 0)
      break;
    written += r;
  }
  close(fd);
}

std::vector<uint8_t> read_file(const std::string &path) {
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0)
    return {};
  struct stat st;
  if (fstat(fd, &st) != 0) {
    close(fd);
    return {};
  }
  std::vector<uint8_t> data(st.st_size);
  size_t total = 0;
  while (total < data.size()) {
    ssize_t r = read(fd, data.data() + total, data.size() - total);
    if (r <= 0)
      break;
    total += r;
  }
  close(fd);
  return data;
}

bool is_garbage(const std::vector<uint8_t> &data) {
  if (data.size() < 64)
    return true;
  size_t check = std::min(data.size(), (size_t)8192);
  size_t zeros = 0, same = 0;
  uint8_t prev = data[0];
  for (size_t i = 0; i < check; i++) {
    if (data[i] == 0)
      zeros++;
    if (data[i] == prev)
      same++;
    prev = data[i];
  }
  return (zeros > check * 9 / 10) || (same > check * 9 / 10);
}

void analyze_elf(const std::vector<uint8_t> &data, const std::string &path) {
  std::ofstream f(path);
  if (!f)
    return;

  f << "=== ELF INFO ===\n";
  f << "RELRO: "
    << (ElfParser::has_full_relro(data)
            ? "Full"
            : (ElfParser::has_relro(data) ? "Partial" : "None"))
    << "\n";
  auto tls = ElfParser::get_tls_range(data);
  if (tls.second > 0)
    f << "TLS: 0x" << std::hex << tls.first << " size=" << std::dec
      << tls.second << "\n";
  auto init = ElfParser::get_init_array(data);
  if (!init.empty()) {
    f << "Init Array: " << init.size() << " functions\n";
    for (auto addr : init)
      f << "  0x" << std::hex << addr << "\n";
  }
  auto fini = ElfParser::get_fini_array(data);
  if (!fini.empty())
    f << "Fini Array: " << fini.size() << " functions\n";

  auto symbols = ElfParser::get_symbols(data);
  f << "\n=== SYMBOLS (" << std::dec << symbols.size() << ") ===\n";
  int objc_count = 0;
  for (const auto &s : symbols) {
    if (s.name.empty() || s.name.size() > 256)
      continue;
    bool ok = true;
    for (char c : s.name)
      if (c < 32 || c > 126) {
        ok = false;
        break;
      }
    if (!ok)
      continue;
    std::string display = ElfParser::demangle_symbol(s.name);
    if (ElfParser::is_objc_method(s.name)) {
      objc_count++;
      auto parsed = ElfParser::parse_objc_method(s.name);
      if (!parsed.first.empty())
        display = "[" + parsed.first + " " + parsed.second + "]";
    }
    f << "0x" << std::hex << std::setw(8) << std::setfill('0') << s.offset
      << " " << s.type << " " << display << "\n";
  }
  if (objc_count > 0)
    f << "\n[Objective-C methods: " << std::dec << objc_count << "]\n";

  auto plt = ElfParser::get_plt_entries(data);
  if (!plt.empty()) {
    f << "\n=== PLT ENTRIES (" << plt.size() << ") ===\n";
    for (const auto &p : plt) {
      f << "GOT 0x" << std::hex << p.got_offset << " -> " << p.symbol_name
        << "\n";
    }
  }

  auto strings = ElfParser::get_strings(data, 6);
  f << "\n=== STRINGS (" << std::dec << strings.size() << ") ===\n";
  size_t cnt = 0;
  for (const auto &s : strings) {
    if (cnt++ > 50000)
      break;
    if (s.value.size() > 200)
      continue;
    bool ok = true;
    for (char c : s.value)
      if (c < 32 || c > 126) {
        ok = false;
        break;
      }
    if (!ok)
      continue;
    f << "0x" << std::hex << std::setw(8) << std::setfill('0') << s.offset
      << " " << s.value << "\n";
  }
}

std::set<std::string> g_processed;
int g_pid = -1;

void scan_dir(const std::string &dir, const std::string &out);

void process(const std::string &name, const std::vector<uint8_t> &data,
             const std::string &out, uint64_t base) {
  std::string sname = name;
  if (sname.find('/') != std::string::npos)
    sname = sname.substr(sname.rfind('/') + 1);
  std::string key = sname + ":" + std::to_string(data.size());
  if (g_processed.count(key))
    return;
  g_processed.insert(key);
  if (is_zip(data)) {
    std::cout << "  [ZIP] " << sname << " (" << Utils::format_size(data.size())
              << ")\n";
    std::cout.flush();
    std::string tmp = "/data/local/tmp/_z_" + sname;
    write_file(tmp, data);
    std::string ext = "/data/local/tmp/_e_" + sname;
    mkdir_p(ext);
    system(
        ("unzip -o -q \"" + tmp + "\" -d \"" + ext + "\" 2>/dev/null").c_str());
    unlink(tmp.c_str());
    std::string nout = out + "/nested_" + sname;
    mkdir_p(nout);
    scan_dir(ext, nout);
    system(("rm -rf \"" + ext + "\"").c_str());
    return;
  }
  bool elf = ElfParser::is_elf(data);
  bool lib = sname.find(".so") != std::string::npos || sname.find("lib") == 0;
  if (elf || lib) {
    std::cout << "  [ELF] " << sname << " (" << Utils::format_size(data.size())
              << ", Base: 0x" << std::hex << base << std::dec << ")\n";
    std::cout.flush();
    std::string oname = sname;
    if (oname.find(".so") == std::string::npos)
      oname += ".so";
    mkdir_p(out + "/raw");
    write_file(out + "/raw/" + oname, data);
    auto fixed = SoFixer::repair(data, base);
    mkdir_p(out + "/so");
    write_file(out + "/so/" + oname, fixed);
    if (g_pid > 0 && base > 0) {
      std::cout << "    [RELINK] Static relinking...";
      std::cout.flush();
      auto relinked = StaticRelinker::relink(fixed, g_pid, base);
      if (relinked.size() > fixed.size()) {
        mkdir_p(out + "/relinked");
        write_file(out + "/relinked/" + oname, relinked);
        std::cout << " Added "
                  << Utils::format_size(relinked.size() - fixed.size())
                  << " embedded code\n";
        std::cout.flush();
      } else {
        std::cout << " No external calls found\n";
        std::cout.flush();
      }
    }
    if (!is_garbage(fixed)) {
      mkdir_p(out + "/analysis");
      analyze_elf(fixed, out + "/analysis/" + oname + ".txt");
    }
    return;
  }
  std::cout << "  [DATA] " << sname << " (" << Utils::format_size(data.size())
            << ")\n";
  std::cout.flush();
}

void scan_dir(const std::string &dir, const std::string &out) {
  DIR *d = opendir(dir.c_str());
  if (!d)
    return;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (e->d_name[0] == '.')
      continue;
    std::string n = e->d_name;
    std::string p = dir + "/" + n;
    struct stat st;
    if (stat(p.c_str(), &st) != 0)
      continue;
    if (S_ISDIR(st.st_mode)) {
      scan_dir(p, out);
    } else {
      if (n.find(".so") == std::string::npos &&
          n.find(".apk") == std::string::npos && n.find("lib") != 0)
        continue;
      auto data = read_file(p);
      if (!data.empty())
        process(n, data, out, 0);
    }
  }
  closedir(d);
}

struct Region {
  unsigned long start, end;
  std::string perms, name;
};

std::vector<Region> get_maps(int pid) {
  std::vector<Region> r;
  std::ifstream f("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(f, line)) {
    unsigned long s, e;
    char p[5] = {0}, n[512] = {0};
    if (sscanf(line.c_str(), "%lx-%lx %4s %*s %*s %*d %511[^\n]", &s, &e, p,
               n) >= 3) {
      Region x;
      x.start = s;
      x.end = e;
      x.perms = p;
      x.name = n;
      while (!x.name.empty() && x.name[0] == ' ')
        x.name = x.name.substr(1);
      r.push_back(x);
    }
  }
  return r;
}

std::vector<uint8_t> dump_mem(int pid, unsigned long addr, size_t size) {
  std::vector<uint8_t> buf(size, 0);
  int fd = open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDONLY);
  if (fd < 0)
    return buf;
  for (size_t off = 0; off < size; off += 4096) {
    size_t len = std::min((size_t)4096, size - off);
    pread(fd, buf.data() + off, len, addr + off);
  }
  close(fd);
  return buf;
}

void dump_memory(int pid, const std::string &pkg, const std::string &out) {
  auto regions = get_maps(pid);
  std::map<std::string, std::vector<Region>> grouped;
  for (auto &r : regions) {
    std::string k = r.name.empty() ? "[anon]" : r.name;
    if (k.find('/') != std::string::npos)
      k = k.substr(k.rfind('/') + 1);
    if (k.find(" (deleted)") != std::string::npos)
      k = k.substr(0, k.find(" (deleted)"));
    grouped[k].push_back(r);
  }
  std::cout << "    Found " << grouped.size() << " mappings\n";
  std::cout.flush();
  std::map<std::string, std::vector<uint8_t>> accumulated;
  std::map<std::string, uint64_t> bases;
  for (auto &[name, regs] : grouped) {
    if (name.find("[vvar]") != std::string::npos ||
        name.find("[vdso]") != std::string::npos ||
        name.find("[stack") != std::string::npos ||
        name.find("/dev/") != std::string::npos || name == "[anon]")
      continue;
    bool is_so = name.find(".so") != std::string::npos;
    bool exec = false;
    for (auto &r : regs)
      if (r.perms.find('x') != std::string::npos)
        exec = true;
    if (!is_so && !exec)
      continue;
    std::sort(regs.begin(), regs.end(),
              [](auto &a, auto &b) { return a.start < b.start; });
    size_t actual_size = 0;
    for (auto &r : regs) {
      if (r.perms.find('r') != std::string::npos)
        actual_size += r.end - r.start;
    }
    if (actual_size > 256 * 1024 * 1024 || actual_size < 1024)
      continue;
    unsigned long base = regs.front().start;
    unsigned long end = regs.back().end;
    size_t span_size = end - base;
    if (span_size > actual_size * 10) {
      for (auto &r : regs) {
        if (r.perms.find('r') == std::string::npos)
          continue;
        size_t rsize = r.end - r.start;
        if (rsize < 4096 || rsize > 256 * 1024 * 1024)
          continue;
        std::string rname = name + "_" + std::to_string(r.start);
        accumulated[rname].resize(rsize, 0);
        bases[rname] = r.start;
      }
    } else {
      accumulated[name].resize(span_size, 0);
      bases[name] = base;
    }
  }
  std::cout << "    [SNAPSHOT] Multi-pass capture (3 passes)...\n";
  std::cout.flush();
  for (int pass = 0; pass < 3; pass++) {
    if (pass > 0) {
      std::cout << "      Pass " << (pass + 1) << "/3...\n";
      std::cout.flush();
      sleep(2);
    } else {
      std::cout << "      Pass 1/3...\n";
      std::cout.flush();
    }
    regions = get_maps(pid);
    for (auto &[name, buf] : accumulated) {
      uint64_t base = bases[name];
      size_t size = buf.size();
      for (auto &r : regions) {
        std::string rn = r.name;
        if (rn.find('/') != std::string::npos)
          rn = rn.substr(rn.rfind('/') + 1);
        if (rn.find(" (deleted)") != std::string::npos)
          rn = rn.substr(0, rn.find(" (deleted)"));
        if (rn != name)
          continue;
        if (r.perms.find('r') == std::string::npos)
          continue;
        if (r.start < base || r.end > base + size)
          continue;
        auto chunk = dump_mem(pid, r.start, r.end - r.start);
        size_t off = r.start - base;
        for (size_t i = 0; i < chunk.size() && off + i < size; i++) {
          if (chunk[i] != 0 && buf[off + i] == 0)
            buf[off + i] = chunk[i];
        }
      }
    }
  }
  std::cout << "    [ON-DEMAND] Page-fault capture (10s)...\n";
  std::cout.flush();
  for (auto &[name, buf] : accumulated) {
    if (buf.size() < 1024 * 1024)
      continue;
    std::cout << "      Tracing: " << name << "\n";
    std::cout.flush();
    auto demand_data =
        ProcessTracer::dump_on_demand(pid, bases[name], buf.size(), 10);
    for (size_t i = 0; i < buf.size() && i < demand_data.size(); i++) {
      if (demand_data[i] != 0 && buf[i] == 0)
        buf[i] = demand_data[i];
    }
  }
  std::cout << "    [JIT] Capturing JIT code (10s)...\n";
  std::cout.flush();
  auto jit_regions = ProcessTracer::capture_jit(pid, 10);
  if (!jit_regions.empty()) {
    std::string jit_out = out + "/jit";
    mkdir_p(jit_out);
    for (size_t i = 0; i < jit_regions.size(); i++) {
      auto &jr = jit_regions[i];
      std::string jit_name =
          "jit_" + std::to_string(i) + "_0x" + std::to_string(jr.addr) + ".bin";
      write_file(jit_out + "/" + jit_name, jr.code);
    }
    std::cout << "      Captured " << jit_regions.size() << " JIT regions\n";
    std::cout.flush();
  }
  std::cout << "    Processing captured modules...\n";
  std::cout.flush();
  for (auto &[name, buf] : accumulated) {
    if (is_garbage(buf))
      continue;
    process(name, buf, out, bases[name]);
  }
}

void cmd_dump(const std::string &pkg, ArchMode arch) {
  ProcessTracer::set_arch(arch);
  std::string arch_str = (arch == ArchMode::ARM64) ? "ARM64" : "ARM32";
  std::cout << "\n================================================\n";
  std::cout << "  HAYABUSA - Android Memory Dumper\n";
  std::cout << "  Architecture: " << arch_str << "\n";
  std::cout << "================================================\n";
  std::cout << "Target: " << pkg << "\n\n";

  std::cout << "[1] Waiting for process...\n";
  std::cout.flush();

  int zygote_pid = ZygoteTracer::find_zygote_pid();
  if (zygote_pid <= 0) {
    std::cout << "    [!] System error: Zygote not found\n";
    return;
  }

  if (!ZygoteTracer::attach_zygote(zygote_pid)) {
    std::cout << "    [!] Failed to initialize - run as root\n";
    return;
  }

  std::cout << "    [+] Ready! Launch the app NOW on the device\n";
  std::cout.flush();

  int child_pid = ZygoteTracer::wait_for_fork(zygote_pid, pkg);
  if (child_pid <= 0) {
    std::cout << "    [!] Process not detected\n";
    return;
  }

  std::cout << "\n[2] Process captured! PID: " << child_pid << "\n";
  std::cout << "    Waiting 3s for initialization...\n";
  std::cout.flush();
  sleep(3);
  std::cout << "[3] Analyzing memory...\n";
  std::cout.flush();

  g_pid = child_pid;
  std::string base = "/data/local/tmp/" + pkg;
  std::string out = base + "_output";
  mkdir_p(out);
  g_processed.clear();

  dump_memory(child_pid, pkg, out);

  std::cout << "\n[4] Extracting resources...\n";
  std::cout.flush();
  auto apks = Utils::get_apk_paths(pkg);
  if (!apks.empty()) {
    std::cout << "    Found " << apks.size() << " APK(s)\n";
    std::string dout = out + "/disk";
    mkdir_p(dout);
    std::string tmp = base + "/_tmp";
    mkdir_p(tmp);
    for (auto &a : apks) {
      std::cout << "    Extracting: " << a << "\n";
      std::cout.flush();
      system(
          ("unzip -o -q \"" + a + "\" -d \"" + tmp + "\" 2>/dev/null").c_str());
    }
    scan_dir(tmp, dout);
    system(("rm -rf \"" + tmp + "\"").c_str());
  } else {
    std::cout << "    No APK found\n";
  }

  g_pid = -1;
  rmdir(base.c_str());
  std::cout << "\n================================================\n";
  std::cout << "  COMPLETE!\n";
  std::cout << "  Output: " << out << "\n";
  std::cout << "================================================\n";
  std::cout.flush();
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    std::cout << "Usage: hayabusa dump <package> --mode <arm32|arm64>\n";
    return 1;
  }
  std::string cmd = argv[1];
  std::string pkg = argv[2];
  ArchMode arch = ArchMode::ARM64;
  bool mode_specified = false;
  for (int i = 3; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--mode" && i + 1 < argc) {
      std::string mode = argv[++i];
      if (mode == "arm32") {
        arch = ArchMode::ARM32;
        mode_specified = true;
      } else if (mode == "arm64") {
        arch = ArchMode::ARM64;
        mode_specified = true;
      } else {
        std::cout << "Error: Invalid mode. Use 'arm32' or 'arm64'\n";
        return 1;
      }
    }
  }
  if (!mode_specified) {
    std::cout << "Error: --mode is required\n";
    std::cout << "Usage: hayabusa dump <package> --mode <arm32|arm64>\n";
    return 1;
  }
  if (cmd == "dump") {
    cmd_dump(pkg, arch);
  } else {
    std::cout << "Unknown command: " << cmd << "\n";
    return 1;
  }
  return 0;
}