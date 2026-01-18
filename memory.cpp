#include "memory.h"
#include "tracer.h"
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <unistd.h>

#ifndef EM_AARCH64
#define EM_AARCH64 183
#endif

#ifndef R_AARCH64_RELATIVE
#define R_AARCH64_RELATIVE 1027
#endif

#ifndef R_AARCH64_JUMP_SLOT
#define R_AARCH64_JUMP_SLOT 1026
#endif

#ifndef R_ARM_RELATIVE
#define R_ARM_RELATIVE 23
#endif

#ifndef R_ARM_JUMP_SLOT
#define R_ARM_JUMP_SLOT 22
#endif

std::vector<ModuleInfo> Memory::get_maps(int pid) {
  std::vector<ModuleInfo> mods;
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line)) {
    unsigned long start, end;
    char perms[5] = {0}, path[512] = {0};
    if (sscanf(line.c_str(), "%lx-%lx %4s %*s %*s %*d %511s", &start, &end,
               perms, path) >= 3) {
      ModuleInfo m;
      m.base = start;
      m.size = end - start;
      m.perms = perms;
      m.name = path[0] ? path : "";
      mods.push_back(m);
    }
  }
  return mods;
}

std::vector<uint8_t> Memory::dump(int pid, unsigned long addr, size_t size) {
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

int Utils::get_pid(const std::string &pkg) {
  DIR *dir = opendir("/proc");
  if (!dir)
    return -1;
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
    if (cmd == pkg) {
      closedir(dir);
      return pid;
    }
  }
  closedir(dir);
  return -1;
}

std::vector<std::string> Utils::get_apk_paths(const std::string &pkg) {
  std::vector<std::string> results;
  FILE *fp = popen(("pm path " + pkg + " 2>/dev/null").c_str(), "r");
  if (!fp)
    return results;
  char buf[512];
  while (fgets(buf, sizeof(buf), fp)) {
    std::string line = buf;
    if (line.substr(0, 8) == "package:")
      line = line.substr(8);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r'))
      line.pop_back();
    if (!line.empty())
      results.push_back(line);
  }
  pclose(fp);
  return results;
}

void Utils::launch_app(const std::string &pkg) {
  system(("monkey -p " + pkg +
          " -c android.intent.category.LAUNCHER 1 2>/dev/null")
             .c_str());
}

std::string Utils::format_size(size_t bytes) {
  const char *u[] = {"B", "KB", "MB", "GB"};
  int i = 0;
  double s = bytes;
  while (s >= 1024 && i < 3) {
    s /= 1024;
    i++;
  }
  std::ostringstream ss;
  ss << std::fixed << std::setprecision(i ? 2 : 0) << s << u[i];
  return ss.str();
}

bool ElfParser::is_elf(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  char magic[4] = {0};
  f.read(magic, 4);
  return magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' &&
         magic[3] == 'F';
}

bool ElfParser::is_elf(const std::vector<uint8_t> &data) {
  return data.size() >= 4 && data[0] == 0x7f && data[1] == 'E' &&
         data[2] == 'L' && data[3] == 'F';
}

bool ElfParser::is_elf32(const std::vector<uint8_t> &data) {
  return data.size() >= 5 && data[4] == ELFCLASS32;
}

std::vector<ElfSymbol>
ElfParser::get_symbols(const std::vector<uint8_t> &data) {
  std::vector<ElfSymbol> symbols;
  if (data.size() < 16)
    return symbols;
  if (!is_elf(data))
    return symbols;
  bool is32 = is_elf32(data);
  if (is32) {
    if (data.size() < sizeof(Elf32_Ehdr))
      return symbols;
    const Elf32_Ehdr *ehdr = reinterpret_cast<const Elf32_Ehdr *>(data.data());
    if (ehdr->e_shoff != 0 &&
        ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize <= data.size()) {
      for (int i = 0; i < ehdr->e_shnum; i++) {
        size_t shdr_off = ehdr->e_shoff + i * ehdr->e_shentsize;
        const Elf32_Shdr *shdr =
            reinterpret_cast<const Elf32_Shdr *>(data.data() + shdr_off);
        if (shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_DYNSYM)
          continue;
        size_t strtab_off = ehdr->e_shoff + shdr->sh_link * ehdr->e_shentsize;
        if (strtab_off + sizeof(Elf32_Shdr) > data.size())
          continue;
        const Elf32_Shdr *strtab_shdr =
            reinterpret_cast<const Elf32_Shdr *>(data.data() + strtab_off);
        if (shdr->sh_offset >= data.size() ||
            strtab_shdr->sh_offset >= data.size())
          continue;
        const char *strtab = reinterpret_cast<const char *>(
            data.data() + strtab_shdr->sh_offset);
        size_t num_syms = shdr->sh_size / sizeof(Elf32_Sym);
        for (size_t j = 0; j < num_syms; j++) {
          size_t sym_off = shdr->sh_offset + j * sizeof(Elf32_Sym);
          if (sym_off + sizeof(Elf32_Sym) > data.size())
            break;
          const Elf32_Sym *sym =
              reinterpret_cast<const Elf32_Sym *>(data.data() + sym_off);
          if (sym->st_name == 0)
            continue;
          ElfSymbol s;
          s.name = strtab + sym->st_name;
          s.offset = sym->st_value;
          s.size = sym->st_size;
          int type = ELF32_ST_TYPE(sym->st_info);
          s.type = (type == STT_FUNC) ? "FUNC"
                                      : (type == STT_OBJECT ? "VAR" : "OTHER");
          symbols.push_back(s);
        }
      }
      if (!symbols.empty())
        return symbols;
    }
    uint32_t dyn_addr = 0, dyn_sz = 0;
    if (ehdr->e_phoff == 0)
      return symbols;
    for (int i = 0; i < ehdr->e_phnum; i++) {
      size_t ph_off = ehdr->e_phoff + i * ehdr->e_phentsize;
      auto ph = reinterpret_cast<const Elf32_Phdr *>(data.data() + ph_off);
      if (ph->p_type == PT_DYNAMIC) {
        dyn_addr = ph->p_offset;
        dyn_sz = ph->p_filesz;
        break;
      }
    }
    if (dyn_addr == 0)
      return symbols;
    const Elf32_Dyn *dyn =
        reinterpret_cast<const Elf32_Dyn *>(data.data() + dyn_addr);
    uint32_t symtab = 0, strtab = 0, hash = 0;
    for (size_t i = 0; i < dyn_sz / sizeof(Elf32_Dyn); i++) {
      switch (dyn[i].d_tag) {
      case DT_SYMTAB:
        symtab = dyn[i].d_un.d_ptr;
        break;
      case DT_STRTAB:
        strtab = dyn[i].d_un.d_ptr;
        break;
      case DT_HASH:
        hash = dyn[i].d_un.d_ptr;
        break;
      }
    }
    uint32_t base = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<const Elf32_Phdr *>(
          data.data() + ehdr->e_phoff + i * ehdr->e_phentsize);
      if (ph->p_type == PT_LOAD) {
        base = ph->p_vaddr;
        break;
      }
    }
    auto r = [&](uint32_t a) { return (a >= base) ? a - base : a; };
    symtab = r(symtab);
    strtab = r(strtab);
    hash = r(hash);
    size_t count = 0;
    if (hash + 8 <= data.size()) {
      const uint32_t *h =
          reinterpret_cast<const uint32_t *>(data.data() + hash);
      count = h[1];
    }
    if (symtab >= data.size() || strtab >= data.size() || count == 0)
      return symbols;
    for (size_t i = 0; i < count; i++) {
      size_t sym_off = symtab + i * sizeof(Elf32_Sym);
      if (sym_off + sizeof(Elf32_Sym) > data.size())
        break;
      const Elf32_Sym *sym =
          reinterpret_cast<const Elf32_Sym *>(data.data() + sym_off);
      if (sym->st_name == 0 || strtab + sym->st_name >= data.size())
        continue;
      ElfSymbol s;
      s.name =
          reinterpret_cast<const char *>(data.data() + strtab + sym->st_name);
      s.offset = sym->st_value;
      s.size = sym->st_size;
      int type = ELF32_ST_TYPE(sym->st_info);
      s.type =
          (type == STT_FUNC) ? "FUNC" : (type == STT_OBJECT ? "VAR" : "OTHER");
      symbols.push_back(s);
    }
  } else {
    if (data.size() < sizeof(Elf64_Ehdr))
      return symbols;
    const Elf64_Ehdr *ehdr = reinterpret_cast<const Elf64_Ehdr *>(data.data());
    if (ehdr->e_shoff != 0 &&
        ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize <= data.size()) {
      for (int i = 0; i < ehdr->e_shnum; i++) {
        size_t shdr_off = ehdr->e_shoff + i * ehdr->e_shentsize;
        const Elf64_Shdr *shdr =
            reinterpret_cast<const Elf64_Shdr *>(data.data() + shdr_off);
        if (shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_DYNSYM)
          continue;
        size_t strtab_off = ehdr->e_shoff + shdr->sh_link * ehdr->e_shentsize;
        if (strtab_off + sizeof(Elf64_Shdr) > data.size())
          continue;
        const Elf64_Shdr *strtab_shdr =
            reinterpret_cast<const Elf64_Shdr *>(data.data() + strtab_off);
        if (shdr->sh_offset >= data.size() ||
            strtab_shdr->sh_offset >= data.size())
          continue;
        const char *strtab = reinterpret_cast<const char *>(
            data.data() + strtab_shdr->sh_offset);
        size_t num_syms = shdr->sh_size / sizeof(Elf64_Sym);
        for (size_t j = 0; j < num_syms; j++) {
          size_t sym_off = shdr->sh_offset + j * sizeof(Elf64_Sym);
          if (sym_off + sizeof(Elf64_Sym) > data.size())
            break;
          const Elf64_Sym *sym =
              reinterpret_cast<const Elf64_Sym *>(data.data() + sym_off);
          if (sym->st_name == 0)
            continue;
          ElfSymbol s;
          s.name = strtab + sym->st_name;
          s.offset = sym->st_value;
          s.size = sym->st_size;
          int type = ELF64_ST_TYPE(sym->st_info);
          s.type = (type == STT_FUNC) ? "FUNC"
                                      : (type == STT_OBJECT ? "VAR" : "OTHER");
          symbols.push_back(s);
        }
      }
      if (!symbols.empty())
        return symbols;
    }
    uint64_t dyn_addr = 0, dyn_sz = 0;
    if (ehdr->e_phoff == 0)
      return symbols;
    for (int i = 0; i < ehdr->e_phnum; i++) {
      size_t ph_off = ehdr->e_phoff + i * ehdr->e_phentsize;
      auto ph = reinterpret_cast<const Elf64_Phdr *>(data.data() + ph_off);
      if (ph->p_type == PT_DYNAMIC) {
        dyn_addr = ph->p_offset;
        dyn_sz = ph->p_filesz;
        break;
      }
    }
    if (dyn_addr == 0)
      return symbols;
    const Elf64_Dyn *dyn =
        reinterpret_cast<const Elf64_Dyn *>(data.data() + dyn_addr);
    uint64_t symtab = 0, strtab = 0, hash = 0;
    for (size_t i = 0; i < dyn_sz / sizeof(Elf64_Dyn); i++) {
      switch (dyn[i].d_tag) {
      case DT_SYMTAB:
        symtab = dyn[i].d_un.d_ptr;
        break;
      case DT_STRTAB:
        strtab = dyn[i].d_un.d_ptr;
        break;
      case DT_HASH:
        hash = dyn[i].d_un.d_ptr;
        break;
      }
    }
    uint64_t base = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<const Elf64_Phdr *>(
          data.data() + ehdr->e_phoff + i * ehdr->e_phentsize);
      if (ph->p_type == PT_LOAD) {
        base = ph->p_vaddr;
        break;
      }
    }
    auto r = [&](uint64_t a) { return (a >= base) ? a - base : a; };
    symtab = r(symtab);
    strtab = r(strtab);
    hash = r(hash);
    size_t count = 0;
    if (hash + 8 <= data.size()) {
      const uint32_t *h =
          reinterpret_cast<const uint32_t *>(data.data() + hash);
      count = h[1];
    }
    if (symtab >= data.size() || strtab >= data.size() || count == 0)
      return symbols;
    for (size_t i = 0; i < count; i++) {
      size_t sym_off = symtab + i * sizeof(Elf64_Sym);
      if (sym_off + sizeof(Elf64_Sym) > data.size())
        break;
      const Elf64_Sym *sym =
          reinterpret_cast<const Elf64_Sym *>(data.data() + sym_off);
      if (sym->st_name == 0 || strtab + sym->st_name >= data.size())
        continue;
      ElfSymbol s;
      s.name =
          reinterpret_cast<const char *>(data.data() + strtab + sym->st_name);
      s.offset = sym->st_value;
      s.size = sym->st_size;
      int type = ELF64_ST_TYPE(sym->st_info);
      s.type =
          (type == STT_FUNC) ? "FUNC" : (type == STT_OBJECT ? "VAR" : "OTHER");
      symbols.push_back(s);
    }
  }
  return symbols;
}

std::vector<ElfString> ElfParser::get_strings(const std::vector<uint8_t> &data,
                                              size_t min_len) {
  std::vector<ElfString> strings;
  std::string current;
  size_t start = 0;
  for (size_t i = 0; i < data.size(); i++) {
    char c = data[i];
    if (c >= 32 && c < 127) {
      if (current.empty())
        start = i;
      current += c;
    } else {
      if (current.length() >= min_len)
        strings.push_back({start, current});
      current.clear();
    }
  }
  if (current.length() >= min_len)
    strings.push_back({start, current});
  return strings;
}

static const char *g_shstrtab =
    "\0.dynsym\0.dynstr\0.hash\0.gnu.hash\0.rel.dyn\0.rel.plt\0.rela.dyn\0."
    "rela.plt\0"
    ".plt\0.text\0.rodata\0.init_array\0.fini_array\0.dynamic\0.got\0.got."
    "plt\0.data\0.bss\0.shstrtab\0";

static uint32_t shstr_off(const char *name) {
  const char *p = strstr(g_shstrtab + 1, name);
  return p ? (uint32_t)(p - g_shstrtab) : 0;
}

static uint64_t align_up(uint64_t v, uint64_t a) {
  return (v + a - 1) & ~(a - 1);
}

static std::vector<uint8_t> repair_elf32(const std::vector<uint8_t> &data,
                                         uint64_t base_addr) {
  std::vector<uint8_t> fixed = data;
  if (fixed.size() < sizeof(Elf32_Ehdr))
    fixed.resize(sizeof(Elf32_Ehdr));
  Elf32_Ehdr *ehdr = reinterpret_cast<Elf32_Ehdr *>(fixed.data());
  if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) {
    memset(ehdr, 0, sizeof(Elf32_Ehdr));
    memcpy(ehdr->e_ident, ELFMAG, 4);
    ehdr->e_ident[EI_CLASS] = ELFCLASS32;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_type = ET_DYN;
    ehdr->e_machine = EM_ARM;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof(Elf32_Ehdr);
    ehdr->e_phentsize = sizeof(Elf32_Phdr);
    ehdr->e_shentsize = sizeof(Elf32_Shdr);
    ehdr->e_phoff = sizeof(Elf32_Ehdr);
  }
  uint32_t bias = 0;
  uint32_t dyn_off = 0, dyn_sz = 0;
  uint32_t last_load_end = 0;
  if (ehdr->e_phoff != 0 &&
      ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize <= fixed.size()) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<Elf32_Phdr *>(fixed.data() + ehdr->e_phoff +
                                               i * ehdr->e_phentsize);
      if (ph->p_type == PT_LOAD && bias == 0)
        bias = ph->p_vaddr;
    }
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<Elf32_Phdr *>(fixed.data() + ehdr->e_phoff +
                                               i * ehdr->e_phentsize);
      if (ph->p_vaddr >= bias) {
        ph->p_vaddr -= bias;
        ph->p_paddr = ph->p_vaddr;
        ph->p_offset = ph->p_vaddr;
        ph->p_filesz = ph->p_memsz;
      }
      if (ph->p_type == PT_LOAD) {
        uint32_t end = ph->p_vaddr + ph->p_memsz;
        if (end > last_load_end)
          last_load_end = end;
      }
      if (ph->p_type == PT_DYNAMIC) {
        dyn_off = ph->p_vaddr;
        dyn_sz = ph->p_filesz;
      }
    }
  }
  if (ehdr->e_entry >= bias)
    ehdr->e_entry -= bias;
  Elf32_Shdr shdr[18] = {};
  auto r = [&](uint32_t a) { return (a >= bias) ? a - bias : a; };
  uint32_t strtab = 0, strsz = 0, symtab = 0, syment = sizeof(Elf32_Sym);
  uint32_t hash = 0, gnu_hash = 0;
  uint32_t rel = 0, relsz = 0, relent = sizeof(Elf32_Rel);
  uint32_t jmprel = 0, pltrelsz = 0;
  uint32_t pltgot = 0;
  uint32_t init_arr = 0, init_sz = 0, fini_arr = 0, fini_sz = 0;
  size_t nDynSyms = 0;
  if (dyn_off != 0 && dyn_sz != 0 && dyn_off + dyn_sz <= fixed.size()) {
    shdr[12].sh_name = shstr_off(".dynamic");
    shdr[12].sh_type = SHT_DYNAMIC;
    shdr[12].sh_flags = SHF_WRITE | SHF_ALLOC;
    shdr[12].sh_addr = shdr[12].sh_offset = dyn_off;
    shdr[12].sh_size = dyn_sz;
    shdr[12].sh_link = 2;
    shdr[12].sh_addralign = 4;
    shdr[12].sh_entsize = 8;
    Elf32_Dyn *dyn = reinterpret_cast<Elf32_Dyn *>(fixed.data() + dyn_off);
    size_t dyn_n = dyn_sz / sizeof(Elf32_Dyn);
    for (size_t i = 0; i < dyn_n; i++) {
      switch (dyn[i].d_tag) {
      case DT_STRTAB:
        strtab = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(strtab);
        break;
      case DT_STRSZ:
        strsz = dyn[i].d_un.d_val;
        break;
      case DT_SYMTAB:
        symtab = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(symtab);
        break;
      case DT_SYMENT:
        syment = dyn[i].d_un.d_val;
        break;
      case DT_HASH:
        hash = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(hash);
        break;
      case DT_GNU_HASH:
        gnu_hash = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(gnu_hash);
        break;
      case DT_REL:
        rel = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(rel);
        break;
      case DT_RELSZ:
        relsz = dyn[i].d_un.d_val;
        break;
      case DT_RELENT:
        relent = dyn[i].d_un.d_val;
        break;
      case DT_JMPREL:
        jmprel = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(jmprel);
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn[i].d_un.d_val;
        break;
      case DT_PLTGOT:
        pltgot = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(pltgot);
        break;
      case DT_INIT_ARRAY:
        init_arr = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(init_arr);
        break;
      case DT_INIT_ARRAYSZ:
        init_sz = dyn[i].d_un.d_val;
        break;
      case DT_FINI_ARRAY:
        fini_arr = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(fini_arr);
        break;
      case DT_FINI_ARRAYSZ:
        fini_sz = dyn[i].d_un.d_val;
        break;
      }
    }
    if (hash) {
      uint32_t h_off = r(hash);
      if (h_off + 8 <= fixed.size()) {
        const uint32_t *htab =
            reinterpret_cast<const uint32_t *>(fixed.data() + h_off);
        uint32_t nbucket = htab[0], nchain = htab[1];
        nDynSyms = nchain;
        shdr[3].sh_name = shstr_off(".hash");
        shdr[3].sh_type = SHT_HASH;
        shdr[3].sh_flags = SHF_ALLOC;
        shdr[3].sh_addr = shdr[3].sh_offset = h_off;
        shdr[3].sh_size = (nbucket + nchain + 2) * 4;
        shdr[3].sh_link = 1;
        shdr[3].sh_addralign = 4;
        shdr[3].sh_entsize = 4;
      }
    }
    if (gnu_hash && nDynSyms == 0) {
      nDynSyms = 4096;
      shdr[4].sh_name = shstr_off(".gnu.hash");
      shdr[4].sh_type = SHT_GNU_HASH;
      shdr[4].sh_flags = SHF_ALLOC;
      shdr[4].sh_addr = shdr[4].sh_offset = r(gnu_hash);
      shdr[4].sh_size = 64;
      shdr[4].sh_link = 1;
      shdr[4].sh_addralign = 4;
    }
    if (symtab && nDynSyms > 0) {
      shdr[1].sh_name = shstr_off(".dynsym");
      shdr[1].sh_type = SHT_DYNSYM;
      shdr[1].sh_flags = SHF_ALLOC;
      shdr[1].sh_addr = shdr[1].sh_offset = r(symtab);
      shdr[1].sh_size = nDynSyms * syment;
      shdr[1].sh_link = 2;
      shdr[1].sh_info = 1;
      shdr[1].sh_addralign = 4;
      shdr[1].sh_entsize = syment;
      Elf32_Sym *syms = reinterpret_cast<Elf32_Sym *>(fixed.data() + r(symtab));
      for (size_t i = 0; i < nDynSyms && r(symtab) + i * syment < fixed.size();
           i++) {
        if (syms[i].st_value >= bias)
          syms[i].st_value -= bias;
        uint8_t type = ELF32_ST_TYPE(syms[i].st_info);
        if (type > STT_FILE) {
          uint8_t bind = ELF32_ST_BIND(syms[i].st_info);
          syms[i].st_info = ELF32_ST_INFO(
              bind, syms[i].st_value == 0 ? STT_FUNC : STT_OBJECT);
        }
      }
    }
    if (strtab && strsz) {
      shdr[2].sh_name = shstr_off(".dynstr");
      shdr[2].sh_type = SHT_STRTAB;
      shdr[2].sh_flags = SHF_ALLOC;
      shdr[2].sh_addr = shdr[2].sh_offset = r(strtab);
      shdr[2].sh_size = strsz;
      shdr[2].sh_addralign = 1;
    }
    if (rel && relsz) {
      shdr[5].sh_name = shstr_off(".rel.dyn");
      shdr[5].sh_type = SHT_REL;
      shdr[5].sh_flags = SHF_ALLOC;
      shdr[5].sh_addr = shdr[5].sh_offset = r(rel);
      shdr[5].sh_size = relsz;
      shdr[5].sh_link = 1;
      shdr[5].sh_addralign = 4;
      shdr[5].sh_entsize = relent;
      Elf32_Rel *rels = reinterpret_cast<Elf32_Rel *>(fixed.data() + r(rel));
      size_t rel_n = relsz / relent;
      for (size_t i = 0; i < rel_n && r(rel) + i * relent < fixed.size(); i++) {
        uint32_t type = ELF32_R_TYPE(rels[i].r_info);
        if (type == R_ARM_RELATIVE || type == R_ARM_JUMP_SLOT) {
          if (rels[i].r_offset >= bias)
            rels[i].r_offset -= bias;
        }
        if (type == R_ARM_RELATIVE) {
          uint32_t off = rels[i].r_offset;
          if (off + 4 <= fixed.size()) {
            uint32_t *ptr = reinterpret_cast<uint32_t *>(fixed.data() + off);
            if (*ptr >= bias)
              *ptr -= bias;
          }
        }
      }
    }
    if (jmprel && pltrelsz) {
      shdr[6].sh_name = shstr_off(".rel.plt");
      shdr[6].sh_type = SHT_REL;
      shdr[6].sh_flags = SHF_ALLOC;
      shdr[6].sh_addr = shdr[6].sh_offset = r(jmprel);
      shdr[6].sh_size = pltrelsz;
      shdr[6].sh_link = 1;
      shdr[6].sh_info = 14;
      shdr[6].sh_addralign = 4;
      shdr[6].sh_entsize = sizeof(Elf32_Rel);
      Elf32_Rel *rels = reinterpret_cast<Elf32_Rel *>(fixed.data() + r(jmprel));
      size_t rel_n = pltrelsz / sizeof(Elf32_Rel);
      for (size_t i = 0;
           i < rel_n && r(jmprel) + i * sizeof(Elf32_Rel) < fixed.size(); i++) {
        if (rels[i].r_offset >= bias)
          rels[i].r_offset -= bias;
      }
      size_t plt_entries = rel_n;
      shdr[7].sh_name = shstr_off(".plt");
      shdr[7].sh_type = SHT_PROGBITS;
      shdr[7].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
      shdr[7].sh_addr = shdr[7].sh_offset =
          (uint32_t)align_up(r(jmprel) + pltrelsz, 4);
      shdr[7].sh_size = (uint32_t)align_up(20 + 12 * plt_entries, 4);
      shdr[7].sh_addralign = 4;
      if (pltgot) {
        shdr[14].sh_name = shstr_off(".got.plt");
        shdr[14].sh_type = SHT_PROGBITS;
        shdr[14].sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr[14].sh_addr = shdr[14].sh_offset = r(pltgot);
        shdr[14].sh_size = (3 + plt_entries) * 4;
        shdr[14].sh_addralign = 4;
        uint32_t *got = reinterpret_cast<uint32_t *>(fixed.data() + r(pltgot));
        size_t got_count = 3 + plt_entries;
        for (size_t i = 0; i < got_count && r(pltgot) + i * 4 < fixed.size();
             i++) {
          if (got[i] >= bias)
            got[i] -= bias;
        }
      }
    }
    if (init_arr && init_sz) {
      shdr[10].sh_name = shstr_off(".init_array");
      shdr[10].sh_type = SHT_INIT_ARRAY;
      shdr[10].sh_flags = SHF_ALLOC | SHF_WRITE;
      shdr[10].sh_addr = shdr[10].sh_offset = r(init_arr);
      shdr[10].sh_size = init_sz;
      shdr[10].sh_addralign = 4;
      shdr[10].sh_entsize = 4;
      uint32_t *arr = reinterpret_cast<uint32_t *>(fixed.data() + r(init_arr));
      for (size_t i = 0; i < init_sz / 4 && r(init_arr) + i * 4 < fixed.size();
           i++) {
        if (arr[i] >= bias)
          arr[i] -= bias;
      }
    }
    if (fini_arr && fini_sz) {
      shdr[11].sh_name = shstr_off(".fini_array");
      shdr[11].sh_type = SHT_FINI_ARRAY;
      shdr[11].sh_flags = SHF_ALLOC | SHF_WRITE;
      shdr[11].sh_addr = shdr[11].sh_offset = r(fini_arr);
      shdr[11].sh_size = fini_sz;
      shdr[11].sh_addralign = 4;
      shdr[11].sh_entsize = 4;
      uint32_t *arr = reinterpret_cast<uint32_t *>(fixed.data() + r(fini_arr));
      for (size_t i = 0; i < fini_sz / 4 && r(fini_arr) + i * 4 < fixed.size();
           i++) {
        if (arr[i] >= bias)
          arr[i] -= bias;
      }
    }
  }
  size_t shstrtab_sz = strlen(g_shstrtab) + 1;
  shdr[17].sh_name = shstr_off(".shstrtab");
  shdr[17].sh_type = SHT_STRTAB;
  while (fixed.size() % 4)
    fixed.push_back(0);
  shdr[17].sh_offset = fixed.size();
  shdr[17].sh_size = shstrtab_sz;
  shdr[17].sh_addralign = 1;
  fixed.insert(fixed.end(), g_shstrtab, g_shstrtab + shstrtab_sz);
  while (fixed.size() % 4)
    fixed.push_back(0);
  uint32_t sh_off = fixed.size();
  for (int i = 0; i < 18; i++) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&shdr[i]);
    fixed.insert(fixed.end(), p, p + sizeof(Elf32_Shdr));
  }
  ehdr = reinterpret_cast<Elf32_Ehdr *>(fixed.data());
  ehdr->e_shoff = sh_off;
  ehdr->e_shnum = 18;
  ehdr->e_shstrndx = 17;
  return fixed;
}

static std::vector<uint8_t> repair_elf64(const std::vector<uint8_t> &data,
                                         uint64_t base_addr) {
  std::vector<uint8_t> fixed = data;
  if (fixed.size() < sizeof(Elf64_Ehdr))
    fixed.resize(sizeof(Elf64_Ehdr));
  Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr *>(fixed.data());
  if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0) {
    memset(ehdr, 0, sizeof(Elf64_Ehdr));
    memcpy(ehdr->e_ident, ELFMAG, 4);
    ehdr->e_ident[EI_CLASS] = ELFCLASS64;
    ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr->e_ident[EI_VERSION] = EV_CURRENT;
    ehdr->e_type = ET_DYN;
    ehdr->e_machine = EM_AARCH64;
    ehdr->e_version = EV_CURRENT;
    ehdr->e_ehsize = sizeof(Elf64_Ehdr);
    ehdr->e_phentsize = sizeof(Elf64_Phdr);
    ehdr->e_shentsize = sizeof(Elf64_Shdr);
    ehdr->e_phoff = sizeof(Elf64_Ehdr);
  }
  uint64_t bias = 0;
  uint64_t dyn_off = 0, dyn_sz = 0;
  uint64_t last_load_end = 0;
  if (ehdr->e_phoff != 0 &&
      ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize <= fixed.size()) {
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<Elf64_Phdr *>(fixed.data() + ehdr->e_phoff +
                                               i * ehdr->e_phentsize);
      if (ph->p_type == PT_LOAD && bias == 0)
        bias = ph->p_vaddr;
    }
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<Elf64_Phdr *>(fixed.data() + ehdr->e_phoff +
                                               i * ehdr->e_phentsize);
      if (ph->p_vaddr >= bias) {
        ph->p_vaddr -= bias;
        ph->p_paddr = ph->p_vaddr;
        ph->p_offset = ph->p_vaddr;
        ph->p_filesz = ph->p_memsz;
      }
      if (ph->p_type == PT_LOAD) {
        uint64_t end = ph->p_vaddr + ph->p_memsz;
        if (end > last_load_end)
          last_load_end = end;
      }
      if (ph->p_type == PT_DYNAMIC) {
        dyn_off = ph->p_vaddr;
        dyn_sz = ph->p_filesz;
      }
    }
  }
  if (ehdr->e_entry >= bias)
    ehdr->e_entry -= bias;
  Elf64_Shdr shdr[18] = {};
  auto r = [&](uint64_t a) { return (a >= bias) ? a - bias : a; };
  uint64_t strtab = 0, strsz = 0, symtab = 0, syment = sizeof(Elf64_Sym);
  uint64_t hash = 0, gnu_hash = 0;
  uint64_t rela = 0, relasz = 0, relaent = sizeof(Elf64_Rela);
  uint64_t jmprel = 0, pltrelsz = 0;
  uint64_t pltgot = 0;
  uint64_t init_arr = 0, init_sz = 0, fini_arr = 0, fini_sz = 0;
  size_t nDynSyms = 0;
  if (dyn_off != 0 && dyn_sz != 0 && dyn_off + dyn_sz <= fixed.size()) {
    shdr[12].sh_name = shstr_off(".dynamic");
    shdr[12].sh_type = SHT_DYNAMIC;
    shdr[12].sh_flags = SHF_WRITE | SHF_ALLOC;
    shdr[12].sh_addr = shdr[12].sh_offset = dyn_off;
    shdr[12].sh_size = dyn_sz;
    shdr[12].sh_link = 2;
    shdr[12].sh_addralign = 8;
    shdr[12].sh_entsize = 16;
    Elf64_Dyn *dyn = reinterpret_cast<Elf64_Dyn *>(fixed.data() + dyn_off);
    size_t dyn_n = dyn_sz / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < dyn_n; i++) {
      switch (dyn[i].d_tag) {
      case DT_STRTAB:
        strtab = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(strtab);
        break;
      case DT_STRSZ:
        strsz = dyn[i].d_un.d_val;
        break;
      case DT_SYMTAB:
        symtab = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(symtab);
        break;
      case DT_SYMENT:
        syment = dyn[i].d_un.d_val;
        break;
      case DT_HASH:
        hash = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(hash);
        break;
      case DT_GNU_HASH:
        gnu_hash = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(gnu_hash);
        break;
      case DT_RELA:
        rela = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(rela);
        break;
      case DT_RELASZ:
        relasz = dyn[i].d_un.d_val;
        break;
      case DT_RELAENT:
        relaent = dyn[i].d_un.d_val;
        break;
      case DT_JMPREL:
        jmprel = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(jmprel);
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn[i].d_un.d_val;
        break;
      case DT_PLTGOT:
        pltgot = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(pltgot);
        break;
      case DT_INIT_ARRAY:
        init_arr = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(init_arr);
        break;
      case DT_INIT_ARRAYSZ:
        init_sz = dyn[i].d_un.d_val;
        break;
      case DT_FINI_ARRAY:
        fini_arr = dyn[i].d_un.d_ptr;
        dyn[i].d_un.d_ptr = r(fini_arr);
        break;
      case DT_FINI_ARRAYSZ:
        fini_sz = dyn[i].d_un.d_val;
        break;
      }
    }
    if (hash) {
      uint64_t h_off = r(hash);
      if (h_off + 8 <= fixed.size()) {
        const uint32_t *htab =
            reinterpret_cast<const uint32_t *>(fixed.data() + h_off);
        uint32_t nbucket = htab[0], nchain = htab[1];
        nDynSyms = nchain;
        shdr[3].sh_name = shstr_off(".hash");
        shdr[3].sh_type = SHT_HASH;
        shdr[3].sh_flags = SHF_ALLOC;
        shdr[3].sh_addr = shdr[3].sh_offset = h_off;
        shdr[3].sh_size = (nbucket + nchain + 2) * 4;
        shdr[3].sh_link = 1;
        shdr[3].sh_addralign = 8;
        shdr[3].sh_entsize = 4;
      }
    }
    if (gnu_hash && nDynSyms == 0) {
      nDynSyms = 4096;
      shdr[4].sh_name = shstr_off(".gnu.hash");
      shdr[4].sh_type = SHT_GNU_HASH;
      shdr[4].sh_flags = SHF_ALLOC;
      shdr[4].sh_addr = shdr[4].sh_offset = r(gnu_hash);
      shdr[4].sh_size = 64;
      shdr[4].sh_link = 1;
      shdr[4].sh_addralign = 8;
    }
    if (symtab && nDynSyms > 0) {
      shdr[1].sh_name = shstr_off(".dynsym");
      shdr[1].sh_type = SHT_DYNSYM;
      shdr[1].sh_flags = SHF_ALLOC;
      shdr[1].sh_addr = shdr[1].sh_offset = r(symtab);
      shdr[1].sh_size = nDynSyms * syment;
      shdr[1].sh_link = 2;
      shdr[1].sh_info = 1;
      shdr[1].sh_addralign = 8;
      shdr[1].sh_entsize = syment;
      Elf64_Sym *syms = reinterpret_cast<Elf64_Sym *>(fixed.data() + r(symtab));
      for (size_t i = 0; i < nDynSyms && r(symtab) + i * syment < fixed.size();
           i++) {
        if (syms[i].st_value >= bias)
          syms[i].st_value -= bias;
        uint8_t type = ELF64_ST_TYPE(syms[i].st_info);
        if (type > STT_FILE) {
          uint8_t bind = ELF64_ST_BIND(syms[i].st_info);
          syms[i].st_info = ELF64_ST_INFO(
              bind, syms[i].st_value == 0 ? STT_FUNC : STT_OBJECT);
        }
      }
    }
    if (strtab && strsz) {
      shdr[2].sh_name = shstr_off(".dynstr");
      shdr[2].sh_type = SHT_STRTAB;
      shdr[2].sh_flags = SHF_ALLOC;
      shdr[2].sh_addr = shdr[2].sh_offset = r(strtab);
      shdr[2].sh_size = strsz;
      shdr[2].sh_addralign = 1;
    }
    if (rela && relasz) {
      shdr[5].sh_name = shstr_off(".rela.dyn");
      shdr[5].sh_type = SHT_RELA;
      shdr[5].sh_flags = SHF_ALLOC;
      shdr[5].sh_addr = shdr[5].sh_offset = r(rela);
      shdr[5].sh_size = relasz;
      shdr[5].sh_link = 1;
      shdr[5].sh_addralign = 8;
      shdr[5].sh_entsize = relaent;
      Elf64_Rela *rels = reinterpret_cast<Elf64_Rela *>(fixed.data() + r(rela));
      size_t rel_n = relasz / relaent;
      for (size_t i = 0; i < rel_n && r(rela) + i * relaent < fixed.size();
           i++) {
        uint32_t type = ELF64_R_TYPE(rels[i].r_info);
        if (rels[i].r_offset >= bias)
          rels[i].r_offset -= bias;
        if (type == R_AARCH64_RELATIVE) {
          if (rels[i].r_addend >= (int64_t)bias)
            rels[i].r_addend -= bias;
          uint64_t off = rels[i].r_offset;
          if (off + 8 <= fixed.size()) {
            uint64_t *ptr = reinterpret_cast<uint64_t *>(fixed.data() + off);
            if (*ptr >= bias)
              *ptr -= bias;
          }
        }
      }
    }
    if (jmprel && pltrelsz) {
      shdr[6].sh_name = shstr_off(".rela.plt");
      shdr[6].sh_type = SHT_RELA;
      shdr[6].sh_flags = SHF_ALLOC;
      shdr[6].sh_addr = shdr[6].sh_offset = r(jmprel);
      shdr[6].sh_size = pltrelsz;
      shdr[6].sh_link = 1;
      shdr[6].sh_info = 14;
      shdr[6].sh_addralign = 8;
      shdr[6].sh_entsize = sizeof(Elf64_Rela);
      Elf64_Rela *rels =
          reinterpret_cast<Elf64_Rela *>(fixed.data() + r(jmprel));
      size_t rel_n = pltrelsz / sizeof(Elf64_Rela);
      for (size_t i = 0;
           i < rel_n && r(jmprel) + i * sizeof(Elf64_Rela) < fixed.size();
           i++) {
        if (rels[i].r_offset >= bias)
          rels[i].r_offset -= bias;
      }
      size_t plt_entries = rel_n;
      shdr[7].sh_name = shstr_off(".plt");
      shdr[7].sh_type = SHT_PROGBITS;
      shdr[7].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
      shdr[7].sh_addr = shdr[7].sh_offset = align_up(r(jmprel) + pltrelsz, 16);
      shdr[7].sh_size = align_up(32 + 16 * plt_entries, 16);
      shdr[7].sh_addralign = 16;
      if (pltgot) {
        shdr[14].sh_name = shstr_off(".got.plt");
        shdr[14].sh_type = SHT_PROGBITS;
        shdr[14].sh_flags = SHF_ALLOC | SHF_WRITE;
        shdr[14].sh_addr = shdr[14].sh_offset = r(pltgot);
        shdr[14].sh_size = (3 + plt_entries) * 8;
        shdr[14].sh_addralign = 8;
        uint64_t *got = reinterpret_cast<uint64_t *>(fixed.data() + r(pltgot));
        size_t got_count = 3 + plt_entries;
        for (size_t i = 0; i < got_count && r(pltgot) + i * 8 < fixed.size();
             i++) {
          if (got[i] >= bias)
            got[i] -= bias;
        }
      }
    }
    if (init_arr && init_sz) {
      shdr[10].sh_name = shstr_off(".init_array");
      shdr[10].sh_type = SHT_INIT_ARRAY;
      shdr[10].sh_flags = SHF_ALLOC | SHF_WRITE;
      shdr[10].sh_addr = shdr[10].sh_offset = r(init_arr);
      shdr[10].sh_size = init_sz;
      shdr[10].sh_addralign = 8;
      shdr[10].sh_entsize = 8;
      uint64_t *arr = reinterpret_cast<uint64_t *>(fixed.data() + r(init_arr));
      for (size_t i = 0; i < init_sz / 8 && r(init_arr) + i * 8 < fixed.size();
           i++) {
        if (arr[i] >= bias)
          arr[i] -= bias;
      }
    }
    if (fini_arr && fini_sz) {
      shdr[11].sh_name = shstr_off(".fini_array");
      shdr[11].sh_type = SHT_FINI_ARRAY;
      shdr[11].sh_flags = SHF_ALLOC | SHF_WRITE;
      shdr[11].sh_addr = shdr[11].sh_offset = r(fini_arr);
      shdr[11].sh_size = fini_sz;
      shdr[11].sh_addralign = 8;
      shdr[11].sh_entsize = 8;
      uint64_t *arr = reinterpret_cast<uint64_t *>(fixed.data() + r(fini_arr));
      for (size_t i = 0; i < fini_sz / 8 && r(fini_arr) + i * 8 < fixed.size();
           i++) {
        if (arr[i] >= bias)
          arr[i] -= bias;
      }
    }
  }
  size_t shstrtab_sz = strlen(g_shstrtab) + 1;
  shdr[17].sh_name = shstr_off(".shstrtab");
  shdr[17].sh_type = SHT_STRTAB;
  while (fixed.size() % 8)
    fixed.push_back(0);
  shdr[17].sh_offset = fixed.size();
  shdr[17].sh_size = shstrtab_sz;
  shdr[17].sh_addralign = 1;
  fixed.insert(fixed.end(), g_shstrtab, g_shstrtab + shstrtab_sz);
  while (fixed.size() % 8)
    fixed.push_back(0);
  uint64_t sh_off = fixed.size();
  for (int i = 0; i < 18; i++) {
    const uint8_t *p = reinterpret_cast<const uint8_t *>(&shdr[i]);
    fixed.insert(fixed.end(), p, p + sizeof(Elf64_Shdr));
  }
  ehdr = reinterpret_cast<Elf64_Ehdr *>(fixed.data());
  ehdr->e_shoff = sh_off;
  ehdr->e_shnum = 18;
  ehdr->e_shstrndx = 17;
  return fixed;
}

std::vector<uint8_t> SoFixer::repair(const std::vector<uint8_t> &data,
                                     uint64_t base_addr) {
  if (data.size() < 5)
    return data;
  bool is32 = ElfParser::is_elf32(data);
  if (ProcessTracer::get_arch() == ArchMode::ARM32)
    is32 = true;
  if (is32)
    return repair_elf32(data, base_addr);
  else
    return repair_elf64(data, base_addr);
}

static std::string get_string_at(const std::vector<uint8_t> &data,
                                 size_t offset) {
  if (offset >= data.size())
    return "";
  std::string s;
  while (offset < data.size() && data[offset] != 0) {
    s += (char)data[offset++];
  }
  return s;
}

std::vector<ElfParser::PltEntry>
ElfParser::get_plt_entries(const std::vector<uint8_t> &data) {
  std::vector<ElfParser::PltEntry> entries;
  if (data.size() < sizeof(Elf64_Ehdr))
    return entries;

  bool is32 = is_elf32(data);

  if (!is32) {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data.data();
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
      return entries;

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(data.data() + ehdr->e_shoff);
    const Elf64_Shdr *shstrtab = nullptr;
    if (ehdr->e_shstrndx < ehdr->e_shnum)
      shstrtab = &shdrs[ehdr->e_shstrndx];

    const Elf64_Shdr *dynsym = nullptr;
    const Elf64_Shdr *dynstr = nullptr;
    const Elf64_Shdr *relaplt = nullptr;
    const Elf64_Shdr *plt = nullptr;

    for (int i = 0; i < ehdr->e_shnum; i++) {
      std::string name;
      if (shstrtab && shdrs[i].sh_name < data.size() - ehdr->e_shoff)
        name = get_string_at(data, shstrtab->sh_offset + shdrs[i].sh_name);

      if (shdrs[i].sh_type == SHT_DYNSYM)
        dynsym = &shdrs[i];
      else if (shdrs[i].sh_type == SHT_STRTAB && name == ".dynstr")
        dynstr = &shdrs[i];
      else if (shdrs[i].sh_type == SHT_RELA &&
               (name == ".rela.plt" || name == ".rela.dyn"))
        relaplt = &shdrs[i];
      else if (name == ".plt" || name == ".plt.got")
        plt = &shdrs[i];
    }

    if (!dynsym || !dynstr || !relaplt)
      return entries;

    size_t rela_count = relaplt->sh_size / sizeof(Elf64_Rela);
    const Elf64_Rela *relas =
        (const Elf64_Rela *)(data.data() + relaplt->sh_offset);
    const Elf64_Sym *syms =
        (const Elf64_Sym *)(data.data() + dynsym->sh_offset);

    for (size_t i = 0; i < rela_count; i++) {
      uint32_t sym_idx = ELF64_R_SYM(relas[i].r_info);
      uint32_t type = ELF64_R_TYPE(relas[i].r_info);

      if (type == R_AARCH64_JUMP_SLOT || type == 1026) {
        ElfParser::PltEntry e;
        e.offset = relas[i].r_offset;
        e.got_offset = relas[i].r_offset;
        e.symbol_index = sym_idx;

        if (sym_idx > 0 && dynsym->sh_size / sizeof(Elf64_Sym) > sym_idx) {
          uint32_t str_off = syms[sym_idx].st_name;
          if (str_off < dynstr->sh_size)
            e.symbol_name = get_string_at(data, dynstr->sh_offset + str_off);
        }
        entries.push_back(e);
      }
    }
  } else {
    const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data.data();
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0)
      return entries;

    const Elf32_Shdr *shdrs = (const Elf32_Shdr *)(data.data() + ehdr->e_shoff);
    const Elf32_Shdr *dynsym = nullptr;
    const Elf32_Shdr *dynstr = nullptr;
    const Elf32_Shdr *relplt = nullptr;

    for (int i = 0; i < ehdr->e_shnum; i++) {
      if (shdrs[i].sh_type == SHT_DYNSYM)
        dynsym = &shdrs[i];
      else if (shdrs[i].sh_type == SHT_STRTAB && i != ehdr->e_shstrndx)
        dynstr = &shdrs[i];
      else if (shdrs[i].sh_type == SHT_REL)
        relplt = &shdrs[i];
    }

    if (!dynsym || !dynstr || !relplt)
      return entries;

    size_t rel_count = relplt->sh_size / sizeof(Elf32_Rel);
    const Elf32_Rel *rels =
        (const Elf32_Rel *)(data.data() + relplt->sh_offset);
    const Elf32_Sym *syms =
        (const Elf32_Sym *)(data.data() + dynsym->sh_offset);

    size_t sym_count = dynsym->sh_size / sizeof(Elf32_Sym);
    for (size_t i = 0; i < rel_count; i++) {
      uint32_t sym_idx = ELF32_R_SYM(rels[i].r_info);
      uint32_t type = ELF32_R_TYPE(rels[i].r_info);

      if (type == R_ARM_JUMP_SLOT) {
        ElfParser::PltEntry e;
        e.offset = rels[i].r_offset;
        e.got_offset = rels[i].r_offset;
        e.symbol_index = sym_idx;

        if (sym_idx > 0 && sym_idx < sym_count) {
          uint32_t str_off = syms[sym_idx].st_name;
          if (str_off < dynstr->sh_size)
            e.symbol_name = get_string_at(data, dynstr->sh_offset + str_off);
        }
        entries.push_back(e);
      }
    }
  }
  return entries;
}

std::string ElfParser::demangle_symbol(const std::string &mangled) {
  if (mangled.empty())
    return mangled;

  if (mangled.find("_GLOBAL__") == 0) {
    if (mangled.find("_GLOBAL__I_") == 0)
      return "[global constructor] " + mangled.substr(11);
    if (mangled.find("_GLOBAL__D_") == 0)
      return "[global destructor] " + mangled.substr(11);
    if (mangled.find("_GLOBAL__sub_I_") == 0)
      return "[static init] " + mangled.substr(15);
    return mangled;
  }

  if (mangled.find("_ZGV") == 0) {
    std::string inner = demangle_symbol("_Z" + mangled.substr(4));
    return "[guard variable] " + inner;
  }

  if (mangled.find("_ZTV") == 0) {
    std::string inner = demangle_symbol("_Z" + mangled.substr(4));
    return "[vtable] " + inner;
  }

  if (mangled.find("_ZTI") == 0) {
    std::string inner = demangle_symbol("_Z" + mangled.substr(4));
    return "[typeinfo] " + inner;
  }

  if (mangled.find("_ZTS") == 0) {
    std::string inner = demangle_symbol("_Z" + mangled.substr(4));
    return "[typeinfo name] " + inner;
  }

  if (mangled.find("_ZTh") == 0 || mangled.find("_ZTv") == 0) {
    size_t pos = 4;
    while (pos < mangled.size() && (isdigit(mangled[pos]) ||
                                    mangled[pos] == 'n' || mangled[pos] == '_'))
      pos++;
    if (pos < mangled.size()) {
      std::string inner = demangle_symbol("_Z" + mangled.substr(pos));
      return "[virtual thunk] " + inner;
    }
  }

  if (mangled.find("_ZTc") == 0) {
    return "[covariant thunk] " + mangled;
  }

  if (mangled[0] != '_')
    return mangled;
  if (mangled.size() < 3 || mangled[1] != 'Z')
    return mangled;

  std::string result;
  size_t pos = 2;
  bool is_nested = false;
  bool is_const_method = false;
  bool is_volatile_method = false;
  std::vector<std::string> components;

  while (pos < mangled.size()) {
    if (mangled[pos] == 'K') {
      is_const_method = true;
      pos++;
    } else if (mangled[pos] == 'V') {
      is_volatile_method = true;
      pos++;
    } else {
      break;
    }
  }

  if (pos < mangled.size() && mangled[pos] == 'N') {
    is_nested = true;
    pos++;
    while (
        pos < mangled.size() &&
        (mangled[pos] == 'K' || mangled[pos] == 'V' || mangled[pos] == 'r')) {
      if (mangled[pos] == 'K')
        is_const_method = true;
      pos++;
    }
  }

  auto parse_operator = [](const std::string &m, size_t &p) -> std::string {
    if (p + 2 > m.size())
      return "";
    std::string op = m.substr(p, 2);
    p += 2;
    if (op == "nw")
      return "operator new";
    if (op == "na")
      return "operator new[]";
    if (op == "dl")
      return "operator delete";
    if (op == "da")
      return "operator delete[]";
    if (op == "ps")
      return "operator+";
    if (op == "ng")
      return "operator-";
    if (op == "ad")
      return "operator&";
    if (op == "de")
      return "operator*";
    if (op == "co")
      return "operator~";
    if (op == "pl")
      return "operator+";
    if (op == "mi")
      return "operator-";
    if (op == "ml")
      return "operator*";
    if (op == "dv")
      return "operator/";
    if (op == "rm")
      return "operator%";
    if (op == "an")
      return "operator&";
    if (op == "or")
      return "operator|";
    if (op == "eo")
      return "operator^";
    if (op == "aS")
      return "operator=";
    if (op == "pL")
      return "operator+=";
    if (op == "mI")
      return "operator-=";
    if (op == "mL")
      return "operator*=";
    if (op == "dV")
      return "operator/=";
    if (op == "rM")
      return "operator%=";
    if (op == "aN")
      return "operator&=";
    if (op == "oR")
      return "operator|=";
    if (op == "eO")
      return "operator^=";
    if (op == "ls")
      return "operator<<";
    if (op == "rs")
      return "operator>>";
    if (op == "lS")
      return "operator<<=";
    if (op == "rS")
      return "operator>>=";
    if (op == "eq")
      return "operator==";
    if (op == "ne")
      return "operator!=";
    if (op == "lt")
      return "operator<";
    if (op == "gt")
      return "operator>";
    if (op == "le")
      return "operator<=";
    if (op == "ge")
      return "operator>=";
    if (op == "ss")
      return "operator<=>";
    if (op == "nt")
      return "operator!";
    if (op == "aa")
      return "operator&&";
    if (op == "oo")
      return "operator||";
    if (op == "pp")
      return "operator++";
    if (op == "mm")
      return "operator--";
    if (op == "cm")
      return "operator,";
    if (op == "pm")
      return "operator->*";
    if (op == "pt")
      return "operator->";
    if (op == "cl")
      return "operator()";
    if (op == "ix")
      return "operator[]";
    if (op == "qu")
      return "operator?";
    if (op == "cv")
      return "operator (type)";
    if (op == "li")
      return "operator \"\"";
    p -= 2;
    return "";
  };

  std::function<std::string(void)> parse_name = [&]() -> std::string {
    if (pos >= mangled.size())
      return "";

    if (mangled[pos] == 'C' && pos + 1 < mangled.size() &&
        isdigit(mangled[pos + 1])) {
      pos += 2;
      if (!components.empty())
        return components.back();
      return "[constructor]";
    }

    if (mangled[pos] == 'D' && pos + 1 < mangled.size() &&
        isdigit(mangled[pos + 1])) {
      pos += 2;
      if (!components.empty())
        return "~" + components.back();
      return "[destructor]";
    }

    if (pos + 2 <= mangled.size()) {
      std::string op = parse_operator(mangled, pos);
      if (!op.empty())
        return op;
    }

    if (mangled[pos] == 'S') {
      pos++;
      if (pos < mangled.size()) {
        char c = mangled[pos];
        if (c == 't') {
          pos++;
          return "std";
        }
        if (c == 'a') {
          pos++;
          return "std::allocator";
        }
        if (c == 'b') {
          pos++;
          return "std::basic_string";
        }
        if (c == 's') {
          pos++;
          return "std::string";
        }
        if (c == 'i') {
          pos++;
          return "std::istream";
        }
        if (c == 'o') {
          pos++;
          return "std::ostream";
        }
        if (c == 'd') {
          pos++;
          return "std::iostream";
        }
        if (c == '_') {
          pos++;
          return "[subst]";
        }
        if (isdigit(c) || isupper(c)) {
          while (pos < mangled.size() && mangled[pos] != '_')
            pos++;
          if (pos < mangled.size())
            pos++;
          return "[subst]";
        }
      }
      return "";
    }

    if (!isdigit(mangled[pos]))
      return "";

    size_t len = 0;
    while (pos < mangled.size() && isdigit(mangled[pos])) {
      len = len * 10 + (mangled[pos] - '0');
      pos++;
    }

    if (pos + len > mangled.size())
      return "";

    std::string name = mangled.substr(pos, len);
    pos += len;

    if (pos < mangled.size() && mangled[pos] == 'I') {
      pos++;
      std::string targs;
      int depth = 1;
      while (pos < mangled.size() && depth > 0) {
        if (mangled[pos] == 'I')
          depth++;
        else if (mangled[pos] == 'E')
          depth--;
        if (depth > 0) {
          char c = mangled[pos];
          if (c == 'i') {
            targs += targs.empty() ? "int" : ", int";
            pos++;
          } else if (c == 'f') {
            targs += targs.empty() ? "float" : ", float";
            pos++;
          } else if (c == 'd') {
            targs += targs.empty() ? "double" : ", double";
            pos++;
          } else if (c == 'b') {
            targs += targs.empty() ? "bool" : ", bool";
            pos++;
          } else if (c == 'c') {
            targs += targs.empty() ? "char" : ", char";
            pos++;
          } else if (c == 'v') {
            pos++;
          } else if (c == 'P' || c == 'R' || c == 'K') {
            pos++;
          } else if (isdigit(c)) {
            size_t tlen = 0;
            while (pos < mangled.size() && isdigit(mangled[pos])) {
              tlen = tlen * 10 + (mangled[pos] - '0');
              pos++;
            }
            if (pos + tlen <= mangled.size()) {
              std::string tname = mangled.substr(pos, tlen);
              targs += targs.empty() ? tname : ", " + tname;
              pos += tlen;
            }
          } else {
            pos++;
          }
        }
      }
      if (pos < mangled.size() && mangled[pos] == 'E')
        pos++;
      if (!targs.empty())
        name += "<" + targs + ">";
      else
        name += "<...>";
    }

    return name;
  };

  while (pos < mangled.size()) {
    if (mangled[pos] == 'E') {
      pos++;
      break;
    }
    if (!isdigit(mangled[pos]) && mangled[pos] != 'C' && mangled[pos] != 'D' &&
        mangled[pos] != 'S' &&
        !(pos + 2 <= mangled.size() && islower(mangled[pos]) &&
          islower(mangled[pos + 1]))) {
      break;
    }
    std::string comp = parse_name();
    if (comp.empty())
      break;
    if (comp != "[subst]")
      components.push_back(comp);
  }

  for (size_t i = 0; i < components.size(); i++) {
    if (i > 0)
      result += "::";
    result += components[i];
  }

  std::string params;
  auto parse_type = [&]() -> std::string {
    if (pos >= mangled.size())
      return "";
    std::string prefix;
    while (pos < mangled.size()) {
      char c = mangled[pos];
      if (c == 'P') {
        prefix += "*";
        pos++;
      } else if (c == 'R') {
        prefix += "&";
        pos++;
      } else if (c == 'O') {
        prefix += "&&";
        pos++;
      } else if (c == 'K') {
        prefix = "const " + prefix;
        pos++;
      } else if (c == 'V') {
        prefix = "volatile " + prefix;
        pos++;
      } else if (c == 'r') {
        prefix = "restrict " + prefix;
        pos++;
      } else
        break;
    }
    if (pos >= mangled.size())
      return prefix;
    char c = mangled[pos++];
    std::string base;
    switch (c) {
    case 'v':
      base = "void";
      break;
    case 'w':
      base = "wchar_t";
      break;
    case 'b':
      base = "bool";
      break;
    case 'c':
      base = "char";
      break;
    case 'a':
      base = "signed char";
      break;
    case 'h':
      base = "unsigned char";
      break;
    case 's':
      base = "short";
      break;
    case 't':
      base = "unsigned short";
      break;
    case 'i':
      base = "int";
      break;
    case 'j':
      base = "unsigned int";
      break;
    case 'l':
      base = "long";
      break;
    case 'm':
      base = "unsigned long";
      break;
    case 'x':
      base = "long long";
      break;
    case 'y':
      base = "unsigned long long";
      break;
    case 'n':
      base = "__int128";
      break;
    case 'o':
      base = "unsigned __int128";
      break;
    case 'f':
      base = "float";
      break;
    case 'd':
      base = "double";
      break;
    case 'e':
      base = "long double";
      break;
    case 'g':
      base = "__float128";
      break;
    case 'z':
      base = "...";
      break;
    case 'D':
      if (pos < mangled.size()) {
        char d = mangled[pos++];
        if (d == 'n')
          base = "decltype(nullptr)";
        else if (d == 'a')
          base = "auto";
        else if (d == 'c')
          base = "decltype(auto)";
        else if (d == 'i')
          base = "char32_t";
        else if (d == 's')
          base = "char16_t";
        else if (d == 'u')
          base = "char8_t";
        else
          base = "D" + std::string(1, d);
      }
      break;
    case 'u': {
      if (pos < mangled.size() && isdigit(mangled[pos])) {
        size_t len = 0;
        while (pos < mangled.size() && isdigit(mangled[pos])) {
          len = len * 10 + (mangled[pos] - '0');
          pos++;
        }
        if (pos + len <= mangled.size()) {
          base = mangled.substr(pos, len);
          pos += len;
        }
      }
      break;
    }
    default:
      if (isdigit(c)) {
        pos--;
        size_t len = 0;
        while (pos < mangled.size() && isdigit(mangled[pos])) {
          len = len * 10 + (mangled[pos] - '0');
          pos++;
        }
        if (pos + len <= mangled.size()) {
          base = mangled.substr(pos, len);
          pos += len;
        }
      } else {
        base = std::string(1, c);
      }
      break;
    }
    return prefix.empty() ? base : base + " " + prefix;
  };

  while (pos < mangled.size() && mangled[pos] != 'E') {
    std::string ptype = parse_type();
    if (ptype.empty())
      break;
    if (ptype == "void" && params.empty())
      break;
    params += params.empty() ? ptype : ", " + ptype;
  }

  if (!result.empty()) {
    result += "(" + params + ")";
    if (is_const_method)
      result += " const";
    if (is_volatile_method)
      result += " volatile";
  }

  return result.empty() ? mangled : result;
}

bool ElfParser::is_objc_method(const std::string &symbol) {
  if (symbol.size() < 4)
    return false;
  if (symbol[0] == '-' || symbol[0] == '+') {
    if (symbol[1] == '[')
      return true;
  }
  if (symbol.find("_OBJC_") == 0)
    return true;
  if (symbol.find("objc_") == 0)
    return true;
  return false;
}

std::pair<std::string, std::string>
ElfParser::parse_objc_method(const std::string &sym) {
  if (sym.size() < 5)
    return {"", ""};
  if ((sym[0] == '-' || sym[0] == '+') && sym[1] == '[') {
    size_t space = sym.find(' ', 2);
    if (space != std::string::npos) {
      std::string cls = sym.substr(2, space - 2);
      size_t end = sym.find(']', space);
      if (end != std::string::npos) {
        std::string method = sym.substr(space + 1, end - space - 1);
        return {cls, method};
      }
    }
  }
  return {"", ""};
}

std::vector<std::string>
ElfParser::find_encrypted_strings(const std::vector<uint8_t> &data) {
  std::vector<std::string> results;

  for (size_t i = 0; i + 16 < data.size(); i++) {
    bool high_entropy = true;
    int printable = 0;
    for (size_t j = 0; j < 16; j++) {
      uint8_t b = data[i + j];
      if (b >= 0x20 && b <= 0x7E)
        printable++;
    }

    if (printable >= 12)
      continue;

    for (uint8_t key = 1; key < 255; key++) {
      std::string decoded;
      bool valid = true;
      for (size_t j = 0; j < 16 && valid; j++) {
        char c = data[i + j] ^ key;
        if (c >= 0x20 && c <= 0x7E)
          decoded += c;
        else if (c == 0)
          break;
        else
          valid = false;
      }
      if (valid && decoded.size() >= 4) {
        results.push_back("XOR(" + std::to_string(key) + "): " + decoded);
        break;
      }
    }
  }
  return results;
}

static uint64_t find_dynamic_entry(const std::vector<uint8_t> &data,
                                   int64_t tag, bool is32) {
  if (is32) {
    const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data.data();
    const Elf32_Phdr *phdrs = (const Elf32_Phdr *)(data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdrs[i].p_type == PT_DYNAMIC) {
        const Elf32_Dyn *dyn =
            (const Elf32_Dyn *)(data.data() + phdrs[i].p_offset);
        while (dyn->d_tag != DT_NULL) {
          if (dyn->d_tag == tag)
            return dyn->d_un.d_val;
          dyn++;
        }
      }
    }
  } else {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data.data();
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdrs[i].p_type == PT_DYNAMIC) {
        const Elf64_Dyn *dyn =
            (const Elf64_Dyn *)(data.data() + phdrs[i].p_offset);
        while (dyn->d_tag != DT_NULL) {
          if (dyn->d_tag == tag)
            return dyn->d_un.d_val;
          dyn++;
        }
      }
    }
  }
  return 0;
}

bool ElfParser::has_relro(const std::vector<uint8_t> &data) {
  if (data.size() < sizeof(Elf64_Ehdr))
    return false;
  bool is32 = is_elf32(data);

  if (is32) {
    const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data.data();
    const Elf32_Phdr *phdrs = (const Elf32_Phdr *)(data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdrs[i].p_type == 0x6474E552)
        return true;
    }
  } else {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data.data();
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdrs[i].p_type == 0x6474E552)
        return true;
    }
  }
  return false;
}

bool ElfParser::has_full_relro(const std::vector<uint8_t> &data) {
  if (!has_relro(data))
    return false;
  uint64_t flags = find_dynamic_entry(data, DT_FLAGS, is_elf32(data));
  return (flags & 0x8) != 0;
}

std::pair<uint64_t, uint64_t>
ElfParser::get_tls_range(const std::vector<uint8_t> &data) {
  if (data.size() < sizeof(Elf64_Ehdr))
    return {0, 0};
  bool is32 = is_elf32(data);

  if (is32) {
    const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data.data();
    const Elf32_Phdr *phdrs = (const Elf32_Phdr *)(data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdrs[i].p_type == PT_TLS) {
        return {phdrs[i].p_vaddr, phdrs[i].p_memsz};
      }
    }
  } else {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data.data();
    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      if (phdrs[i].p_type == PT_TLS) {
        return {phdrs[i].p_vaddr, phdrs[i].p_memsz};
      }
    }
  }
  return {0, 0};
}

std::vector<uint64_t>
ElfParser::get_init_array(const std::vector<uint8_t> &data) {
  std::vector<uint64_t> funcs;
  bool is32 = is_elf32(data);

  uint64_t init_arr = find_dynamic_entry(data, 25, is32);
  uint64_t init_sz = find_dynamic_entry(data, 27, is32);

  if (init_arr == 0 || init_sz == 0)
    return funcs;

  if (is32) {
    size_t count = init_sz / 4;
    if (init_arr < data.size()) {
      const uint32_t *arr = (const uint32_t *)(data.data() + init_arr);
      for (size_t i = 0; i < count && init_arr + i * 4 < data.size(); i++) {
        if (arr[i] != 0)
          funcs.push_back(arr[i]);
      }
    }
  } else {
    size_t count = init_sz / 8;
    if (init_arr < data.size()) {
      const uint64_t *arr = (const uint64_t *)(data.data() + init_arr);
      for (size_t i = 0; i < count && init_arr + i * 8 < data.size(); i++) {
        if (arr[i] != 0)
          funcs.push_back(arr[i]);
      }
    }
  }
  return funcs;
}

std::vector<uint64_t>
ElfParser::get_fini_array(const std::vector<uint8_t> &data) {
  std::vector<uint64_t> funcs;
  bool is32 = is_elf32(data);

  uint64_t fini_arr = find_dynamic_entry(data, 26, is32);
  uint64_t fini_sz = find_dynamic_entry(data, 28, is32);

  if (fini_arr == 0 || fini_sz == 0)
    return funcs;

  if (is32) {
    size_t count = fini_sz / 4;
    if (fini_arr < data.size()) {
      const uint32_t *arr = (const uint32_t *)(data.data() + fini_arr);
      for (size_t i = 0; i < count && fini_arr + i * 4 < data.size(); i++) {
        if (arr[i] != 0)
          funcs.push_back(arr[i]);
      }
    }
  } else {
    size_t count = fini_sz / 8;
    if (fini_arr < data.size()) {
      const uint64_t *arr = (const uint64_t *)(data.data() + fini_arr);
      for (size_t i = 0; i < count && fini_arr + i * 8 < data.size(); i++) {
        if (arr[i] != 0)
          funcs.push_back(arr[i]);
      }
    }
  }
  return funcs;
}

uint64_t ElfParser::resolve_plt_symbol(int pid,
                                       const std::vector<uint8_t> &data,
                                       const std::string &symbol_name) {
  if (symbol_name.empty())
    return 0;

  auto lib_ranges = ProcessTracer::get_library_ranges(pid);

  for (const auto &r : lib_ranges) {
    if (r.name.empty())
      continue;
    if (r.name.find(".so") == std::string::npos)
      continue;

    std::string lib_base = r.name;
    size_t slash = lib_base.rfind('/');
    if (slash != std::string::npos)
      lib_base = lib_base.substr(slash + 1);

    uint64_t addr =
        FunctionHooker::find_remote_symbol(pid, lib_base, symbol_name);
    if (addr != 0)
      return addr;
  }

  return 0;
}

static bool parse_pattern(const std::string &pattern,
                          std::vector<uint8_t> &bytes,
                          std::vector<bool> &mask) {
  bytes.clear();
  mask.clear();
  std::istringstream iss(pattern);
  std::string token;
  while (iss >> token) {
    if (token == "?" || token == "??" || token == "**") {
      bytes.push_back(0);
      mask.push_back(false);
    } else {
      try {
        uint8_t b = (uint8_t)std::stoul(token, nullptr, 16);
        bytes.push_back(b);
        mask.push_back(true);
      } catch (...) {
        return false;
      }
    }
  }
  return !bytes.empty();
}

std::vector<PatternMatch>
ElfParser::pattern_scan(const std::vector<uint8_t> &data,
                        const std::string &pattern) {
  std::vector<PatternMatch> results;
  std::vector<uint8_t> pat_bytes;
  std::vector<bool> pat_mask;

  if (!parse_pattern(pattern, pat_bytes, pat_mask))
    return results;

  size_t pat_len = pat_bytes.size();
  if (pat_len == 0 || data.size() < pat_len)
    return results;

  for (size_t i = 0; i <= data.size() - pat_len; i++) {
    bool match = true;
    for (size_t j = 0; j < pat_len && match; j++) {
      if (pat_mask[j] && data[i + j] != pat_bytes[j])
        match = false;
    }
    if (match) {
      PatternMatch m;
      m.offset = i;
      m.pattern = pattern;
      size_t ctx_start = (i >= 8) ? i - 8 : 0;
      size_t ctx_end = std::min(i + pat_len + 8, data.size());
      std::ostringstream ctx;
      for (size_t k = ctx_start; k < ctx_end; k++) {
        ctx << std::hex << std::setw(2) << std::setfill('0') << (int)data[k]
            << " ";
      }
      m.context = ctx.str();
      results.push_back(m);
    }
  }
  return results;
}

std::vector<PatternMatch>
ElfParser::pattern_scan_multi(const std::vector<uint8_t> &data,
                              const std::vector<std::string> &patterns) {
  std::vector<PatternMatch> all_results;
  for (const auto &pat : patterns) {
    auto matches = pattern_scan(data, pat);
    all_results.insert(all_results.end(), matches.begin(), matches.end());
  }
  return all_results;
}

std::string ElfParser::generate_signature(const std::vector<uint8_t> &data,
                                          uint64_t offset, size_t length) {
  if (offset + length > data.size())
    length = data.size() - offset;

  std::ostringstream sig;
  bool is32 = is_elf32(data);

  for (size_t i = 0; i < length; i += 4) {
    if (offset + i + 4 > data.size())
      break;

    uint32_t inst = *(uint32_t *)(data.data() + offset + i);

    bool has_addr = false;

    if (!is32) {
      if ((inst & 0x9F000000) == 0x90000000)
        has_addr = true;
      if ((inst & 0xFC000000) == 0x94000000)
        has_addr = true;
      if ((inst & 0xFC000000) == 0x14000000)
        has_addr = true;
    } else {
      if ((inst & 0x0F000000) == 0x0A000000)
        has_addr = true;
      if ((inst & 0x0F000000) == 0x0B000000)
        has_addr = true;
    }

    if (has_addr) {
      sig << "?? ?? ?? ?? ";
    } else {
      for (int j = 0; j < 4; j++) {
        sig << std::hex << std::setw(2) << std::setfill('0')
            << (int)data[offset + i + j] << " ";
      }
    }
  }

  return sig.str();
}

std::vector<RTTIInfo> ElfParser::scan_rtti(const std::vector<uint8_t> &data,
                                           uint64_t base_addr) {
  std::vector<RTTIInfo> results;
  if (data.size() < 64)
    return results;

  bool is32 = is_elf32(data);
  size_t ptr_size = is32 ? 4 : 8;

  auto symbols = get_symbols(data);
  std::map<uint64_t, std::string> typeinfo_map;

  for (const auto &s : symbols) {
    if (s.name.find("_ZTI") == 0) {
      typeinfo_map[s.offset] = s.name;
    }
  }

  for (const auto &s : symbols) {
    if (s.name.find("_ZTV") != 0)
      continue;

    RTTIInfo info;
    info.vtable_addr = base_addr + s.offset;
    info.class_name = s.name;
    info.demangled_name = demangle_symbol(s.name);
    info.base_class_typeinfo = 0;

    if (s.offset >= ptr_size * 2) {
      if (is32) {
        info.typeinfo_addr =
            *(uint32_t *)(data.data() + s.offset - ptr_size * 2);
      } else {
        info.typeinfo_addr =
            *(uint64_t *)(data.data() + s.offset - ptr_size * 2);
      }
    }

    info.virtual_functions = get_vtable_functions(data, s.offset, base_addr);

    results.push_back(info);
  }

  auto strings = get_strings(data, 4);
  std::map<uint64_t, std::string> string_map;
  for (const auto &s : strings) {
    if (!s.value.empty() &&
        (isdigit(s.value[0]) || (isupper(s.value[0]) && isalpha(s.value[1])))) {
      string_map[s.offset] = s.value;
    }
  }

  return results;
}

RTTIInfo ElfParser::find_vtable_by_name(const std::vector<uint8_t> &data,
                                        const std::string &class_name,
                                        uint64_t base_addr) {
  auto all_rtti = scan_rtti(data, base_addr);

  for (const auto &r : all_rtti) {
    if (r.class_name.find(class_name) != std::string::npos ||
        r.demangled_name.find(class_name) != std::string::npos) {
      return r;
    }
  }

  return RTTIInfo{};
}

std::vector<uint64_t>
ElfParser::get_vtable_functions(const std::vector<uint8_t> &data,
                                uint64_t vtable_offset, uint64_t base_addr) {
  std::vector<uint64_t> funcs;
  if (vtable_offset >= data.size())
    return funcs;

  bool is32 = is_elf32(data);
  size_t ptr_size = is32 ? 4 : 8;

  size_t start = vtable_offset;

  for (size_t i = 0; i < 200; i++) {
    size_t off = start + i * ptr_size;
    if (off + ptr_size > data.size())
      break;

    uint64_t func_ptr;
    if (is32) {
      func_ptr = *(uint32_t *)(data.data() + off);
    } else {
      func_ptr = *(uint64_t *)(data.data() + off);
    }

    if (func_ptr == 0)
      break;

    uint64_t relative = func_ptr - base_addr;
    if (relative < data.size()) {
      funcs.push_back(func_ptr);
    } else if (func_ptr < 0x1000) {
      break;
    }
  }

  return funcs;
}

StringXref ElfParser::find_string_xrefs(const std::vector<uint8_t> &data,
                                        const std::string &str,
                                        uint64_t base_addr) {
  StringXref result;
  result.string_value = str;

  for (size_t i = 0; i + str.size() <= data.size(); i++) {
    if (memcmp(data.data() + i, str.c_str(), str.size()) == 0) {
      result.string_offset = i;
      break;
    }
  }

  if (result.string_offset == 0 && str != std::string(1, data[0]))
    return result;

  bool is32 = is_elf32(data);
  uint64_t str_addr = base_addr + result.string_offset;

  if (!is32) {
    for (size_t i = 0; i + 8 <= data.size(); i += 4) {
      uint32_t inst0 = *(uint32_t *)(data.data() + i);
      uint32_t inst1 = *(uint32_t *)(data.data() + i + 4);

      if ((inst0 & 0x9F000000) == 0x90000000) {
        if ((inst1 & 0xFF000000) == 0x91000000) {
          uint8_t rd0 = inst0 & 0x1F;
          uint8_t rd1 = inst1 & 0x1F;
          uint8_t rn1 = (inst1 >> 5) & 0x1F;

          if (rd0 == rn1) {
            int32_t immhi = ((inst0 >> 5) & 0x7FFFF) << 2;
            int32_t immlo = (inst0 >> 29) & 0x3;
            int32_t imm = immhi | immlo;
            if (imm & 0x100000)
              imm |= 0xFFE00000;
            int64_t page_offset = (int64_t)imm << 12;

            uint64_t pc = base_addr + i;
            uint64_t page = (pc & ~0xFFFULL) + page_offset;

            uint32_t add_imm = (inst1 >> 10) & 0xFFF;
            if ((inst1 >> 22) & 1)
              add_imm <<= 12;

            uint64_t target = page + add_imm;

            if (target == str_addr) {
              result.references.push_back(i);
              result.ref_type = "ADRP+ADD";
            }
          }
        }
      }
    }
  } else {
    for (size_t i = 0; i + 4 <= data.size(); i += 4) {
      uint32_t inst = *(uint32_t *)(data.data() + i);

      if ((inst & 0x0F7F0000) == 0x051F0000) {
        uint32_t offset = inst & 0xFFF;
        bool add = (inst >> 23) & 1;
        uint64_t pc = base_addr + i + 8;

        uint64_t target = add ? (pc + offset) : (pc - offset);
        if (target >= base_addr && target - base_addr + 4 <= data.size()) {
          uint32_t ptr_val = *(uint32_t *)(data.data() + target - base_addr);
          if (ptr_val == str_addr) {
            result.references.push_back(i);
            result.ref_type = "LDR";
          }
        }
      }
    }
  }

  return result;
}

std::vector<StringXref>
ElfParser::find_string_xrefs_pattern(const std::vector<uint8_t> &data,
                                     const std::string &pattern,
                                     uint64_t base_addr) {
  std::vector<StringXref> results;

  auto strings = get_strings(data, 4);
  for (const auto &s : strings) {
    bool match = false;
    if (pattern.find('*') != std::string::npos) {
      if (pattern[0] == '*') {
        match = s.value.find(pattern.substr(1)) != std::string::npos;
      } else if (pattern.back() == '*') {
        match = s.value.find(pattern.substr(0, pattern.size() - 1)) == 0;
      } else {
        match = s.value.find(pattern) != std::string::npos;
      }
    } else {
      match = s.value == pattern;
    }

    if (match) {
      auto xref = find_string_xrefs(data, s.value, base_addr);
      if (!xref.references.empty()) {
        results.push_back(xref);
      }
    }
  }

  return results;
}

std::map<uint64_t, std::vector<uint64_t>>
ElfParser::build_string_xref_map(const std::vector<uint8_t> &data,
                                 uint64_t base_addr) {
  std::map<uint64_t, std::vector<uint64_t>> xref_map;

  auto strings = get_strings(data, 6);
  for (const auto &s : strings) {
    auto xref = find_string_xrefs(data, s.value, base_addr);
    if (!xref.references.empty()) {
      xref_map[s.offset] = xref.references;
    }
  }

  return xref_map;
}

std::vector<DecryptResult>
ElfParser::try_decrypt(const std::vector<uint8_t> &data, uint64_t offset,
                       size_t length) {
  std::vector<DecryptResult> results;

  if (offset + length > data.size())
    return results;

  std::vector<uint8_t> encrypted(data.begin() + offset,
                                 data.begin() + offset + length);

  
  auto calc_printable_ratio = [](const std::vector<uint8_t> &buf) -> double {
    if (buf.empty())
      return 0.0;
    int printable = 0;
    for (uint8_t b : buf) {
      if ((b >= 0x20 && b <= 0x7E) || b == 0 || b == '\n' || b == '\r' ||
          b == '\t')
        printable++;
    }
    return (double)printable / buf.size();
  };

  
  auto has_known_patterns = [](const std::vector<uint8_t> &buf) -> bool {
    std::string s(buf.begin(), buf.end());
    
    if (s.find("http") != std::string::npos)
      return true;
    if (s.find("android") != std::string::npos)
      return true;
    if (s.find("java/") != std::string::npos)
      return true;
    if (s.find("com/") != std::string::npos)
      return true;
    if (s.find(".json") != std::string::npos)
      return true;
    if (s.find(".xml") != std::string::npos)
      return true;
    if (s.find("api") != std::string::npos)
      return true;
    if (s.find("key") != std::string::npos)
      return true;
    if (s.find("token") != std::string::npos)
      return true;
    return false;
  };

  
  auto is_base64_char = [](uint8_t c) -> bool {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
  };

  int base64_count = 0;
  for (uint8_t b : encrypted) {
    if (is_base64_char(b))
      base64_count++;
  }

  if (base64_count > (int)(length * 0.9) && length >= 4) {
    
    static const uint8_t b64_table[256] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, 52, 53, 54, 55, 56, 57,
        58, 59, 60, 61, 64, 64, 64, 64, 64, 64, 64, 0,  1,  2,  3,  4,  5,  6,
        7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 64, 64, 64, 64, 64, 64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64};

    std::vector<uint8_t> decoded;
    decoded.reserve(length * 3 / 4);
    uint32_t accum = 0;
    int bits = 0;
    for (uint8_t c : encrypted) {
      if (c == '=')
        break;
      uint8_t v = b64_table[c];
      if (v == 64)
        continue;
      accum = (accum << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        decoded.push_back((accum >> bits) & 0xFF);
      }
    }

    if (!decoded.empty() && calc_printable_ratio(decoded) > 0.7) {
      DecryptResult r;
      r.offset = offset;
      r.original = encrypted;
      r.decrypted = decoded;
      r.method = "BASE64";
      r.key_size = 0;
      results.push_back(r);
    }
  }

  
  for (uint8_t key = 1; key < 255; key++) {
    std::vector<uint8_t> decrypted = encrypted;
    for (auto &b : decrypted)
      b ^= key;

    double ratio = calc_printable_ratio(decrypted);
    bool has_patterns = has_known_patterns(decrypted);

    if (ratio > 0.8 || (ratio > 0.6 && has_patterns)) {
      DecryptResult r;
      r.offset = offset;
      r.original = encrypted;
      r.decrypted = decrypted;
      r.method = "XOR-BYTE";
      r.key_or_info[0] = key;
      r.key_size = 1;
      results.push_back(r);
      break;
    }
  }

  
  if (length >= 16 && results.empty()) {
    
    std::map<int, int> distance_counts;
    for (size_t win = 3; win <= 5; win++) {
      for (size_t i = 0; i + win < length; i++) {
        for (size_t j = i + win; j + win <= length; j++) {
          if (memcmp(encrypted.data() + i, encrypted.data() + j, win) == 0) {
            int dist = j - i;
            for (int d = 2; d <= 16; d++) {
              if (dist % d == 0)
                distance_counts[d]++;
            }
          }
        }
      }
    }

    
    std::vector<int> key_lengths = {4, 8, 16, 2, 3, 6};
    for (auto &[len, count] : distance_counts) {
      if (count > 2 && len >= 2 && len <= 16) {
        bool found = false;
        for (int kl : key_lengths)
          if (kl == len)
            found = true;
        if (!found)
          key_lengths.push_back(len);
      }
    }

    for (int key_len : key_lengths) {
      if (key_len > (int)length / 2)
        continue;

      
      std::vector<uint8_t> key(key_len, 0);
      bool key_found = true;

      for (int k = 0; k < key_len; k++) {
        std::vector<int> freq(256, 0);
        for (size_t i = k; i < length; i += key_len) {
          freq[encrypted[i]]++;
        }

        
        int max_idx = 0;
        for (int i = 0; i < 256; i++) {
          if (freq[i] > freq[max_idx])
            max_idx = i;
        }

        
        uint8_t best_key = 0;
        double best_ratio = 0;
        for (uint8_t common : {' ', 'e', 'a', 't', 'o', '\0'}) {
          uint8_t try_key = max_idx ^ common;
          std::vector<uint8_t> test;
          for (size_t i = k; i < length; i += key_len) {
            test.push_back(encrypted[i] ^ try_key);
          }
          double ratio = calc_printable_ratio(test);
          if (ratio > best_ratio) {
            best_ratio = ratio;
            best_key = try_key;
          }
        }

        if (best_ratio < 0.5) {
          key_found = false;
          break;
        }
        key[k] = best_key;
      }

      if (key_found) {
        std::vector<uint8_t> decrypted = encrypted;
        for (size_t i = 0; i < length; i++) {
          decrypted[i] ^= key[i % key_len];
        }

        double ratio = calc_printable_ratio(decrypted);
        if (ratio > 0.7 || (ratio > 0.5 && has_known_patterns(decrypted))) {
          DecryptResult r;
          r.offset = offset;
          r.original = encrypted;
          r.decrypted = decrypted;
          r.method = "XOR-MULTI-" + std::to_string(key_len);
          memcpy(r.key_or_info, key.data(), std::min(key.size(), (size_t)32));
          r.key_size = key_len;
          results.push_back(r);
          break;
        }
      }
    }
  }

  
  if (length >= 4 && results.empty()) {
    for (uint32_t key = 0x01010101; key < 0x10101010; key += 0x01010101) {
      std::vector<uint8_t> decrypted = encrypted;
      for (size_t i = 0; i + 4 <= decrypted.size(); i += 4) {
        *(uint32_t *)(decrypted.data() + i) ^= key;
      }

      double ratio = calc_printable_ratio(decrypted);
      if (ratio > 0.8 || (ratio > 0.6 && has_known_patterns(decrypted))) {
        DecryptResult r;
        r.offset = offset;
        r.original = encrypted;
        r.decrypted = decrypted;
        r.method = "XOR-DWORD";
        *(uint32_t *)r.key_or_info = key;
        r.key_size = 4;
        results.push_back(r);
        break;
      }
    }
  }

  
  if (results.empty()) {
    for (int delta = -128; delta <= 127; delta++) {
      if (delta == 0)
        continue;
      std::vector<uint8_t> decrypted = encrypted;
      for (auto &b : decrypted)
        b = (uint8_t)(b + delta);

      double ratio = calc_printable_ratio(decrypted);
      if (ratio > 0.8 || (ratio > 0.6 && has_known_patterns(decrypted))) {
        DecryptResult r;
        r.offset = offset;
        r.original = encrypted;
        r.decrypted = decrypted;
        r.method = (delta > 0) ? "ADD" : "SUB";
        r.key_or_info[0] = (uint8_t)std::abs(delta);
        r.key_size = 1;
        results.push_back(r);
        break;
      }
    }
  }

  return results;
}

std::vector<uint8_t> ElfParser::decrypt_xor(const std::vector<uint8_t> &data,
                                            const std::vector<uint8_t> &key) {
  if (key.empty())
    return data;
  std::vector<uint8_t> result = data;
  for (size_t i = 0; i < result.size(); i++) {
    result[i] ^= key[i % key.size()];
  }
  return result;
}

std::vector<uint8_t> ElfParser::decrypt_rc4(const std::vector<uint8_t> &data,
                                            const std::vector<uint8_t> &key) {
  if (key.empty())
    return data;

  uint8_t S[256];
  for (int i = 0; i < 256; i++)
    S[i] = i;

  int j = 0;
  for (int i = 0; i < 256; i++) {
    j = (j + S[i] + key[i % key.size()]) & 0xFF;
    std::swap(S[i], S[j]);
  }

  std::vector<uint8_t> result = data;
  int i = 0;
  j = 0;
  for (size_t k = 0; k < result.size(); k++) {
    i = (i + 1) & 0xFF;
    j = (j + S[i]) & 0xFF;
    std::swap(S[i], S[j]);
    result[k] ^= S[(S[i] + S[j]) & 0xFF];
  }

  return result;
}

std::vector<DecryptResult>
ElfParser::auto_decrypt_strings(const std::vector<uint8_t> &data) {
  std::vector<DecryptResult> results;

  for (size_t i = 0; i + 16 < data.size(); i++) {
    int printable = 0;
    bool all_zero = true;
    for (size_t j = 0; j < 16; j++) {
      if (data[i + j] >= 0x20 && data[i + j] <= 0x7E)
        printable++;
      if (data[i + j] != 0)
        all_zero = false;
    }

    if (printable >= 12 || all_zero)
      continue;

    auto decrypted = try_decrypt(data, i, 64);
    if (!decrypted.empty()) {
      results.insert(results.end(), decrypted.begin(), decrypted.end());
      i += 64;
    }
  }

  return results;
}

std::vector<uint8_t>
ElfParser::find_encryption_key(const std::vector<uint8_t> &data) {
  auto init_funcs = get_init_array(data);

  std::vector<uint8_t> potential_key;

  for (uint64_t func_addr : init_funcs) {
    if (func_addr >= data.size())
      continue;

    for (size_t i = 0; i < 64 && func_addr + i + 4 <= data.size(); i += 4) {
      uint32_t inst = *(uint32_t *)(data.data() + func_addr + i);

      if ((inst & 0x7F800000) == 0x52800000) {
        uint16_t imm = (inst >> 5) & 0xFFFF;
        if (imm > 0 && imm != 0xFFFF) {
          potential_key.push_back(imm & 0xFF);
          if (potential_key.size() >= 16)
            break;
        }
      }
    }
  }

  return potential_key;
}

std::vector<uint8_t> RuntimeAnalyzer::read_decrypted(int pid, uint64_t addr,
                                                     size_t size) {
  return Memory::dump(pid, addr, size);
}

std::vector<std::pair<uint64_t, size_t>>
RuntimeAnalyzer::find_decrypted_regions(int pid, uint64_t base,
                                        const std::vector<uint8_t> &disk_data) {
  std::vector<std::pair<uint64_t, size_t>> regions;

  auto runtime_data = Memory::dump(pid, base, disk_data.size());
  if (runtime_data.size() != disk_data.size())
    return regions;

  size_t start = 0;
  bool in_diff = false;

  for (size_t i = 0; i < disk_data.size(); i++) {
    bool differs = (runtime_data[i] != disk_data[i]) && (disk_data[i] != 0);

    if (differs && !in_diff) {
      start = i;
      in_diff = true;
    } else if (!differs && in_diff) {
      if (i - start >= 16) {
        regions.push_back({base + start, i - start});
      }
      in_diff = false;
    }
  }

  if (in_diff && disk_data.size() - start >= 16) {
    regions.push_back({base + start, disk_data.size() - start});
  }

  return regions;
}

bool RuntimeAnalyzer::trace_init_array(
    int pid, uint64_t base, const std::vector<uint64_t> &init_funcs) {
  if (!ProcessTracer::attach(pid))
    return false;

  std::map<uint64_t, uint32_t> original_instructions;

  for (uint64_t func : init_funcs) {
    uint32_t orig;
    if (ProcessTracer::read_memory(pid, func, &orig, 4)) {
      original_instructions[func] = orig;
      uint32_t brk = 0xD4200000;
      ProcessTracer::write_memory(pid, func, &brk, 4);
    }
  }

  ProcessTracer::continue_process(pid);

  int status;
  for (int i = 0; i < (int)init_funcs.size() * 2; i++) {
    if (!ProcessTracer::wait_for_stop(pid, &status))
      break;

    uint64_t pc = ProcessTracer::get_pc(pid);

    auto it = original_instructions.find(pc);
    if (it != original_instructions.end()) {
      ProcessTracer::write_memory(pid, pc, &it->second, 4);
    }

    ProcessTracer::continue_process(pid);
  }

  for (const auto &pair : original_instructions) {
    ProcessTracer::write_memory(pid, pair.first, &pair.second, 4);
  }

  ProcessTracer::detach(pid);
  return true;
}

std::vector<uint8_t> RuntimeAnalyzer::dump_after_function(int pid,
                                                          uint64_t func_addr,
                                                          uint64_t target_addr,
                                                          size_t size) {
  if (!ProcessTracer::attach(pid))
    return {};

  uint64_t ret_addr = func_addr;
  for (int i = 0; i < 1000; i++) {
    uint32_t inst;
    if (!ProcessTracer::read_memory(pid, func_addr + i * 4, &inst, 4))
      break;
    if ((inst & 0xFFFFFC1F) == 0xD65F0000) {
      ret_addr = func_addr + i * 4;
      break;
    }
  }

  uint32_t orig;
  ProcessTracer::read_memory(pid, ret_addr, &orig, 4);
  uint32_t brk = 0xD4200000;
  ProcessTracer::write_memory(pid, ret_addr, &brk, 4);

  ProcessTracer::continue_process(pid);

  int status;
  ProcessTracer::wait_for_stop(pid, &status);

  ProcessTracer::write_memory(pid, ret_addr, &orig, 4);

  std::vector<uint8_t> result(size);
  ProcessTracer::read_memory(pid, target_addr, result.data(), size);

  ProcessTracer::detach(pid);
  return result;
}

std::vector<uint64_t>
RuntimeAnalyzer::find_instances_by_vtable(int pid, uint64_t vtable_addr) {
  std::vector<uint64_t> instances;

  auto maps = Memory::get_maps(pid);

  for (const auto &m : maps) {
    if (m.name.find("[heap]") == std::string::npos &&
        m.name.find("[anon:") == std::string::npos)
      continue;

    if (m.perms.find('r') == std::string::npos)
      continue;

    std::vector<uint8_t> region = Memory::dump(pid, m.base, m.size);

    for (size_t i = 0; i + 8 <= region.size(); i += 8) {
      uint64_t ptr = *(uint64_t *)(region.data() + i);
      if (ptr == vtable_addr) {
        instances.push_back(m.base + i);
      }
    }
  }

  return instances;
}

double ElfParser::calculate_entropy(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0.0;

  size_t freq[256] = {0};
  for (size_t i = 0; i < size; i++) {
    freq[data[i]]++;
  }

  double entropy = 0.0;
  for (int i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      double p = (double)freq[i] / size;
      entropy -= p * log2(p);
    }
  }

  return entropy;
}

std::vector<EntropyInfo>
ElfParser::find_high_entropy_regions(const std::vector<uint8_t> &data,
                                     size_t block_size, double threshold) {
  std::vector<EntropyInfo> results;

  if (data.size() < block_size)
    return results;

  size_t step = block_size / 2;
  uint64_t region_start = 0;
  bool in_high_entropy = false;
  double max_entropy = 0;

  for (size_t i = 0; i + block_size <= data.size(); i += step) {
    double entropy = calculate_entropy(data.data() + i, block_size);

    if (entropy >= threshold) {
      if (!in_high_entropy) {
        region_start = i;
        in_high_entropy = true;
        max_entropy = entropy;
      } else {
        max_entropy = std::max(max_entropy, entropy);
      }
    } else if (in_high_entropy) {
      EntropyInfo info;
      info.offset = region_start;
      info.size = i - region_start;
      info.entropy = max_entropy;
      info.likely_encrypted = (max_entropy > 7.5);
      info.likely_compressed = (max_entropy > 7.0 && max_entropy <= 7.5);
      results.push_back(info);
      in_high_entropy = false;
    }
  }

  if (in_high_entropy) {
    EntropyInfo info;
    info.offset = region_start;
    info.size = data.size() - region_start;
    info.entropy = max_entropy;
    info.likely_encrypted = (max_entropy > 7.5);
    info.likely_compressed = (max_entropy > 7.0 && max_entropy <= 7.5);
    results.push_back(info);
  }

  return results;
}

static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

static const uint8_t AES_RCON[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10,
                                     0x20, 0x40, 0x80, 0x1b, 0x36};

std::vector<AESKeyInfo>
ElfParser::detect_aes_keys(const std::vector<uint8_t> &data) {
  std::vector<AESKeyInfo> results;

  for (size_t i = 0; i + 256 <= data.size(); i++) {
    int sbox_match = 0;
    for (int j = 0; j < 256; j++) {
      if (data[i + j] == AES_SBOX[j])
        sbox_match++;
    }
    if (sbox_match >= 250) {
      AESKeyInfo info;
      info.offset = i;
      info.key_size = 0;
      info.detection_method = "S-BOX";
      info.confidence = (double)sbox_match / 256.0;
      results.push_back(info);
      i += 255;
      continue;
    }
  }

  for (size_t i = 0; i + 176 <= data.size(); i += 4) {
    bool valid_schedule = true;
    int rcon_matches = 0;

    for (int round = 1; round <= 10 && valid_schedule; round++) {
      size_t prev_key = i + (round - 1) * 16;
      size_t curr_key = i + round * 16;

      if (curr_key + 16 > data.size()) {
        valid_schedule = false;
        break;
      }

      uint8_t temp[4];
      for (int j = 0; j < 4; j++) {
        temp[j] = data[prev_key + 12 + ((j + 1) % 4)];
      }
      for (int j = 0; j < 4; j++) {
        temp[j] = AES_SBOX[temp[j]];
      }
      temp[0] ^= AES_RCON[round];

      uint8_t expected[4];
      for (int j = 0; j < 4; j++) {
        expected[j] = data[prev_key + j] ^ temp[j];
      }

      int match = 0;
      for (int j = 0; j < 4; j++) {
        if (data[curr_key + j] == expected[j])
          match++;
      }
      if (match >= 3)
        rcon_matches++;
    }

    if (rcon_matches >= 8) {
      AESKeyInfo info;
      info.offset = i;
      memcpy(info.key, data.data() + i, 16);
      info.key_size = 16;
      info.detection_method = "KEY-SCHEDULE-128";
      info.confidence = (double)rcon_matches / 10.0;
      results.push_back(info);
    }
  }

  return results;
}

std::vector<HeuristicFunction>
ElfParser::find_functions_stripped(const std::vector<uint8_t> &data,
                                   uint64_t base_addr) {
  std::vector<HeuristicFunction> results;
  bool is32 = is_elf32(data);

  if (!is32) {
    for (size_t i = 0; i + 8 <= data.size(); i += 4) {
      uint32_t inst = *(const uint32_t *)(data.data() + i);

      bool is_stp_prologue = false;
      int stack_size = 0;

      if ((inst & 0xFFC003E0) == 0xA98003E0) {
        is_stp_prologue = true;
        int imm = ((inst >> 15) & 0x7F);
        if (imm & 0x40)
          imm |= 0xFFFFFF80;
        stack_size = -imm * 8;
      }

      if ((inst & 0xFF0003FF) == 0xD10003FF) {
        stack_size = ((inst >> 10) & 0xFFF);
        if (stack_size > 0)
          is_stp_prologue = true;
      }

      if (is_stp_prologue && stack_size >= 16 && stack_size <= 4096) {
        HeuristicFunction func;
        func.start_addr = base_addr + i;
        func.has_prologue = true;
        func.stack_frame_size = stack_size;
        func.has_epilogue = false;

        for (size_t j = i + 4; j < i + 65536 && j + 4 <= data.size(); j += 4) {
          uint32_t inst2 = *(const uint32_t *)(data.data() + j);

          if ((inst2 & 0xFFFFFC1F) == 0xD65F0000) {
            func.end_addr = base_addr + j + 4;
            func.size = func.end_addr - func.start_addr;
            func.has_epilogue = true;
            break;
          }

          if ((inst2 & 0xFFC003E0) == 0xA8C003E0) {
            func.end_addr = base_addr + j + 4;
            func.size = func.end_addr - func.start_addr;
            func.has_epilogue = true;
            break;
          }

          if ((inst2 & 0xFC000000) == 0x94000000) {
            int32_t offset = inst2 & 0x03FFFFFF;
            if (offset & 0x02000000)
              offset |= 0xFC000000;
            uint64_t target = base_addr + j + (int64_t)offset * 4;
            func.call_targets.push_back(target);
          }
        }

        if (func.has_epilogue && func.size >= 16 && func.size <= 1024 * 1024) {
          results.push_back(func);
          i = (func.end_addr - base_addr) - 4;
        }
      }
    }
  } else {
    for (size_t i = 0; i + 4 <= data.size(); i += 4) {
      uint32_t inst = *(const uint32_t *)(data.data() + i);

      bool is_push_prologue = ((inst & 0xFFFF0000) == 0xE92D0000);
      int stack_size = 0;

      if ((inst & 0xFFFFF000) == 0xE24DD000) {
        stack_size = inst & 0xFFF;
        is_push_prologue = true;
      }

      if (is_push_prologue) {
        HeuristicFunction func;
        func.start_addr = base_addr + i;
        func.has_prologue = true;
        func.stack_frame_size = stack_size;
        func.has_epilogue = false;

        for (size_t j = i + 4; j < i + 65536 && j + 4 <= data.size(); j += 4) {
          uint32_t inst2 = *(const uint32_t *)(data.data() + j);

          if ((inst2 & 0x0FFF8000) == 0x08BD8000) {
            func.end_addr = base_addr + j + 4;
            func.size = func.end_addr - func.start_addr;
            func.has_epilogue = true;
            break;
          }

          if ((inst2 & 0x0FFFFFF0) == 0x012FFF10 && (inst2 & 0xF) == 14) {
            func.end_addr = base_addr + j + 4;
            func.size = func.end_addr - func.start_addr;
            func.has_epilogue = true;
            break;
          }

          if ((inst2 & 0x0F000000) == 0x0B000000) {
            int32_t offset = inst2 & 0x00FFFFFF;
            if (offset & 0x00800000)
              offset |= 0xFF000000;
            uint64_t target = base_addr + j + 8 + offset * 4;
            func.call_targets.push_back(target);
          }
        }

        if (func.has_epilogue && func.size >= 8 && func.size <= 1024 * 1024) {
          results.push_back(func);
          i = (func.end_addr - base_addr) - 4;
        }
      }
    }
  }

  return results;
}

std::vector<RTTIInfo>
ElfParser::scan_vtables_stripped(const std::vector<uint8_t> &data,
                                 uint64_t base_addr) {
  std::vector<RTTIInfo> results;
  bool is32 = is_elf32(data);
  size_t ptr_size = is32 ? 4 : 8;

  auto funcs = find_functions_stripped(data, base_addr);
  std::set<uint64_t> func_addrs;
  for (const auto &f : funcs) {
    func_addrs.insert(f.start_addr);
  }

  for (size_t i = ptr_size * 2; i + ptr_size * 4 <= data.size();
       i += ptr_size) {
    int valid_ptrs = 0;
    std::vector<uint64_t> potential_funcs;

    for (int j = 0; j < 20 && i + (j + 1) * ptr_size <= data.size(); j++) {
      uint64_t ptr;
      if (is32) {
        ptr = *(uint32_t *)(data.data() + i + j * ptr_size);
      } else {
        ptr = *(uint64_t *)(data.data() + i + j * ptr_size);
      }

      if (ptr == 0)
        break;

      uint64_t relative = ptr - base_addr;
      if (relative < data.size()) {
        if (func_addrs.count(ptr) || relative % 4 == 0) {
          valid_ptrs++;
          potential_funcs.push_back(ptr);
        }
      } else {
        break;
      }
    }

    if (valid_ptrs >= 3) {
      RTTIInfo info;
      info.vtable_addr = base_addr + i;
      info.virtual_functions = potential_funcs;
      info.class_name = "<unknown_" + std::to_string(i) + ">";
      info.demangled_name = info.class_name;

      if (i >= ptr_size) {
        uint64_t typeinfo_ptr;
        if (is32) {
          typeinfo_ptr = *(uint32_t *)(data.data() + i - ptr_size);
        } else {
          typeinfo_ptr = *(uint64_t *)(data.data() + i - ptr_size);
        }
        info.typeinfo_addr = typeinfo_ptr;
      }

      results.push_back(info);
      i += valid_ptrs * ptr_size - ptr_size;
    }
  }

  return results;
}

std::vector<StringXref>
ElfParser::find_all_string_xrefs(const std::vector<uint8_t> &data,
                                 uint64_t base_addr) {
  std::vector<StringXref> results;
  bool is32 = is_elf32(data);

  auto strings = get_strings(data, 4);
  std::map<uint64_t, std::string> str_map;
  for (const auto &s : strings) {
    str_map[s.offset] = s.value;
  }

  if (!is32) {
    for (size_t i = 0; i + 4 <= data.size(); i += 4) {
      uint32_t inst = *(uint32_t *)(data.data() + i);

      if ((inst & 0x9F000000) == 0x10000000) {
        int32_t immhi = ((inst >> 5) & 0x7FFFF) << 2;
        int32_t immlo = (inst >> 29) & 0x3;
        int32_t imm = immhi | immlo;
        if (imm & 0x100000)
          imm |= 0xFFE00000;

        uint64_t target = base_addr + i + imm;
        uint64_t relative = target - base_addr;

        if (relative < data.size()) {
          auto it = str_map.find(relative);
          if (it != str_map.end()) {
            StringXref xref;
            xref.string_offset = relative;
            xref.string_value = it->second;
            xref.references.push_back(i);
            xref.ref_type = "ADR";
            results.push_back(xref);
          }
        }
      }

      if ((inst & 0xBF000000) == 0x18000000) {
        int32_t imm = ((inst >> 5) & 0x7FFFF) << 2;
        if (imm & 0x100000)
          imm |= 0xFFE00000;

        uint64_t target = base_addr + i + imm;
        uint64_t relative = target - base_addr;

        if (relative < data.size()) {
          auto it = str_map.find(relative);
          if (it != str_map.end()) {
            StringXref xref;
            xref.string_offset = relative;
            xref.string_value = it->second;
            xref.references.push_back(i);
            xref.ref_type = "LDR-LITERAL";
            results.push_back(xref);
          }
        }
      }
    }
  } else {
    for (size_t i = 0; i + 4 <= data.size(); i += 4) {
      uint32_t inst = *(uint32_t *)(data.data() + i);

      if ((inst & 0x0F7F0000) == 0x051F0000) {
        uint32_t offset = inst & 0xFFF;
        bool add = (inst >> 23) & 1;
        uint64_t pc = base_addr + i + 8;
        uint64_t target = add ? (pc + offset) : (pc - offset);
        uint64_t relative = target - base_addr;

        if (relative + 4 <= data.size()) {
          uint32_t ptr_val = *(uint32_t *)(data.data() + relative);
          uint64_t str_rel = ptr_val - base_addr;
          if (str_rel < data.size()) {
            auto it = str_map.find(str_rel);
            if (it != str_map.end()) {
              StringXref xref;
              xref.string_offset = str_rel;
              xref.string_value = it->second;
              xref.references.push_back(i);
              xref.ref_type = "LDR-INDIRECT";
              results.push_back(xref);
            }
          }
        }
      }
    }
  }

  return results;
}
