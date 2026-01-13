#include "memory.h"
#include "tracer.h"
#include <algorithm>
#include <cstring>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <iostream>
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

    for (size_t i = 0; i < rel_count; i++) {
      uint32_t sym_idx = ELF32_R_SYM(rels[i].r_info);
      uint32_t type = ELF32_R_TYPE(rels[i].r_info);

      if (type == R_ARM_JUMP_SLOT) {
        ElfParser::PltEntry e;
        e.offset = rels[i].r_offset;
        e.got_offset = rels[i].r_offset;
        e.symbol_index = sym_idx;

        if (sym_idx > 0) {
          uint32_t str_off = syms[sym_idx].st_name;
          e.symbol_name = get_string_at(data, dynstr->sh_offset + str_off);
        }
        entries.push_back(e);
      }
    }
  }
  return entries;
}

std::string ElfParser::demangle_symbol(const std::string &mangled) {
  if (mangled.empty() || mangled[0] != '_')
    return mangled;
  if (mangled.size() < 3 || mangled[1] != 'Z')
    return mangled;

  std::string result;
  size_t pos = 2;
  bool is_nested = false;

  if (pos < mangled.size() && mangled[pos] == 'N') {
    is_nested = true;
    pos++;
  }

  while (pos < mangled.size()) {
    if (mangled[pos] == 'E')
      break;
    if (!isdigit(mangled[pos]))
      break;

    size_t len = 0;
    while (pos < mangled.size() && isdigit(mangled[pos])) {
      len = len * 10 + (mangled[pos] - '0');
      pos++;
    }

    if (pos + len > mangled.size())
      break;

    if (!result.empty())
      result += "::";
    result += mangled.substr(pos, len);
    pos += len;
  }

  if (pos < mangled.size() && mangled[pos] == 'E')
    pos++;

  std::string params;
  while (pos < mangled.size()) {
    char c = mangled[pos++];
    switch (c) {
    case 'v':
      break;
    case 'i':
      params += params.empty() ? "int" : ", int";
      break;
    case 'f':
      params += params.empty() ? "float" : ", float";
      break;
    case 'd':
      params += params.empty() ? "double" : ", double";
      break;
    case 'b':
      params += params.empty() ? "bool" : ", bool";
      break;
    case 'c':
      params += params.empty() ? "char" : ", char";
      break;
    case 'P':
      params += params.empty() ? "*" : ", *";
      break;
    case 'R':
      params += params.empty() ? "&" : ", &";
      break;
    case 'K':
      break;
    default:
      break;
    }
  }

  if (!result.empty())
    result += "(" + params + ")";
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