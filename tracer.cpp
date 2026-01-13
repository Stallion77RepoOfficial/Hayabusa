#include "tracer.h"
#include <cstring>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <linux/ptrace.h>
#include <set>
#include <signal.h>
#include <sys/mman.h>
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

#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17
#define PTRACE_CONT 7
#define PTRACE_SINGLESTEP 9
#define PTRACE_GETREGSET 0x4204
#define PTRACE_SETREGSET 0x4205
#define NT_PRSTATUS 1

static ArchMode g_arch = ArchMode::ARM64;

struct user_regs_struct_64 {
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
};

struct user_regs_struct_32 {
  uint32_t regs[18];
};

void ProcessTracer::set_arch(ArchMode mode) { g_arch = mode; }
ArchMode ProcessTracer::get_arch() { return g_arch; }

bool ProcessTracer::attach(int pid) {
  if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
    return false;
  int status;
  waitpid(pid, &status, 0);
  return WIFSTOPPED(status);
}

bool ProcessTracer::detach(int pid) {
  return ptrace(PTRACE_DETACH, pid, nullptr, nullptr) >= 0;
}

bool ProcessTracer::read_memory(int pid, uint64_t addr, void *buf, size_t len) {
  struct iovec local = {buf, len};
  struct iovec remote = {(void *)addr, len};
  return process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)len;
}

bool ProcessTracer::write_memory(int pid, uint64_t addr, const void *buf,
                                 size_t len) {
  struct iovec local = {(void *)buf, len};
  struct iovec remote = {(void *)addr, len};
  return process_vm_writev(pid, &local, 1, &remote, 1, 0) == (ssize_t)len;
}

bool ProcessTracer::set_protection(int pid, uint64_t addr, size_t len,
                                   int prot) {
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    regs.regs[0] = addr;
    regs.regs[1] = len;
    regs.regs[2] = prot;
    regs.regs[8] = 226;
    uint64_t pc = regs.pc;
    uint32_t orig_inst;
    read_memory(pid, pc, &orig_inst, 4);
    uint32_t svc_inst = 0xD4000001;
    write_memory(pid, pc, &svc_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
  } else {
    user_regs_struct_32 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    regs.regs[0] = (uint32_t)addr;
    regs.regs[1] = (uint32_t)len;
    regs.regs[2] = (uint32_t)prot;
    regs.regs[7] = 125;
    uint32_t pc = regs.regs[15];
    uint32_t orig_inst;
    read_memory(pid, pc, &orig_inst, 4);
    uint32_t svc_inst = 0xEF000000;
    write_memory(pid, pc, &svc_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
  }
  return true;
}

bool ProcessTracer::single_step(int pid) {
  if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) < 0)
    return false;
  int status;
  waitpid(pid, &status, 0);
  return WIFSTOPPED(status);
}

bool ProcessTracer::continue_process(int pid) {
  return ptrace(PTRACE_CONT, pid, nullptr, nullptr) >= 0;
}

bool ProcessTracer::wait_for_stop(int pid, int *status) {
  return waitpid(pid, status, 0) == pid;
}

uint64_t ProcessTracer::get_pc(int pid) {
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return 0;
    return regs.pc;
  } else {
    user_regs_struct_32 regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return 0;
    return regs.regs[15];
  }
}

uint64_t ProcessTracer::get_register(int pid, int reg) {
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return 0;
    if (reg < 31)
      return regs.regs[reg];
    if (reg == 31)
      return regs.sp;
    if (reg == 32)
      return regs.pc;
    return 0;
  } else {
    user_regs_struct_32 regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return 0;
    if (reg < 18)
      return regs.regs[reg];
    return 0;
  }
}

bool ProcessTracer::set_register(int pid, int reg, uint64_t val) {
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return false;
    if (reg < 31)
      regs.regs[reg] = val;
    else if (reg == 31)
      regs.sp = val;
    else if (reg == 32)
      regs.pc = val;
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) >= 0;
  } else {
    user_regs_struct_32 regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return false;
    if (reg < 18)
      regs.regs[reg] = (uint32_t)val;
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) >= 0;
  }
}

std::vector<uint8_t> ProcessTracer::dump_on_demand(int pid, uint64_t base,
                                                   size_t size,
                                                   int duration_sec) {
  std::vector<uint8_t> result(size, 0);
  std::vector<bool> captured(size / 4096, false);
  if (!attach(pid))
    return result;
  read_memory(pid, base, result.data(), size);
  for (size_t i = 0; i < size / 4096; i++) {
    bool has_data = false;
    for (size_t j = 0; j < 4096 && !has_data; j++) {
      if (result[i * 4096 + j] != 0)
        has_data = true;
    }
    if (!has_data) {
      set_protection(pid, base + i * 4096, 4096, PROT_NONE);
    } else {
      captured[i] = true;
    }
  }
  continue_process(pid);
  time_t start = time(nullptr);
  while (time(nullptr) - start < duration_sec) {
    int status;
    pid_t wpid = waitpid(pid, &status, WNOHANG);
    if (wpid == pid && WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      if (sig == SIGSEGV) {
        uint64_t fault_addr = get_pc(pid);
        size_t page_idx = (fault_addr - base) / 4096;
        if (page_idx < captured.size() && !captured[page_idx]) {
          set_protection(pid, base + page_idx * 4096, 4096,
                         PROT_READ | PROT_EXEC);
          std::vector<uint8_t> page_data(4096);
          read_memory(pid, base + page_idx * 4096, page_data.data(), 4096);
          memcpy(result.data() + page_idx * 4096, page_data.data(), 4096);
          captured[page_idx] = true;
        }
        continue_process(pid);
      } else {
        ptrace(PTRACE_CONT, pid, nullptr, (void *)(long)sig);
      }
    }
    usleep(1000);
  }
  for (size_t i = 0; i < captured.size(); i++) {
    if (!captured[i])
      set_protection(pid, base + i * 4096, 4096, PROT_READ | PROT_EXEC);
  }
  detach(pid);
  return result;
}

std::vector<JITRegion> ProcessTracer::capture_jit(int pid, int duration_sec) {
  std::vector<JITRegion> jit_regions;
  std::map<uint64_t, size_t> known_regions;
  if (!attach(pid))
    return jit_regions;
  continue_process(pid);
  time_t start = time(nullptr);
  while (time(nullptr) - start < duration_sec) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
      if (line.find("[anon:") != std::string::npos &&
          (line.find("jit") != std::string::npos ||
           line.find("JIT") != std::string::npos ||
           line.find("dalvik") != std::string::npos)) {
        uint64_t start_addr, end_addr;
        sscanf(line.c_str(), "%lx-%lx", (unsigned long *)&start_addr,
               (unsigned long *)&end_addr);
        size_t size = end_addr - start_addr;
        if (known_regions.find(start_addr) == known_regions.end() ||
            known_regions[start_addr] != size) {
          known_regions[start_addr] = size;
          JITRegion region;
          region.addr = start_addr;
          region.size = size;
          region.code.resize(size);
          read_memory(pid, start_addr, region.code.data(), size);
          jit_regions.push_back(region);
        }
      }
    }
    usleep(100000);
  }
  detach(pid);
  return jit_regions;
}

uint64_t FunctionHooker::allocate_remote(int pid, size_t size) {
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    regs.regs[0] = 0;
    regs.regs[1] = size;
    regs.regs[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.regs[4] = -1;
    regs.regs[5] = 0;
    regs.regs[8] = 222;
    uint64_t pc = regs.pc;
    uint32_t orig_inst;
    ProcessTracer::read_memory(pid, pc, &orig_inst, 4);
    uint32_t svc_inst = 0xD4000001;
    ProcessTracer::write_memory(pid, pc, &svc_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    uint64_t result = regs.regs[0];
    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    return (result == (uint64_t)-1) ? 0 : result;
  } else {
    user_regs_struct_32 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    regs.regs[0] = 0;
    regs.regs[1] = (uint32_t)size;
    regs.regs[2] = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.regs[3] = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.regs[4] = -1;
    regs.regs[5] = 0;
    regs.regs[7] = 192;
    uint32_t pc = regs.regs[15];
    uint32_t orig_inst;
    ProcessTracer::read_memory(pid, pc, &orig_inst, 4);
    uint32_t svc_inst = 0xEF000000;
    ProcessTracer::write_memory(pid, pc, &svc_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    uint32_t result = regs.regs[0];
    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    return (result == (uint32_t)-1) ? 0 : result;
  }
}

bool FunctionHooker::free_remote(int pid, uint64_t addr, size_t size) {
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    regs.regs[0] = addr;
    regs.regs[1] = size;
    regs.regs[8] = 215;
    uint64_t pc = regs.pc;
    uint32_t orig_inst;
    ProcessTracer::read_memory(pid, pc, &orig_inst, 4);
    uint32_t svc_inst = 0xD4000001;
    ProcessTracer::write_memory(pid, pc, &svc_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
  } else {
    user_regs_struct_32 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    regs.regs[0] = (uint32_t)addr;
    regs.regs[1] = (uint32_t)size;
    regs.regs[7] = 91;
    uint32_t pc = regs.regs[15];
    uint32_t orig_inst;
    ProcessTracer::read_memory(pid, pc, &orig_inst, 4);
    uint32_t svc_inst = 0xEF000000;
    ProcessTracer::write_memory(pid, pc, &svc_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
  }
  return true;
}

static uint64_t parse_remote_symbol_64(int pid, uint64_t lib_base,
                                       const std::string &sym) {
  uint8_t ehdr_buf[64];
  if (!ProcessTracer::read_memory(pid, lib_base, ehdr_buf, 64))
    return 0;
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ehdr_buf;
  if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
    return 0;
  uint64_t phdr_off = ehdr->e_phoff;
  uint16_t phnum = ehdr->e_phnum;
  uint16_t phentsize = ehdr->e_phentsize;
  uint64_t dyn_vaddr = 0, dyn_size = 0;
  for (uint16_t i = 0; i < phnum; i++) {
    uint8_t phdr_buf[56];
    if (!ProcessTracer::read_memory(pid, lib_base + phdr_off + i * phentsize,
                                    phdr_buf, 56))
      continue;
    Elf64_Phdr *phdr = (Elf64_Phdr *)phdr_buf;
    if (phdr->p_type == PT_DYNAMIC) {
      dyn_vaddr = phdr->p_vaddr;
      dyn_size = phdr->p_memsz;
      break;
    }
  }
  if (dyn_vaddr == 0)
    return 0;
  uint64_t symtab = 0, strtab = 0, hash = 0, gnu_hash = 0;
  size_t nchain = 0;
  for (uint64_t off = 0; off < dyn_size; off += 16) {
    uint8_t dyn_buf[16];
    if (!ProcessTracer::read_memory(pid, lib_base + dyn_vaddr + off, dyn_buf,
                                    16))
      break;
    Elf64_Dyn *dyn = (Elf64_Dyn *)dyn_buf;
    if (dyn->d_tag == DT_NULL)
      break;
    switch (dyn->d_tag) {
    case DT_SYMTAB:
      symtab = dyn->d_un.d_ptr;
      break;
    case DT_STRTAB:
      strtab = dyn->d_un.d_ptr;
      break;
    case DT_HASH:
      hash = dyn->d_un.d_ptr;
      break;
    case DT_GNU_HASH:
      gnu_hash = dyn->d_un.d_ptr;
      break;
    }
  }
  if (symtab == 0 || strtab == 0)
    return 0;
  if (hash != 0) {
    uint32_t hash_hdr[2];
    if (ProcessTracer::read_memory(pid, hash, hash_hdr, 8))
      nchain = hash_hdr[1];
  }
  if (nchain == 0 && gnu_hash != 0) {
    uint32_t gnu_hdr[4];
    if (ProcessTracer::read_memory(pid, gnu_hash, gnu_hdr, 16)) {
      uint32_t nbuckets = gnu_hdr[0];
      uint32_t symoffset = gnu_hdr[1];
      uint32_t bloom_size = gnu_hdr[2];
      uint64_t buckets_addr = gnu_hash + 16 + bloom_size * 8;
      uint32_t max_bucket = 0;
      for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t b;
        if (ProcessTracer::read_memory(pid, buckets_addr + i * 4, &b, 4) &&
            b > max_bucket)
          max_bucket = b;
      }
      if (max_bucket > 0) {
        uint64_t chain_addr = buckets_addr + nbuckets * 4;
        uint32_t idx = max_bucket - symoffset;
        while (true) {
          uint32_t chain_val;
          if (!ProcessTracer::read_memory(pid, chain_addr + idx * 4, &chain_val,
                                          4))
            break;
          if (chain_val & 1) {
            nchain = max_bucket + 1;
            break;
          }
          idx++;
          max_bucket++;
        }
      }
      if (nchain == 0)
        nchain = symoffset + 1024;
    }
  }
  if (nchain == 0)
    nchain = 4096;
  for (size_t i = 0; i < nchain; i++) {
    uint8_t sym_buf[24];
    if (!ProcessTracer::read_memory(pid, symtab + i * 24, sym_buf, 24))
      break;
    Elf64_Sym *s = (Elf64_Sym *)sym_buf;
    if (s->st_name == 0 || s->st_value == 0)
      continue;
    char name_buf[256] = {0};
    ProcessTracer::read_memory(pid, strtab + s->st_name, name_buf, 255);
    if (strcmp(name_buf, sym.c_str()) == 0)
      return s->st_value;
  }
  return 0;
}

static uint64_t parse_remote_symbol_32(int pid, uint64_t lib_base,
                                       const std::string &sym) {
  uint8_t ehdr_buf[52];
  if (!ProcessTracer::read_memory(pid, lib_base, ehdr_buf, 52))
    return 0;
  Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ehdr_buf;
  if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
    return 0;
  uint32_t phdr_off = ehdr->e_phoff;
  uint16_t phnum = ehdr->e_phnum;
  uint16_t phentsize = ehdr->e_phentsize;
  uint32_t dyn_vaddr = 0, dyn_size = 0;
  for (uint16_t i = 0; i < phnum; i++) {
    uint8_t phdr_buf[32];
    if (!ProcessTracer::read_memory(pid, lib_base + phdr_off + i * phentsize,
                                    phdr_buf, 32))
      continue;
    Elf32_Phdr *phdr = (Elf32_Phdr *)phdr_buf;
    if (phdr->p_type == PT_DYNAMIC) {
      dyn_vaddr = phdr->p_vaddr;
      dyn_size = phdr->p_memsz;
      break;
    }
  }
  if (dyn_vaddr == 0)
    return 0;
  uint32_t symtab = 0, strtab = 0, hash = 0;
  size_t nchain = 0;
  for (uint32_t off = 0; off < dyn_size; off += 8) {
    uint8_t dyn_buf[8];
    if (!ProcessTracer::read_memory(pid, lib_base + dyn_vaddr + off, dyn_buf,
                                    8))
      break;
    Elf32_Dyn *dyn = (Elf32_Dyn *)dyn_buf;
    if (dyn->d_tag == DT_NULL)
      break;
    switch (dyn->d_tag) {
    case DT_SYMTAB:
      symtab = dyn->d_un.d_ptr;
      break;
    case DT_STRTAB:
      strtab = dyn->d_un.d_ptr;
      break;
    case DT_HASH:
      hash = dyn->d_un.d_ptr;
      break;
    }
  }
  if (symtab == 0 || strtab == 0)
    return 0;
  if (hash != 0) {
    uint32_t hash_hdr[2];
    if (ProcessTracer::read_memory(pid, hash, hash_hdr, 8))
      nchain = hash_hdr[1];
  }
  if (nchain == 0)
    nchain = 4096;
  for (size_t i = 0; i < nchain; i++) {
    uint8_t sym_buf[16];
    if (!ProcessTracer::read_memory(pid, symtab + i * 16, sym_buf, 16))
      break;
    Elf32_Sym *s = (Elf32_Sym *)sym_buf;
    if (s->st_name == 0 || s->st_value == 0)
      continue;
    char name_buf[256] = {0};
    ProcessTracer::read_memory(pid, strtab + s->st_name, name_buf, 255);
    if (strcmp(name_buf, sym.c_str()) == 0)
      return s->st_value;
  }
  return 0;
}

uint64_t FunctionHooker::find_remote_symbol(int pid, const std::string &lib,
                                            const std::string &sym) {
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line)) {
    if (line.find(lib) == std::string::npos)
      continue;
    if (line.find("r-xp") == std::string::npos &&
        line.find("r--p") == std::string::npos)
      continue;
    uint64_t base;
    sscanf(line.c_str(), "%lx", (unsigned long *)&base);
    uint64_t offset;
    if (g_arch == ArchMode::ARM64)
      offset = parse_remote_symbol_64(pid, base, sym);
    else
      offset = parse_remote_symbol_32(pid, base, sym);
    if (offset != 0)
      return base + offset;
  }
  return 0;
}

bool FunctionHooker::hook_function(int pid, uint64_t target, uint64_t hook,
                                   uint64_t *original) {
  if (g_arch == ArchMode::ARM64) {
    uint32_t orig_bytes[4];
    if (!ProcessTracer::read_memory(pid, target, orig_bytes, 16))
      return false;
    uint64_t trampoline = allocate_remote(pid, 64);
    if (trampoline == 0)
      return false;
    uint8_t tramp_code[32];
    memcpy(tramp_code, orig_bytes, 16);
    uint32_t br_back[4] = {0x58000050, (uint32_t)(target + 16),
                           (uint32_t)((target + 16) >> 32), 0xD61F0000};
    memcpy(tramp_code + 16, br_back, 16);
    ProcessTracer::write_memory(pid, trampoline, tramp_code, 32);
    *original = trampoline;
    uint32_t hook_jmp[4] = {0x58000050, (uint32_t)hook, (uint32_t)(hook >> 32),
                            0xD61F0000};
    return ProcessTracer::write_memory(pid, target, hook_jmp, 16);
  } else {
    uint32_t orig_bytes[2];
    if (!ProcessTracer::read_memory(pid, target, orig_bytes, 8))
      return false;
    uint64_t trampoline = allocate_remote(pid, 32);
    if (trampoline == 0)
      return false;
    uint8_t tramp_code[16];
    memcpy(tramp_code, orig_bytes, 8);
    uint32_t br_back[2] = {0xE51FF004, (uint32_t)(target + 8)};
    memcpy(tramp_code + 8, br_back, 8);
    ProcessTracer::write_memory(pid, trampoline, tramp_code, 16);
    *original = trampoline;
    uint32_t hook_jmp[2] = {0xE51FF004, (uint32_t)hook};
    return ProcessTracer::write_memory(pid, target, hook_jmp, 8);
  }
}

bool FunctionHooker::unhook_function(int pid, uint64_t target,
                                     uint64_t original) {
  size_t patch_size = (g_arch == ArchMode::ARM64) ? 16 : 8;
  std::vector<uint8_t> orig_bytes(patch_size);
  if (!ProcessTracer::read_memory(pid, original, orig_bytes.data(), patch_size))
    return false;
  return ProcessTracer::write_memory(pid, target, orig_bytes.data(),
                                     patch_size);
}

bool FunctionHooker::inject_library(int pid, const std::string &lib_path) {
  uint64_t dlopen_addr = find_remote_symbol(pid, "libdl.so", "dlopen");
  if (dlopen_addr == 0)
    dlopen_addr = find_remote_symbol(pid, "libc.so", "__loader_dlopen");
  if (dlopen_addr == 0)
    return false;
  size_t path_len = lib_path.size() + 1;
  uint64_t remote_path = allocate_remote(pid, path_len);
  if (remote_path == 0)
    return false;
  ProcessTracer::write_memory(pid, remote_path, lib_path.c_str(), path_len);
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    regs.regs[0] = remote_path;
    regs.regs[1] = RTLD_NOW;
    regs.pc = dlopen_addr;
    regs.regs[30] = 0;
    uint32_t orig_inst;
    ProcessTracer::read_memory(pid, dlopen_addr, &orig_inst, 4);
    uint32_t brk_inst = 0xD4200000;
    ProcessTracer::write_memory(pid, dlopen_addr, &brk_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    uint64_t result = regs.regs[0];
    ProcessTracer::write_memory(pid, dlopen_addr, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    free_remote(pid, remote_path, path_len);
    return result != 0;
  } else {
    user_regs_struct_32 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;
    uint32_t sp = regs.regs[13] - 16;
    regs.regs[13] = sp;
    uint32_t args[2] = {(uint32_t)remote_path, RTLD_NOW};
    ProcessTracer::write_memory(pid, sp, args, 8);
    regs.regs[15] = (uint32_t)dlopen_addr;
    regs.regs[14] = 0;
    uint32_t orig_inst;
    ProcessTracer::read_memory(pid, dlopen_addr, &orig_inst, 4);
    uint32_t brk_inst = 0xE1200070;
    ProcessTracer::write_memory(pid, dlopen_addr, &brk_inst, 4);
    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    int status;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    uint32_t result = regs.regs[0];
    ProcessTracer::write_memory(pid, dlopen_addr, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    free_remote(pid, remote_path, path_len);
    return result != 0;
  }
}

std::vector<RelinkEntry>
StaticRelinker::find_external_calls(const std::vector<uint8_t> &data,
                                    uint64_t base) {
  std::vector<RelinkEntry> entries;
  if (data.size() < 64)
    return entries;
  bool is32 = (data[4] == ELFCLASS32);
  if (is32) {
    const Elf32_Ehdr *ehdr = reinterpret_cast<const Elf32_Ehdr *>(data.data());
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
      return entries;
    if (ehdr->e_phoff == 0)
      return entries;
    uint32_t dyn_off = 0, dyn_sz = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<const Elf32_Phdr *>(
          data.data() + ehdr->e_phoff + i * ehdr->e_phentsize);
      if (ph->p_type == PT_DYNAMIC) {
        dyn_off = ph->p_offset;
        dyn_sz = ph->p_filesz;
        break;
      }
    }
    if (dyn_off == 0)
      return entries;
    uint32_t jmprel = 0, pltrelsz = 0, symtab = 0, strtab = 0;
    const Elf32_Dyn *dyn =
        reinterpret_cast<const Elf32_Dyn *>(data.data() + dyn_off);
    for (size_t i = 0; i < dyn_sz / sizeof(Elf32_Dyn); i++) {
      switch (dyn[i].d_tag) {
      case DT_JMPREL:
        jmprel = dyn[i].d_un.d_ptr;
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn[i].d_un.d_val;
        break;
      case DT_SYMTAB:
        symtab = dyn[i].d_un.d_ptr;
        break;
      case DT_STRTAB:
        strtab = dyn[i].d_un.d_ptr;
        break;
      }
    }
    if (jmprel == 0 || symtab == 0 || strtab == 0)
      return entries;
    size_t count = pltrelsz / sizeof(Elf32_Rel);
    for (size_t i = 0; i < count; i++) {
      uint32_t rel_off = jmprel + i * sizeof(Elf32_Rel);
      if (rel_off + sizeof(Elf32_Rel) > data.size())
        break;
      auto rel = reinterpret_cast<const Elf32_Rel *>(data.data() + rel_off);
      uint32_t sym_idx = ELF32_R_SYM(rel->r_info);
      uint32_t sym_off = symtab + sym_idx * sizeof(Elf32_Sym);
      if (sym_off + sizeof(Elf32_Sym) > data.size())
        continue;
      auto sym = reinterpret_cast<const Elf32_Sym *>(data.data() + sym_off);
      if (sym->st_name == 0 || strtab + sym->st_name >= data.size())
        continue;
      RelinkEntry entry;
      entry.call_site = rel->r_offset;
      entry.target_addr = 0;
      entry.symbol_name =
          reinterpret_cast<const char *>(data.data() + strtab + sym->st_name);
      entries.push_back(entry);
    }
  } else {
    const Elf64_Ehdr *ehdr = reinterpret_cast<const Elf64_Ehdr *>(data.data());
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
      return entries;
    if (ehdr->e_phoff == 0)
      return entries;
    uint64_t dyn_off = 0, dyn_sz = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
      auto ph = reinterpret_cast<const Elf64_Phdr *>(
          data.data() + ehdr->e_phoff + i * ehdr->e_phentsize);
      if (ph->p_type == PT_DYNAMIC) {
        dyn_off = ph->p_offset;
        dyn_sz = ph->p_filesz;
        break;
      }
    }
    if (dyn_off == 0)
      return entries;
    uint64_t jmprel = 0, pltrelsz = 0, symtab = 0, strtab = 0;
    const Elf64_Dyn *dyn =
        reinterpret_cast<const Elf64_Dyn *>(data.data() + dyn_off);
    for (size_t i = 0; i < dyn_sz / sizeof(Elf64_Dyn); i++) {
      switch (dyn[i].d_tag) {
      case DT_JMPREL:
        jmprel = dyn[i].d_un.d_ptr;
        break;
      case DT_PLTRELSZ:
        pltrelsz = dyn[i].d_un.d_val;
        break;
      case DT_SYMTAB:
        symtab = dyn[i].d_un.d_ptr;
        break;
      case DT_STRTAB:
        strtab = dyn[i].d_un.d_ptr;
        break;
      }
    }
    if (jmprel == 0 || symtab == 0 || strtab == 0)
      return entries;
    size_t count = pltrelsz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < count; i++) {
      uint64_t rel_off = jmprel + i * sizeof(Elf64_Rela);
      if (rel_off + sizeof(Elf64_Rela) > data.size())
        break;
      auto rela = reinterpret_cast<const Elf64_Rela *>(data.data() + rel_off);
      uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
      uint64_t sym_off = symtab + sym_idx * sizeof(Elf64_Sym);
      if (sym_off + sizeof(Elf64_Sym) > data.size())
        continue;
      auto sym = reinterpret_cast<const Elf64_Sym *>(data.data() + sym_off);
      if (sym->st_name == 0 || strtab + sym->st_name >= data.size())
        continue;
      RelinkEntry entry;
      entry.call_site = rela->r_offset;
      entry.target_addr = 0;
      entry.symbol_name =
          reinterpret_cast<const char *>(data.data() + strtab + sym->st_name);
      entries.push_back(entry);
    }
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
  std::vector<uint8_t> func_data(max_size);
  if (!ProcessTracer::read_memory(pid, addr, func_data.data(), max_size))
    return {};
  size_t actual_size = max_size;
  if (g_arch == ArchMode::ARM64) {
    for (size_t i = 0; i < max_size; i += 4) {
      uint32_t inst = *(uint32_t *)(func_data.data() + i);
      if (inst == 0xD65F03C0) {
        actual_size = i + 4;
        break;
      }
    }
  } else {
    for (size_t i = 0; i < max_size; i += 4) {
      uint32_t inst = *(uint32_t *)(func_data.data() + i);
      if ((inst & 0x0FFFFFFF) == 0x01A0F00E) {
        actual_size = i + 4;
        break;
      }
    }
  }
  func_data.resize(actual_size);
  return func_data;
}

struct LibraryRange {
  uint64_t start;
  uint64_t end;
  std::string name;
};

static std::vector<LibraryRange> get_library_ranges(int pid) {
  std::vector<LibraryRange> ranges;
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line)) {
    if (line.find("r-xp") == std::string::npos &&
        line.find("r--p") == std::string::npos)
      continue;
    uint64_t start, end;
    if (sscanf(line.c_str(), "%lx-%lx", (unsigned long *)&start,
               (unsigned long *)&end) != 2)
      continue;
    std::string name;
    size_t path_pos = line.find('/');
    if (path_pos != std::string::npos) {
      std::string path = line.substr(path_pos);
      while (!path.empty() && (path.back() == ' ' || path.back() == '\n'))
        path.pop_back();
      size_t slash = path.rfind('/');
      name = (slash != std::string::npos) ? path.substr(slash + 1) : path;
    } else {
      size_t bracket = line.find('[');
      if (bracket != std::string::npos) {
        size_t bracket_end = line.find(']', bracket);
        if (bracket_end != std::string::npos)
          name = line.substr(bracket, bracket_end - bracket + 1);
      }
      if (name.empty())
        name = "anon_" + std::to_string(start);
    }
    ranges.push_back({start, end, name});
  }
  return ranges;
}

static std::string
find_library_for_address(const std::vector<LibraryRange> &ranges,
                         uint64_t addr) {
  for (const auto &r : ranges) {
    if (addr >= r.start && addr < r.end)
      return r.name;
  }
  return "";
}

static std::vector<std::pair<uint64_t, uint64_t>>
scan_bl_instructions_64(const std::vector<uint8_t> &code, uint64_t base) {
  std::vector<std::pair<uint64_t, uint64_t>> calls;
  for (size_t i = 0; i + 4 <= code.size(); i += 4) {
    uint32_t inst = *(const uint32_t *)(code.data() + i);
    if ((inst & 0xFC000000) == 0x94000000) {
      int32_t offset = inst & 0x03FFFFFF;
      if (offset & 0x02000000)
        offset |= 0xFC000000;
      uint64_t pc = base + i;
      uint64_t target = pc + (int64_t)offset * 4;
      calls.push_back({i, target});
    }
  }
  return calls;
}

static std::vector<std::pair<uint64_t, uint64_t>>
scan_bl_instructions_32(const std::vector<uint8_t> &code, uint64_t base) {
  std::vector<std::pair<uint64_t, uint64_t>> calls;
  for (size_t i = 0; i + 4 <= code.size(); i += 4) {
    uint32_t inst = *(const uint32_t *)(code.data() + i);
    if ((inst & 0x0F000000) == 0x0B000000) {
      int32_t offset = inst & 0x00FFFFFF;
      if (offset & 0x00800000)
        offset |= 0xFF000000;
      uint64_t pc = base + i + 8;
      uint64_t target = pc + offset * 4;
      calls.push_back({i, target});
    }
  }
  return calls;
}

std::vector<uint8_t>
StaticRelinker::relink(const std::vector<uint8_t> &elf_data, int pid,
                       uint64_t base_addr) {
  std::vector<uint8_t> result = elf_data;
  auto lib_ranges = get_library_ranges(pid);
  std::string self_lib;
  for (const auto &r : lib_ranges) {
    if (base_addr >= r.start && base_addr < r.end) {
      self_lib = r.name;
      break;
    }
  }
  std::vector<std::pair<uint64_t, uint64_t>> external_calls;
  uint64_t self_start = base_addr;
  uint64_t self_end = base_addr + elf_data.size();
  if (!self_lib.empty()) {
    for (const auto &r : lib_ranges) {
      if (r.name == self_lib) {
        if (r.start < self_start)
          self_start = r.start;
        if (r.end > self_end)
          self_end = r.end;
      }
    }
  }
  if (g_arch == ArchMode::ARM64) {
    auto all_calls = scan_bl_instructions_64(elf_data, base_addr);
    for (const auto &call : all_calls) {
      uint64_t target = call.second;
      uint64_t resolved_target = target;
      std::string direct_lib = find_library_for_address(lib_ranges, target);
      if (!direct_lib.empty() && direct_lib != self_lib) {
        external_calls.push_back({call.first, target});
        continue;
      }
      if (target >= self_start && target < self_end) {
        uint8_t plt_stub[16];
        if (ProcessTracer::read_memory(pid, target, plt_stub, 16)) {
          for (int skip = 0; skip <= 4; skip += 4) {
            uint32_t inst0 = *(uint32_t *)(plt_stub + skip);
            uint32_t inst1 = *(uint32_t *)(plt_stub + skip + 4);
            bool is_adrp = (inst0 & 0x9F000000) == 0x90000000;
            bool is_ldr = (inst1 & 0xFFC00000) == 0xF9400000;
            if (is_adrp && is_ldr) {
              int32_t immhi = ((inst0 >> 5) & 0x7FFFF) << 2;
              int32_t immlo = (inst0 >> 29) & 0x3;
              int32_t imm21 = (immhi | immlo);
              if (imm21 & 0x100000)
                imm21 |= 0xFFE00000;
              int64_t page_offset = (int64_t)imm21 << 12;
              uint64_t page_base = ((target + skip) & ~0xFFFULL) + page_offset;
              uint32_t ldr_imm = ((inst1 >> 10) & 0xFFF) << 3;
              uint64_t got_addr = page_base + ldr_imm;
              uint64_t got_value = 0;
              if (ProcessTracer::read_memory(pid, got_addr, &got_value, 8)) {
                if (got_value > 0x1000 && got_value != target) {
                  std::string got_lib =
                      find_library_for_address(lib_ranges, got_value);
                  if (!got_lib.empty() && got_lib != self_lib) {
                    resolved_target = got_value;
                    break;
                  }
                }
              }
            }
          }
        }
      }
      if (resolved_target != target) {
        external_calls.push_back({call.first, resolved_target});
      }
    }
  } else {
    auto all_calls = scan_bl_instructions_32(elf_data, base_addr);
    for (const auto &call : all_calls) {
      uint64_t target = call.second;
      uint64_t resolved_target = target;
      if (target >= base_addr && target < base_addr + elf_data.size()) {
        uint64_t offset_in_elf = target - base_addr;
        if (offset_in_elf + 8 <= elf_data.size()) {
          uint32_t inst0 = *(const uint32_t *)(elf_data.data() + offset_in_elf);
          if ((inst0 & 0x0E5F0000) == 0x04100000) {
            uint32_t got_offset = inst0 & 0xFFF;
            uint64_t got_addr = target + 8 + got_offset;
            uint32_t got_value = 0;
            if (ProcessTracer::read_memory(pid, got_addr, &got_value, 4)) {
              if (got_value != 0 && got_value != (uint32_t)target)
                resolved_target = got_value;
            }
          }
        }
      }
      std::string target_lib =
          find_library_for_address(lib_ranges, resolved_target);
      if (!target_lib.empty() && target_lib != self_lib)
        external_calls.push_back({call.first, resolved_target});
    }
  }
  if (external_calls.empty())
    return result;
  size_t align = (g_arch == ArchMode::ARM64) ? 16 : 4;
  uint64_t embed_offset = result.size();
  while (embed_offset % align)
    embed_offset++;
  result.resize(embed_offset);
  std::map<uint64_t, uint64_t> embedded_addrs;
  size_t embedded_count = 0;
  for (const auto &call : external_calls) {
    uint64_t target_addr = call.second;
    if (embedded_addrs.count(target_addr))
      continue;
    auto func_code = embed_function(pid, target_addr, 4096);
    if (func_code.empty() || func_code.size() < 8)
      continue;
    uint64_t local_offset = result.size();
    embedded_addrs[target_addr] = local_offset;
    result.insert(result.end(), func_code.begin(), func_code.end());
    while (result.size() % align)
      result.push_back(0);
    embedded_count++;
    if (embedded_count >= 256)
      break;
  }
  for (const auto &call : external_calls) {
    uint64_t call_offset = call.first;
    uint64_t target_addr = call.second;
    if (!embedded_addrs.count(target_addr))
      continue;
    uint64_t local_offset = embedded_addrs[target_addr];
    if (call_offset + 4 > elf_data.size())
      continue;
    if (g_arch == ArchMode::ARM64) {
      int64_t rel_offset = (int64_t)local_offset - (int64_t)call_offset;
      rel_offset /= 4;
      if (rel_offset >= -0x2000000 && rel_offset < 0x2000000) {
        uint32_t new_inst = 0x94000000 | (rel_offset & 0x03FFFFFF);
        *(uint32_t *)(result.data() + call_offset) = new_inst;
      }
    } else {
      int64_t rel_offset = (int64_t)local_offset - (int64_t)(call_offset + 8);
      rel_offset /= 4;
      if (rel_offset >= -0x800000 && rel_offset < 0x800000) {
        uint32_t orig_inst = *(uint32_t *)(result.data() + call_offset);
        uint32_t new_inst =
            (orig_inst & 0xFF000000) | (rel_offset & 0x00FFFFFF);
        *(uint32_t *)(result.data() + call_offset) = new_inst;
      }
    }
  }
  return result;
}
