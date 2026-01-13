#include "tracer.h"
#include "memory.h"
#include <cstring>
#include <dirent.h>
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

namespace InstructionDecoder {

DecodedInstruction decode_arm64(uint32_t inst, uint64_t addr) {
  DecodedInstruction d{};
  d.raw = inst;
  d.address = addr;
  d.type = InstructionType::Other;
  d.is_return = false;
  d.is_call = false;
  d.is_indirect = false;
  d.target_address = 0;

  if ((inst & 0xFC000000) == 0x94000000) {
    d.type = InstructionType::BranchLink;
    int32_t imm = inst & 0x03FFFFFF;
    if (imm & 0x02000000)
      imm |= 0xFC000000;
    d.target_address = addr + (int64_t)imm * 4;
    d.is_call = true;
  } else if ((inst & 0xFC000000) == 0x14000000) {
    d.type = InstructionType::Branch;
    int32_t imm = inst & 0x03FFFFFF;
    if (imm & 0x02000000)
      imm |= 0xFC000000;
    d.target_address = addr + (int64_t)imm * 4;
  } else if ((inst & 0xFFFFFC1F) == 0xD61F0000) {
    d.type = InstructionType::BranchRegister;
    d.rn = (inst >> 5) & 0x1F;
    d.is_indirect = true;
  } else if ((inst & 0xFFFFFC1F) == 0xD63F0000) {
    d.type = InstructionType::BranchLink;
    d.rn = (inst >> 5) & 0x1F;
    d.is_call = true;
    d.is_indirect = true;
  } else if ((inst & 0xFFFFFC1F) == 0xD65F0000) {
    d.type = InstructionType::Return;
    d.rn = (inst >> 5) & 0x1F;
    d.is_return = true;
  } else if ((inst & 0xFF000010) == 0x54000000) {
    d.type = InstructionType::ConditionalBranch;
    int32_t imm = (inst >> 5) & 0x7FFFF;
    if (imm & 0x40000)
      imm |= 0xFFF80000;
    d.target_address = addr + (int64_t)imm * 4;
  } else if ((inst & 0x7E000000) == 0x34000000) {
    d.type = InstructionType::ConditionalBranch;
    int32_t imm = (inst >> 5) & 0x7FFFF;
    if (imm & 0x40000)
      imm |= 0xFFF80000;
    d.target_address = addr + (int64_t)imm * 4;
    d.rn = inst & 0x1F;
  } else if ((inst & 0x7E000000) == 0x36000000) {
    d.type = InstructionType::ConditionalBranch;
    int32_t imm = (inst >> 5) & 0x3FFF;
    if (imm & 0x2000)
      imm |= 0xFFFFC000;
    d.target_address = addr + (int64_t)imm * 4;
    d.rn = inst & 0x1F;
  } else if ((inst & 0x9F000000) == 0x90000000) {
    d.type = InstructionType::Adrp;
    d.rd = inst & 0x1F;
    int32_t immhi = ((inst >> 5) & 0x7FFFF) << 2;
    int32_t immlo = (inst >> 29) & 0x3;
    int32_t imm = immhi | immlo;
    if (imm & 0x100000)
      imm |= 0xFFE00000;
    d.immediate = (int64_t)imm << 12;
    d.target_address = (addr & ~0xFFFULL) + d.immediate;
  } else if ((inst & 0x9F000000) == 0x10000000) {
    d.type = InstructionType::Add;
    d.rd = inst & 0x1F;
    int32_t immhi = ((inst >> 5) & 0x7FFFF) << 2;
    int32_t immlo = (inst >> 29) & 0x3;
    int32_t imm = immhi | immlo;
    if (imm & 0x100000)
      imm |= 0xFFE00000;
    d.immediate = imm;
    d.target_address = addr + d.immediate;
  } else if ((inst & 0xFFC00000) == 0xF9400000) {
    d.type = InstructionType::Load;
    d.rd = inst & 0x1F;
    d.rn = (inst >> 5) & 0x1F;
    d.immediate = ((inst >> 10) & 0xFFF) << 3;
  } else if ((inst & 0xFFC00000) == 0xB9400000) {
    d.type = InstructionType::Load;
    d.rd = inst & 0x1F;
    d.rn = (inst >> 5) & 0x1F;
    d.immediate = ((inst >> 10) & 0xFFF) << 2;
  } else if ((inst & 0xFF000000) == 0x91000000) {
    d.type = InstructionType::Add;
    d.rd = inst & 0x1F;
    d.rn = (inst >> 5) & 0x1F;
    d.immediate = (inst >> 10) & 0xFFF;
    if ((inst >> 22) & 1)
      d.immediate <<= 12;
  } else if ((inst & 0xFFC00000) == 0xF9000000) {
    d.type = InstructionType::Store;
    d.rd = inst & 0x1F;
    d.rn = (inst >> 5) & 0x1F;
    d.immediate = ((inst >> 10) & 0xFFF) << 3;
  }

  return d;
}

DecodedInstruction decode_arm32(uint32_t inst, uint64_t addr) {
  DecodedInstruction d{};
  d.raw = inst;
  d.address = addr;
  d.type = InstructionType::Other;
  d.is_return = false;
  d.is_call = false;
  d.is_indirect = false;
  d.target_address = 0;

  uint32_t cond = (inst >> 28) & 0xF;

  if ((inst & 0x0F000000) == 0x0B000000) {
    d.type = InstructionType::BranchLink;
    int32_t imm = inst & 0x00FFFFFF;
    if (imm & 0x00800000)
      imm |= 0xFF000000;
    d.target_address = addr + 8 + (int64_t)imm * 4;
    d.is_call = true;
  } else if ((inst & 0x0F000000) == 0x0A000000) {
    d.type = (cond == 0xE) ? InstructionType::Branch
                           : InstructionType::ConditionalBranch;
    int32_t imm = inst & 0x00FFFFFF;
    if (imm & 0x00800000)
      imm |= 0xFF000000;
    d.target_address = addr + 8 + (int64_t)imm * 4;
  } else if ((inst & 0xFE000000) == 0xFA000000) {
    d.type = InstructionType::BranchLink;
    int32_t imm = inst & 0x00FFFFFF;
    if (imm & 0x00800000)
      imm |= 0xFF000000;
    int32_t h = ((inst >> 24) & 1) << 1;
    d.target_address = addr + 8 + (int64_t)imm * 4 + h;
    d.is_call = true;
  } else if ((inst & 0x0FFFFFF0) == 0x012FFF10) {
    d.type = InstructionType::BranchRegister;
    d.rm = inst & 0xF;
    d.is_indirect = true;
    if (d.rm == 14) {
      d.is_return = true;
      d.type = InstructionType::Return;
    }
  } else if ((inst & 0x0FFFFFF0) == 0x012FFF30) {
    d.type = InstructionType::BranchLink;
    d.rm = inst & 0xF;
    d.is_call = true;
    d.is_indirect = true;
  } else if ((inst & 0x0FFFFFFF) == 0x01A0F00E) {
    d.type = InstructionType::Return;
    d.is_return = true;
  } else if ((inst & 0x0FFF8000) == 0x08BD8000) {
    d.type = InstructionType::Return;
    d.is_return = true;
  } else if ((inst & 0x0F5F0000) == 0x051F0000 && ((inst >> 12) & 0xF) == 15) {
    d.type = InstructionType::BranchRegister;
    d.is_indirect = true;
    d.rn = (inst >> 16) & 0xF;
  } else if ((inst & 0x0E500000) == 0x04100000) {
    d.type = InstructionType::Load;
    d.rd = (inst >> 12) & 0xF;
    d.rn = (inst >> 16) & 0xF;
    d.immediate = inst & 0xFFF;
    if (!((inst >> 23) & 1))
      d.immediate = -d.immediate;
  } else if ((inst & 0x0E500000) == 0x04000000) {
    d.type = InstructionType::Store;
    d.rd = (inst >> 12) & 0xF;
    d.rn = (inst >> 16) & 0xF;
    d.immediate = inst & 0xFFF;
  }

  return d;
}

DecodedInstruction decode(uint32_t inst, uint64_t addr, ArchMode arch) {
  if (arch == ArchMode::ARM64)
    return decode_arm64(inst, addr);
  else
    return decode_arm32(inst, addr);
}

bool is_function_end_arm64(const uint8_t *code, size_t offset, size_t size) {
  if (offset + 4 > size)
    return true;
  uint32_t inst = *(const uint32_t *)(code + offset);
  auto d = decode_arm64(inst, 0);
  return d.is_return;
}

bool is_function_end_arm32(const uint8_t *code, size_t offset, size_t size) {
  if (offset + 4 > size)
    return true;
  uint32_t inst = *(const uint32_t *)(code + offset);
  auto d = decode_arm32(inst, 0);
  return d.is_return;
}

size_t find_function_end(const uint8_t *code, size_t max_size, ArchMode arch) {
  for (size_t i = 0; i < max_size; i += 4) {
    if (arch == ArchMode::ARM64) {
      if (is_function_end_arm64(code, i, max_size))
        return i + 4;
    } else {
      if (is_function_end_arm32(code, i, max_size))
        return i + 4;
    }
  }
  return max_size;
}

std::vector<CallInfo> scan_calls_arm64(const uint8_t *code, size_t size,
                                       uint64_t base) {
  std::vector<CallInfo> calls;
  for (size_t i = 0; i + 4 <= size; i += 4) {
    uint32_t inst = *(const uint32_t *)(code + i);
    auto d = decode_arm64(inst, base + i);
    if (d.is_call && !d.is_indirect) {
      CallInfo ci{};
      ci.call_site_offset = i;
      ci.target_address = d.target_address;
      ci.resolved_address = d.target_address;
      ci.is_plt_call = false;
      ci.is_external = false;
      calls.push_back(ci);
    }
  }
  return calls;
}

std::vector<CallInfo> scan_calls_arm32(const uint8_t *code, size_t size,
                                       uint64_t base) {
  std::vector<CallInfo> calls;
  for (size_t i = 0; i + 4 <= size; i += 4) {
    uint32_t inst = *(const uint32_t *)(code + i);
    auto d = decode_arm32(inst, base + i);
    if (d.is_call && !d.is_indirect) {
      CallInfo ci{};
      ci.call_site_offset = i;
      ci.target_address = d.target_address;
      ci.resolved_address = d.target_address;
      ci.is_plt_call = false;
      ci.is_external = false;
      calls.push_back(ci);
    }
  }
  return calls;
}

std::vector<CallInfo> scan_calls(const uint8_t *code, size_t size,
                                 uint64_t base, ArchMode arch) {
  if (arch == ArchMode::ARM64)
    return scan_calls_arm64(code, size, base);
  else
    return scan_calls_arm32(code, size, base);
}

uint64_t resolve_plt_arm64(int pid, uint64_t plt_addr) {
  uint8_t stub[16];
  if (!ProcessTracer::read_memory(pid, plt_addr, stub, 16))
    return 0;

  for (int skip = 0; skip <= 4; skip += 4) {
    uint32_t inst0 = *(uint32_t *)(stub + skip);
    uint32_t inst1 = *(uint32_t *)(stub + skip + 4);

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

uint64_t resolve_plt_arm32(int pid, uint64_t plt_addr) {
  uint8_t stub[12];
  if (!ProcessTracer::read_memory(pid, plt_addr, stub, 12))
    return 0;

  uint32_t inst0 = *(uint32_t *)stub;
  if ((inst0 & 0x0E5F0000) == 0x04100000) {
    uint32_t offset = inst0 & 0xFFF;
    uint64_t got_addr = plt_addr + 8 + offset;
    uint32_t got_value = 0;
    if (ProcessTracer::read_memory(pid, got_addr, &got_value, 4))
      return got_value;
  }
  return 0;
}

uint64_t resolve_plt(int pid, uint64_t plt_addr, ArchMode arch) {
  if (arch == ArchMode::ARM64)
    return resolve_plt_arm64(pid, plt_addr);
  else
    return resolve_plt_arm32(pid, plt_addr);
}

struct FunctionBoundary {
  uint64_t start;
  uint64_t end;
  size_t size;
  bool has_frame_pointer;
  int stack_size;
};

bool is_arm64_prologue(uint32_t inst) {
  if ((inst & 0xFFC003E0) == 0xA9800000)
    return true;
  if ((inst & 0xFFC003E0) == 0xA98003E0)
    return true;
  if ((inst & 0xFF0003FF) == 0xD10003FF)
    return true;
  if ((inst & 0xFFE0FFFF) == 0x910003FD)
    return true;
  if ((inst & 0xFFC003E0) == 0x6D800000)
    return true;
  return false;
}

bool is_arm32_prologue(uint32_t inst) {
  if ((inst & 0xFFFF0000) == 0xE92D0000)
    return true;
  if ((inst & 0xFFFFF000) == 0xE52DE000)
    return true;
  if ((inst & 0xFFFFF000) == 0xE24DD000)
    return true;
  if ((inst & 0xFFFF0FFF) == 0xE1A0B00D)
    return true;
  return false;
}

bool is_arm64_epilogue(uint32_t inst) {
  if ((inst & 0xFFFFFC1F) == 0xD65F0000)
    return true;
  if ((inst & 0xFFC003E0) == 0xA8C00000)
    return true;
  return false;
}

bool is_arm32_epilogue(uint32_t inst) {
  if ((inst & 0x0FFF0FFF) == 0x01A0F00E)
    return true;
  if ((inst & 0x0FFF8000) == 0x08BD8000)
    return true;
  if ((inst & 0x0FFFFFF0) == 0x012FFF10 && (inst & 0xF) == 14)
    return true;
  return false;
}

std::vector<FunctionBoundary> linear_sweep_arm64(const uint8_t *code,
                                                 size_t size, uint64_t base) {
  std::vector<FunctionBoundary> funcs;
  size_t i = 0;
  while (i + 4 <= size) {
    uint32_t inst = *(const uint32_t *)(code + i);
    if (is_arm64_prologue(inst)) {
      FunctionBoundary fb;
      fb.start = base + i;
      fb.has_frame_pointer = ((inst & 0xFFE0FFFF) == 0x910003FD);
      fb.stack_size = 0;
      if ((inst & 0xFF0003FF) == 0xD10003FF) {
        fb.stack_size = ((inst >> 10) & 0xFFF);
      }
      size_t j = i + 4;
      while (j + 4 <= size) {
        uint32_t inst2 = *(const uint32_t *)(code + j);
        if (is_arm64_epilogue(inst2)) {
          fb.end = base + j + 4;
          fb.size = fb.end - fb.start;
          if (fb.size >= 8 && fb.size <= 1024 * 1024) {
            funcs.push_back(fb);
          }
          i = j + 4;
          break;
        }
        if (is_arm64_prologue(inst2) && j > i + 8) {
          fb.end = base + j;
          fb.size = fb.end - fb.start;
          if (fb.size >= 8) {
            funcs.push_back(fb);
          }
          i = j;
          break;
        }
        j += 4;
        if (j - i > 64 * 1024) {
          i += 4;
          break;
        }
      }
      if (j + 4 > size)
        i = size;
    } else {
      i += 4;
    }
  }
  return funcs;
}

std::vector<FunctionBoundary> linear_sweep_arm32(const uint8_t *code,
                                                 size_t size, uint64_t base) {
  std::vector<FunctionBoundary> funcs;
  size_t i = 0;
  while (i + 4 <= size) {
    uint32_t inst = *(const uint32_t *)(code + i);
    if (is_arm32_prologue(inst)) {
      FunctionBoundary fb;
      fb.start = base + i;
      fb.has_frame_pointer = false;
      fb.stack_size = 0;
      if ((inst & 0xFFFFF000) == 0xE24DD000) {
        fb.stack_size = inst & 0xFFF;
      }
      size_t j = i + 4;
      while (j + 4 <= size) {
        uint32_t inst2 = *(const uint32_t *)(code + j);
        if (is_arm32_epilogue(inst2)) {
          fb.end = base + j + 4;
          fb.size = fb.end - fb.start;
          if (fb.size >= 8 && fb.size <= 1024 * 1024) {
            funcs.push_back(fb);
          }
          i = j + 4;
          break;
        }
        if (is_arm32_prologue(inst2) && j > i + 8) {
          fb.end = base + j;
          fb.size = fb.end - fb.start;
          if (fb.size >= 8) {
            funcs.push_back(fb);
          }
          i = j;
          break;
        }
        j += 4;
        if (j - i > 64 * 1024) {
          i += 4;
          break;
        }
      }
      if (j + 4 > size)
        i = size;
    } else {
      i += 4;
    }
  }
  return funcs;
}

std::vector<FunctionBoundary> linear_sweep(const uint8_t *code, size_t size,
                                           uint64_t base, ArchMode arch) {
  if (arch == ArchMode::ARM64)
    return linear_sweep_arm64(code, size, base);
  else
    return linear_sweep_arm32(code, size, base);
}

} // namespace InstructionDecoder

int ZygoteTracer::find_zygote_pid() {
  DIR *d = opendir("/proc");
  if (!d)
    return -1;
  struct dirent *ent;
  while ((ent = readdir(d))) {
    int pid = atoi(ent->d_name);
    if (pid <= 0)
      continue;
    std::ifstream f("/proc/" + std::string(ent->d_name) + "/cmdline");
    std::string cmd;
    std::getline(f, cmd);
    if (cmd.find("zygote64") != std::string::npos ||
        cmd.find("zygote") != std::string::npos) {
      closedir(d);
      return pid;
    }
  }
  closedir(d);
  return -1;
}

bool ZygoteTracer::attach_zygote(int zygote_pid) {
  if (ptrace(PTRACE_ATTACH, zygote_pid, nullptr, nullptr) < 0)
    return false;
  int status;
  waitpid(zygote_pid, &status, 0);
  if (!WIFSTOPPED(status))
    return false;

  unsigned long opts = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
  if (ptrace(PTRACE_SETOPTIONS, zygote_pid, nullptr, opts) < 0) {
    ptrace(PTRACE_DETACH, zygote_pid, nullptr, nullptr);
    return false;
  }
  return true;
}

int ZygoteTracer::wait_for_fork(int zygote_pid, const std::string &target_pkg) {
  ptrace(PTRACE_CONT, zygote_pid, nullptr, nullptr);

  while (true) {
    int status;
    int pid = waitpid(-1, &status, __WALL);
    if (pid < 0)
      break;

    if (WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      if (sig == SIGTRAP) {
        int event = (status >> 16) & 0xFF;
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
          unsigned long child_pid;
          ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &child_pid);

          usleep(100000);
          std::ifstream f("/proc/" + std::to_string(child_pid) + "/cmdline");
          std::string cmd;
          std::getline(f, cmd);

          if (cmd.find(target_pkg) != std::string::npos) {
            ptrace(PTRACE_DETACH, zygote_pid, nullptr, nullptr);
            return child_pid;
          }
        }
      }
      ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    }
  }
  return -1;
}

bool ZygoteTracer::intercept_dlopen(int pid) {
  auto maps = ProcessTracer::get_library_ranges(pid);
  uint64_t linker_base = 0;
  for (const auto &m : maps) {
    if (m.name.find("linker64") != std::string::npos ||
        m.name.find("linker") != std::string::npos) {
      linker_base = m.start;
      break;
    }
  }
  return linker_base != 0;
}

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

std::vector<LibraryRange> ProcessTracer::get_library_ranges(int pid) {
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

std::string
ProcessTracer::find_library_for_address(const std::vector<LibraryRange> &ranges,
                                        uint64_t addr) {
  for (const auto &r : ranges) {
    if (addr >= r.start && addr < r.end)
      return r.name;
  }
  return "";
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
  static constexpr size_t DEFAULT_MAX_FUNC_SIZE = 64 * 1024;
  size_t read_size = (max_size == 0) ? DEFAULT_MAX_FUNC_SIZE : max_size;

  std::vector<uint8_t> func_data(read_size);
  if (!ProcessTracer::read_memory(pid, addr, func_data.data(), read_size))
    return {};

  size_t actual_size = InstructionDecoder::find_function_end(func_data.data(),
                                                             read_size, g_arch);

  if (actual_size < 4)
    actual_size = 4;

  func_data.resize(actual_size);
  return func_data;
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
  auto lib_ranges = ProcessTracer::get_library_ranges(pid);
  std::string self_lib;
  for (const auto &r : lib_ranges) {
    if (base_addr >= r.start && base_addr < r.end) {
      self_lib = r.name;
      break;
    }
  }

  auto plt_entries = ElfParser::get_plt_entries(elf_data);
  std::map<uint64_t, std::string> got_to_symbol;
  std::map<std::string, uint64_t> symbol_to_addr;

  for (const auto &pe : plt_entries) {
    if (!pe.symbol_name.empty()) {
      got_to_symbol[pe.got_offset] = pe.symbol_name;
      if (symbol_to_addr.find(pe.symbol_name) == symbol_to_addr.end()) {
        uint64_t addr =
            ElfParser::resolve_plt_symbol(pid, elf_data, pe.symbol_name);
        if (addr != 0) {
          symbol_to_addr[pe.symbol_name] = addr;
        }
      }
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
      std::string direct_lib =
          ProcessTracer::find_library_for_address(lib_ranges, target);
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
                  std::string got_lib = ProcessTracer::find_library_for_address(
                      lib_ranges, got_value);
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
          ProcessTracer::find_library_for_address(lib_ranges, resolved_target);
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
  static constexpr size_t MAX_TOTAL_EMBED_SIZE = 16 * 1024 * 1024;

  for (const auto &call : external_calls) {
    uint64_t target_addr = call.second;
    if (embedded_addrs.count(target_addr))
      continue;

    auto func_code = embed_function(pid, target_addr, 0);
    if (func_code.empty() || func_code.size() < 8)
      continue;

    if (result.size() + func_code.size() > MAX_TOTAL_EMBED_SIZE)
      break;

    uint64_t local_offset = result.size();
    embedded_addrs[target_addr] = local_offset;
    result.insert(result.end(), func_code.begin(), func_code.end());
    while (result.size() % align)
      result.push_back(0);
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

void StaticRelinker::recursive_embed(EmbedContext &ctx, uint64_t addr) {
  if (ctx.current_depth >= EmbedContext::MAX_DEPTH)
    return;

  if (ctx.total_embedded_size >= EmbedContext::MAX_TOTAL_SIZE)
    return;

  if (ctx.embedded_addresses.count(addr))
    return;

  auto lib_ranges = ProcessTracer::get_library_ranges(ctx.pid);
  std::string lib = ProcessTracer::find_library_for_address(lib_ranges, addr);

  if (lib == ctx.self_library)
    return;

  ctx.embedded_addresses.insert(addr);

  auto code = embed_function(ctx.pid, addr, 0);
  if (code.empty())
    return;

  auto calls = InstructionDecoder::scan_calls(code.data(), code.size(), addr,
                                              ProcessTracer::get_arch());

  ctx.current_depth++;
  for (auto &call : calls) {
    if (call.target_address == 0 || call.target_address == addr)
      continue;

    std::string call_lib = ProcessTracer::find_library_for_address(
        lib_ranges, call.target_address);

    if (!call_lib.empty() && call_lib != ctx.self_library) {
      call.is_external = true;

      if (!ctx.embedded_addresses.count(call.target_address)) {
        recursive_embed(ctx, call.target_address);
      }
    }
  }
  ctx.current_depth--;

  ctx.pending_embeds.push_back({addr, code});
  ctx.total_embedded_size += code.size();
}
