#include "tracer.h"
#include "memory.h"
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <linux/ptrace.h>
#include <set>
#include <signal.h>
#include <sstream>
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

static std::set<int> g_attached_zygote_pids;

void ZygoteTracer::register_attached_pid(int pid) {
  g_attached_zygote_pids.insert(pid);
}

void ZygoteTracer::unregister_attached_pid(int pid) {
  g_attached_zygote_pids.erase(pid);
}

std::set<int> &ZygoteTracer::get_attached_pids() {
  return g_attached_zygote_pids;
}

void ZygoteTracer::cleanup_all_attached() {
  for (int pid : g_attached_zygote_pids) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    kill(pid, SIGCONT);
  }
  g_attached_zygote_pids.clear();
}

struct user_regs_struct_64 {
  uint64_t regs[31];
  uint64_t sp;
  uint64_t pc;
  uint64_t pstate;
};

struct user_regs_struct_32 {
  uint32_t regs[18];
};

static constexpr int SYS_MMAP_64 = 222;
static constexpr int SYS_MUNMAP_64 = 215;
static constexpr int SYS_MPROTECT_64 = 226;
static constexpr int SYS_MMAP2_32 = 192;
static constexpr int SYS_MUNMAP_32 = 91;
static constexpr int SYS_MPROTECT_32 = 125;

static uint64_t execute_syscall(int pid, const std::vector<uint64_t> &args,
                                int syscall_nr) {
  if (g_arch == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs{}, regs{};
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return static_cast<uint64_t>(-1);
    regs = orig_regs;
    for (size_t i = 0; i < args.size() && i < 8; i++)
      regs.regs[i] = args[i];
    regs.regs[8] = syscall_nr;
    uint64_t pc = regs.pc;
    uint32_t orig_inst = 0;
    if (!ProcessTracer::read_memory(pid, pc, &orig_inst, 4))
      return static_cast<uint64_t>(-1);
    uint32_t svc_inst = 0xD4000001;
    if (!ProcessTracer::write_memory(pid, pc, &svc_inst, 4))
      return static_cast<uint64_t>(-1);
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      return static_cast<uint64_t>(-1);
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) < 0) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
      return static_cast<uint64_t>(-1);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
      return static_cast<uint64_t>(-1);
    }
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
      return static_cast<uint64_t>(-1);
    }
    uint64_t result = regs.regs[0];
    (void)ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    iov.iov_len = sizeof(orig_regs);
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    return result;
  } else {
    user_regs_struct_32 orig_regs{}, regs{};
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0)
      return static_cast<uint64_t>(-1);
    regs = orig_regs;
    for (size_t i = 0; i < args.size() && i < 6; i++)
      regs.regs[i] = (uint32_t)args[i];
    regs.regs[7] = syscall_nr;
    uint32_t pc = regs.regs[15];
    uint32_t orig_inst = 0;
    if (!ProcessTracer::read_memory(pid, pc, &orig_inst, 4))
      return static_cast<uint64_t>(-1);
    uint32_t svc_inst = 0xEF000000;
    if (!ProcessTracer::write_memory(pid, pc, &svc_inst, 4))
      return static_cast<uint64_t>(-1);
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      return static_cast<uint64_t>(-1);
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) < 0) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
      return static_cast<uint64_t>(-1);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status)) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
      return static_cast<uint64_t>(-1);
    }
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
      ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
      return static_cast<uint64_t>(-1);
    }
    uint32_t result = regs.regs[0];
    (void)ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    iov.iov_len = sizeof(orig_regs);
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    return result;
  }
}

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
  if ((inst & 0xFFFF0FFF) == 0xE1A0000D)
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
      std::cout << "    [DEBUG] Found Zygote: " << cmd << " (PID: " << pid
                << ")\n";
      closedir(d);
      return pid;
    }
  }
  closedir(d);
  return -1;
}

void ProcessTracer::set_arch(ArchMode mode) { g_arch = mode; }
ArchMode ProcessTracer::get_arch() { return g_arch; }

static std::map<int, int> g_attach_refcount;

bool ProcessTracer::attach(int pid) {
  auto it = g_attach_refcount.find(pid);
  if (it != g_attach_refcount.end() && it->second > 0) {
    it->second++;
    return true;
  }
  if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) < 0)
    return false;
  int status;
  if (waitpid(pid, &status, 0) != pid) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return false;
  }
  if (!WIFSTOPPED(status)) {
    ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
    return false;
  }
  g_attach_refcount[pid] = 1;
  return true;
}

bool ProcessTracer::detach(int pid) {
  auto it = g_attach_refcount.find(pid);
  if (it != g_attach_refcount.end() && it->second > 1) {
    it->second--;
    return true;
  }
  g_attach_refcount.erase(pid);
  return ptrace(PTRACE_DETACH, pid, nullptr, nullptr) >= 0;
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

bool ProcessTracer::set_protection(int pid, uint64_t addr, size_t len,
                                   int prot) {
  int syscall_nr =
      (g_arch == ArchMode::ARM64) ? SYS_MPROTECT_64 : SYS_MPROTECT_32;
  uint64_t ret =
      execute_syscall(pid, {addr, (uint64_t)len, (uint64_t)prot}, syscall_nr);
  return ret == 0;
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
  size_t page_count = (size + 4095) / 4096;
  std::vector<bool> captured(page_count, false);
  std::vector<int> original_prot(page_count, PROT_READ | PROT_EXEC);

  if (!attach(pid))
    return result;

  auto maps = Memory::get_maps(pid);
  for (size_t i = 0; i < page_count; i++) {
    uint64_t page_addr = base + i * 4096;
    for (const auto &m : maps) {
      uint64_t mend = m.base + m.size;
      if (page_addr < m.base || page_addr >= mend)
        continue;
      int prot = 0;
      if (m.perms.find('r') != std::string::npos)
        prot |= PROT_READ;
      if (m.perms.find('w') != std::string::npos)
        prot |= PROT_WRITE;
      if (m.perms.find('x') != std::string::npos)
        prot |= PROT_EXEC;
      original_prot[i] = prot;
      break;
    }
  }

  read_memory(pid, base, result.data(), size);

  for (size_t i = 0; i < page_count; i++) {
    bool has_data = false;
    size_t page_size = std::min<size_t>(4096, size - i * 4096);
    for (size_t j = 0; j < page_size && !has_data; j++) {
      if (result[i * 4096 + j] != 0)
        has_data = true;
    }
    if (has_data) {
      captured[i] = true;
    }
  }

  for (size_t i = 0; i < page_count; i++) {
    if (!captured[i]) {
      size_t page_size = std::min<size_t>(4096, size - i * 4096);
      if (!set_protection(pid, base + i * 4096, page_size, PROT_NONE))
        captured[i] = true;
    }
  }

  if (!continue_process(pid)) {
    for (size_t i = 0; i < captured.size(); i++) {
      if (!captured[i]) {
        set_protection(pid, base + i * 4096,
                       std::min<size_t>(4096, size - i * 4096),
                       original_prot[i]);
      }
    }
    detach(pid);
    return result;
  }
  time_t start = time(nullptr);

  while (time(nullptr) - start < duration_sec) {
    int status;
    pid_t wpid = waitpid(pid, &status, WNOHANG);

    if (wpid == pid && WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);

      if (sig == SIGSEGV) {
        siginfo_t si;
        if (ptrace(PTRACE_GETSIGINFO, pid, nullptr, &si) >= 0) {
          uint64_t fault_addr = (uint64_t)si.si_addr;

          if (fault_addr >= base && fault_addr < base + size) {
            size_t page_idx = (fault_addr - base) / 4096;

            if (page_idx < captured.size() && !captured[page_idx]) {
              size_t page_size = std::min<size_t>(4096, size - page_idx * 4096);

              if (!set_protection(pid, base + page_idx * 4096, page_size,
                                  original_prot[page_idx])) {
                continue;
              }

              std::vector<uint8_t> page_data(page_size);
              read_memory(pid, base + page_idx * 4096, page_data.data(),
                          page_size);
              memcpy(result.data() + page_idx * 4096, page_data.data(),
                     page_size);
              captured[page_idx] = true;
            }
          } else {
            for (size_t i = 0; i < captured.size(); i++) {
              if (!captured[i]) {
                set_protection(pid, base + i * 4096,
                               std::min<size_t>(4096, size - i * 4096),
                               original_prot[i]);
                captured[i] = true;
              }
            }
          }
        }
        if (!continue_process(pid))
          break;
      } else {
        ptrace(PTRACE_CONT, pid, nullptr, (void *)(long)sig);
      }
    } else if (wpid == pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
      break;
    }

    usleep(1000);
  }

  for (size_t i = 0; i < captured.size(); i++) {
    if (!captured[i]) {
      set_protection(pid, base + i * 4096,
                     std::min<size_t>(4096, size - i * 4096),
                     original_prot[i]);
    }
  }

  detach(pid);
  return result;
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
      name = path;
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
  int syscall_nr = (g_arch == ArchMode::ARM64) ? SYS_MMAP_64 : SYS_MMAP2_32;
  uint64_t result = execute_syscall(
      pid,
      {0, (uint64_t)size, (uint64_t)(PROT_READ | PROT_WRITE | PROT_EXEC),
       (uint64_t)(MAP_PRIVATE | MAP_ANONYMOUS), (uint64_t)-1, 0},
      syscall_nr);
  return (result == (uint64_t)-1) ? 0 : result;
}

bool FunctionHooker::free_remote(int pid, uint64_t addr, size_t size) {
  int syscall_nr = (g_arch == ArchMode::ARM64) ? SYS_MUNMAP_64 : SYS_MUNMAP_32;
  uint64_t ret = execute_syscall(pid, {addr, (uint64_t)size}, syscall_nr);
  return ret == 0;
}

template <typename Ehdr, typename Phdr, typename Dyn, typename Sym>
static uint64_t parse_remote_symbol_impl(int pid, uint64_t lib_base,
                                         const std::string &sym) {
  constexpr size_t ehdr_sz = sizeof(Ehdr);
  constexpr size_t phdr_sz = sizeof(Phdr);
  constexpr size_t dyn_sz = sizeof(Dyn);
  constexpr size_t sym_sz = sizeof(Sym);
  constexpr bool is64 =
      (sizeof(
           typename std::remove_pointer<decltype(((Ehdr *)nullptr))>::type) ==
       sizeof(Elf64_Ehdr));

  uint8_t ehdr_buf[ehdr_sz];
  if (!ProcessTracer::read_memory(pid, lib_base, ehdr_buf, ehdr_sz))
    return 0;
  Ehdr *ehdr = (Ehdr *)ehdr_buf;
  if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
    return 0;

  uint64_t phdr_off = ehdr->e_phoff;
  uint16_t phnum = ehdr->e_phnum;
  uint16_t phentsize = ehdr->e_phentsize;
  uint64_t dyn_vaddr = 0, dyn_size = 0;

  for (uint16_t i = 0; i < phnum; i++) {
    uint8_t phdr_buf[phdr_sz];
    if (!ProcessTracer::read_memory(pid, lib_base + phdr_off + i * phentsize,
                                    phdr_buf, phdr_sz))
      continue;
    Phdr *phdr = (Phdr *)phdr_buf;
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
  for (uint64_t off = 0; off < dyn_size; off += dyn_sz) {
    uint8_t dyn_buf[dyn_sz];
    if (!ProcessTracer::read_memory(pid, lib_base + dyn_vaddr + off, dyn_buf,
                                    dyn_sz))
      break;
    Dyn *dyn = (Dyn *)dyn_buf;
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
      size_t bloom_entry_sz = is64 ? 8 : 4;
      uint64_t buckets_addr = gnu_hash + 16 + bloom_size * bloom_entry_sz;
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
        uint32_t guard = 0;
        while (guard++ < (1u << 20)) {
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

  auto read_remote_cstr = [&](uint64_t addr, size_t max_len) -> std::string {
    std::string out;
    out.reserve(std::min<size_t>(max_len, 256));
    size_t off = 0;
    while (off < max_len) {
      char chunk[64];
      size_t to_read = std::min(sizeof(chunk), max_len - off);
      if (!ProcessTracer::read_memory(pid, addr + off, chunk, to_read))
        break;
      for (size_t i = 0; i < to_read; i++) {
        if (chunk[i] == '\0')
          return out;
        out.push_back(chunk[i]);
      }
      off += to_read;
    }
    return out;
  };

  for (size_t i = 0; i < nchain; i++) {
    uint8_t sym_buf[sym_sz];
    if (!ProcessTracer::read_memory(pid, symtab + i * sym_sz, sym_buf, sym_sz))
      break;
    Sym *s = (Sym *)sym_buf;
    if (s->st_name == 0 || s->st_value == 0)
      continue;
    std::string name = read_remote_cstr(strtab + s->st_name, 4096);
    if (name == sym)
      return s->st_value;
  }
  return 0;
}

uint64_t FunctionHooker::find_remote_symbol(int pid, const std::string &lib,
                                            const std::string &sym) {
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  std::vector<uint64_t> candidate_bases;
  while (std::getline(maps, line)) {
    if (line.find("r-xp") == std::string::npos &&
        line.find("r--p") == std::string::npos)
      continue;
    size_t path_pos = line.find('/');
    if (path_pos == std::string::npos)
      continue;
    std::string path = line.substr(path_pos);
    while (!path.empty() && (path.back() == ' ' || path.back() == '\n'))
      path.pop_back();
    size_t slash = path.rfind('/');
    std::string base_name =
        (slash != std::string::npos) ? path.substr(slash + 1) : path;
    if (base_name != lib && path.find("/" + lib) == std::string::npos)
      continue;
    uint64_t base = 0;
    uint64_t map_off = 0;
    if (sscanf(line.c_str(), "%lx-%*lx %*4s %lx", (unsigned long *)&base,
               (unsigned long *)&map_off) < 2)
      continue;
    if (map_off == 0)
      candidate_bases.insert(candidate_bases.begin(), base);
    else
      candidate_bases.push_back(base);
  }
  for (uint64_t base : candidate_bases) {
    uint64_t offset;
    if (g_arch == ArchMode::ARM64) {
      offset = parse_remote_symbol_impl<Elf64_Ehdr, Elf64_Phdr, Elf64_Dyn,
                                        Elf64_Sym>(pid, base, sym);
    } else {
      offset = parse_remote_symbol_impl<Elf32_Ehdr, Elf32_Phdr, Elf32_Dyn,
                                        Elf32_Sym>(pid, base, sym);
    }
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
    uint32_t jmp_back[2] = {0x58000050, 0xD61F0200};
    memcpy(tramp_code + 16, jmp_back, 8);
    uint64_t ret_addr = target + 16;
    memcpy(tramp_code + 24, &ret_addr, 8);
    if (!ProcessTracer::write_memory(pid, trampoline, tramp_code, 32)) {
      free_remote(pid, trampoline, 64);
      return false;
    }
    if (original)
      *original = trampoline;
    uint32_t hook_jmp[2] = {0x58000050, 0xD61F0200};
    uint8_t patch[16];
    memcpy(patch, hook_jmp, 8);
    memcpy(patch + 8, &hook, 8);
    if (!ProcessTracer::write_memory(pid, target, patch, sizeof(patch))) {
      free_remote(pid, trampoline, 64);
      return false;
    }
    return true;
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
    if (!ProcessTracer::write_memory(pid, trampoline, tramp_code, 16)) {
      free_remote(pid, trampoline, 32);
      return false;
    }
    if (original)
      *original = trampoline;
    uint32_t hook_jmp[2] = {0xE51FF004, (uint32_t)hook};
    if (!ProcessTracer::write_memory(pid, target, hook_jmp, 8)) {
      free_remote(pid, trampoline, 32);
      return false;
    }
    return true;
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
  if (lib_path.empty())
    return false;
  uint64_t handle = MemoryInjector::remote_dlopen(pid, lib_path, RTLD_NOW);
  return handle != 0;
}

std::vector<RelinkEntry>
StaticRelinker::find_external_calls(const std::vector<uint8_t> &data,
                                    uint64_t base) {
  (void)base;
  std::vector<RelinkEntry> entries;
  if (data.size() < 64)
    return entries;
  bool is32 = (data[4] == ELFCLASS32);
  if (is32) {
    const Elf32_Ehdr *ehdr = reinterpret_cast<const Elf32_Ehdr *>(data.data());
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
      return entries;
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 ||
        ehdr->e_phentsize != sizeof(Elf32_Phdr))
      return entries;
    size_t ph_end = static_cast<size_t>(ehdr->e_phoff) +
                    static_cast<size_t>(ehdr->e_phnum) * sizeof(Elf32_Phdr);
    if (ph_end > data.size())
      return entries;
    uint32_t dyn_off = 0, dyn_sz = 0;
    const Elf32_Phdr *phdrs = reinterpret_cast<const Elf32_Phdr *>(
        data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      const Elf32_Phdr *ph = &phdrs[i];
      if (ph->p_type == PT_DYNAMIC) {
        dyn_off = ph->p_offset;
        dyn_sz = ph->p_filesz;
        break;
      }
    }
    if (dyn_off == 0 || dyn_off >= data.size())
      return entries;
    if (dyn_off + dyn_sz > data.size())
      dyn_sz = data.size() - dyn_off;
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

    auto vaddr_to_off = [&](uint32_t vaddr, uint32_t &out) -> bool {
      if (vaddr < data.size()) {
        out = vaddr;
        return true;
      }
      for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf32_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD)
          continue;
        uint64_t seg_start = ph->p_vaddr;
        uint64_t seg_end = ph->p_vaddr + ph->p_memsz;
        if (vaddr < seg_start || vaddr >= seg_end)
          continue;
        uint64_t off = ph->p_offset + (static_cast<uint64_t>(vaddr) - seg_start);
        if (off >= data.size())
          return false;
        out = static_cast<uint32_t>(off);
        return true;
      }
      return false;
    };

    uint32_t jmprel_off = 0, symtab_off = 0, strtab_off = 0;
    if (!vaddr_to_off(jmprel, jmprel_off) || !vaddr_to_off(symtab, symtab_off) ||
        !vaddr_to_off(strtab, strtab_off))
      return entries;

    size_t count = pltrelsz / sizeof(Elf32_Rel);
    for (size_t i = 0; i < count; i++) {
      uint64_t rel_off = static_cast<uint64_t>(jmprel_off) +
                         i * sizeof(Elf32_Rel);
      if (rel_off + sizeof(Elf32_Rel) > data.size())
        break;
      auto rel = reinterpret_cast<const Elf32_Rel *>(data.data() + rel_off);
      uint32_t sym_idx = ELF32_R_SYM(rel->r_info);
      uint64_t sym_off = static_cast<uint64_t>(symtab_off) +
                         static_cast<uint64_t>(sym_idx) * sizeof(Elf32_Sym);
      if (sym_off + sizeof(Elf32_Sym) > data.size())
        continue;
      auto sym = reinterpret_cast<const Elf32_Sym *>(data.data() + sym_off);
      uint64_t name_off = static_cast<uint64_t>(strtab_off) + sym->st_name;
      if (sym->st_name == 0 || name_off >= data.size())
        continue;
      RelinkEntry entry;
      entry.call_site = rel->r_offset;
      entry.target_addr = 0;
      entry.symbol_name = reinterpret_cast<const char *>(data.data() + name_off);
      entries.push_back(entry);
    }
  } else {
    const Elf64_Ehdr *ehdr = reinterpret_cast<const Elf64_Ehdr *>(data.data());
    if (memcmp(ehdr->e_ident, ELFMAG, 4) != 0)
      return entries;
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 ||
        ehdr->e_phentsize != sizeof(Elf64_Phdr))
      return entries;
    size_t ph_end = static_cast<size_t>(ehdr->e_phoff) +
                    static_cast<size_t>(ehdr->e_phnum) * sizeof(Elf64_Phdr);
    if (ph_end > data.size())
      return entries;
    uint64_t dyn_off = 0, dyn_sz = 0;
    const Elf64_Phdr *phdrs = reinterpret_cast<const Elf64_Phdr *>(
        data.data() + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
      const Elf64_Phdr *ph = &phdrs[i];
      if (ph->p_type == PT_DYNAMIC) {
        dyn_off = ph->p_offset;
        dyn_sz = ph->p_filesz;
        break;
      }
    }
    if (dyn_off == 0 || dyn_off >= data.size())
      return entries;
    if (dyn_off + dyn_sz > data.size())
      dyn_sz = data.size() - dyn_off;
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

    auto vaddr_to_off = [&](uint64_t vaddr, uint64_t &out) -> bool {
      if (vaddr < data.size()) {
        out = vaddr;
        return true;
      }
      for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD)
          continue;
        uint64_t seg_start = ph->p_vaddr;
        uint64_t seg_end = ph->p_vaddr + ph->p_memsz;
        if (vaddr < seg_start || vaddr >= seg_end)
          continue;
        uint64_t off = ph->p_offset + (vaddr - seg_start);
        if (off >= data.size())
          return false;
        out = off;
        return true;
      }
      return false;
    };

    uint64_t jmprel_off = 0, symtab_off = 0, strtab_off = 0;
    if (!vaddr_to_off(jmprel, jmprel_off) || !vaddr_to_off(symtab, symtab_off) ||
        !vaddr_to_off(strtab, strtab_off))
      return entries;

    size_t count = pltrelsz / sizeof(Elf64_Rela);
    for (size_t i = 0; i < count; i++) {
      uint64_t rel_off = jmprel_off + i * sizeof(Elf64_Rela);
      if (rel_off + sizeof(Elf64_Rela) > data.size())
        break;
      auto rela = reinterpret_cast<const Elf64_Rela *>(data.data() + rel_off);
      uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
      uint64_t sym_off = symtab_off + sym_idx * sizeof(Elf64_Sym);
      if (sym_off + sizeof(Elf64_Sym) > data.size())
        continue;
      auto sym = reinterpret_cast<const Elf64_Sym *>(data.data() + sym_off);
      uint64_t name_off = strtab_off + sym->st_name;
      if (sym->st_name == 0 || name_off >= data.size())
        continue;
      RelinkEntry entry;
      entry.call_site = rela->r_offset;
      entry.target_addr = 0;
      entry.symbol_name = reinterpret_cast<const char *>(data.data() + name_off);
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

std::vector<uint8_t>
StaticRelinker::relink(const std::vector<uint8_t> &elf_data, int pid,
                       uint64_t base_addr) {
  RelinkConfig cfg{};
  cfg.max_depth = 8;
  cfg.max_total_size = 64 * 1024 * 1024;
  cfg.fix_relocations = true;
  cfg.inline_plt_calls = true;
  return StaticRelinkerEx::relink_full(elf_data, pid, base_addr, cfg);
}

uint64_t MemoryInjector::remote_mmap(int pid, uint64_t addr, size_t size,
                                     int prot, int flags) {
  if (!ProcessTracer::attach(pid))
    return 0;

  int syscall_nr = (g_arch == ArchMode::ARM64) ? SYS_MMAP_64 : SYS_MMAP2_32;
  uint64_t ret = execute_syscall(
      pid,
      {addr, (uint64_t)size, (uint64_t)prot, (uint64_t)flags, (uint64_t)-1, 0},
      syscall_nr);
  ProcessTracer::detach(pid);
  return (ret == (uint64_t)-1) ? 0 : ret;
}

bool MemoryInjector::remote_munmap(int pid, uint64_t addr, size_t size) {
  if (!ProcessTracer::attach(pid))
    return false;

  int syscall_nr = (g_arch == ArchMode::ARM64) ? SYS_MUNMAP_64 : SYS_MUNMAP_32;
  uint64_t ret = execute_syscall(pid, {addr, (uint64_t)size}, syscall_nr);
  ProcessTracer::detach(pid);
  return (ret == 0);
}

bool MemoryInjector::remote_mprotect(int pid, uint64_t addr, size_t size,
                                     int prot) {
  return ProcessTracer::set_protection(pid, addr, size, prot);
}

RemoteCallResult
MemoryInjector::call_remote(int pid, uint64_t func_addr,
                            const std::vector<uint64_t> &args) {
  RemoteCallResult result = {0, false, 0, ""};

  if (!ProcessTracer::attach(pid)) {
    result.error_message = "Failed to attach";
    return result;
  }

  if (ProcessTracer::get_arch() == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs{}, regs{};
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    uint64_t stub_addr = 0;
    bool have_orig_regs = false;

    do {
      if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
        result.error_message = "Failed to get registers";
        break;
      }
      have_orig_regs = true;
      regs = orig_regs;

      for (size_t i = 0; i < args.size() && i < 8; i++) {
        regs.regs[i] = args[i];
      }

      if (args.size() > 8) {
        size_t stack_args = args.size() - 8;
        regs.sp -= stack_args * 8;
        regs.sp &= ~0xFULL;
        for (size_t i = 8; i < args.size(); i++) {
          uint64_t val = args[i];
          if (!ProcessTracer::write_memory(pid, regs.sp + (i - 8) * 8, &val, 8)) {
            result.error_message = "Failed to write stack args";
            break;
          }
        }
        if (!result.error_message.empty())
          break;
      }

      stub_addr = FunctionHooker::allocate_remote(pid, 32);
      if (stub_addr == 0) {
        result.error_message = "Failed to allocate stub";
        break;
      }

      uint32_t stub_code[] = {
          0x58000049,
          0xD63F0120,
          0xD4200000,
          0x00000000,
      };
      if (!ProcessTracer::write_memory(pid, stub_addr, stub_code, sizeof(stub_code)) ||
          !ProcessTracer::write_memory(pid, stub_addr + 16, &func_addr,
                                      sizeof(func_addr))) {
        result.error_message = "Failed to write stub";
        break;
      }

      regs.regs[30] = stub_addr + 8;
      regs.pc = stub_addr;

      iov.iov_base = &regs;
      iov.iov_len = sizeof(regs);
      if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
        result.error_message = "Failed to set registers";
        break;
      }
      if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        result.error_message = "Failed to continue process";
        break;
      }

      int status = 0;
      if (waitpid(pid, &status, 0) != pid) {
        result.error_message = "waitpid failed";
        break;
      }
      if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        result.error_message = "Unexpected stop signal";
        break;
      }

      iov.iov_base = &regs;
      iov.iov_len = sizeof(regs);
      if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
        result.error_message = "Failed to read result registers";
        break;
      }
      result.return_value = regs.regs[0];
      result.success = true;
    } while (false);

    if (have_orig_regs) {
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    }
    if (stub_addr != 0)
      FunctionHooker::free_remote(pid, stub_addr, 32);
  } else {
    user_regs_struct_32 orig_regs{}, regs{};
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    uint64_t stub_addr = 0;
    bool have_orig_regs = false;

    do {
      if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
        result.error_message = "Failed to get registers";
        break;
      }
      have_orig_regs = true;
      regs = orig_regs;

      for (size_t i = 0; i < args.size() && i < 4; i++) {
        regs.regs[i] = static_cast<uint32_t>(args[i]);
      }

      if (args.size() > 4) {
        size_t stack_args = args.size() - 4;
        regs.regs[13] -= stack_args * 4;
        regs.regs[13] &= ~0x7;
        for (size_t i = 4; i < args.size(); i++) {
          uint32_t val = static_cast<uint32_t>(args[i]);
          if (!ProcessTracer::write_memory(pid, regs.regs[13] + (i - 4) * 4,
                                           &val, 4)) {
            result.error_message = "Failed to write stack args";
            break;
          }
        }
        if (!result.error_message.empty())
          break;
      }

      stub_addr = FunctionHooker::allocate_remote(pid, 16);
      if (stub_addr == 0) {
        result.error_message = "Failed to allocate stub";
        break;
      }

      uint32_t stub_code[] = {
          0xE59FC004,
          0xE12FFF3C,
          0xE1200070,
          static_cast<uint32_t>(func_addr),
      };
      if (!ProcessTracer::write_memory(pid, stub_addr, stub_code,
                                       sizeof(stub_code))) {
        result.error_message = "Failed to write stub";
        break;
      }

      regs.regs[14] = static_cast<uint32_t>(stub_addr + 8);
      regs.regs[15] = static_cast<uint32_t>(stub_addr);

      iov.iov_base = &regs;
      iov.iov_len = sizeof(regs);
      if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
        result.error_message = "Failed to set registers";
        break;
      }
      if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0) {
        result.error_message = "Failed to continue process";
        break;
      }

      int status = 0;
      if (waitpid(pid, &status, 0) != pid) {
        result.error_message = "waitpid failed";
        break;
      }
      if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        result.error_message = "Unexpected stop signal";
        break;
      }

      iov.iov_base = &regs;
      iov.iov_len = sizeof(regs);
      if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
        result.error_message = "Failed to read result registers";
        break;
      }
      result.return_value = regs.regs[0];
      result.success = true;
    } while (false);

    if (have_orig_regs) {
      iov.iov_base = &orig_regs;
      iov.iov_len = sizeof(orig_regs);
      ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    }
    if (stub_addr != 0)
      FunctionHooker::free_remote(pid, stub_addr, 16);
  }

  ProcessTracer::detach(pid);
  return result;
}

RemoteCallResult
MemoryInjector::call_remote_void(int pid, uint64_t func_addr,
                                 const std::vector<uint64_t> &args) {
  return call_remote(pid, func_addr, args);
}

uint64_t MemoryInjector::remote_dlopen(int pid, const std::string &path,
                                       int flags) {

  uint64_t dlopen_addr =
      FunctionHooker::find_remote_symbol(pid, "libdl.so", "dlopen");
  if (dlopen_addr == 0)
    dlopen_addr =
        FunctionHooker::find_remote_symbol(pid, "libc.so", "__loader_dlopen");
  if (dlopen_addr == 0)
    dlopen_addr = find_linker_function(pid, "__loader_dlopen");
  if (dlopen_addr == 0)
    return 0;

  if (!ProcessTracer::attach(pid))
    return 0;

  size_t path_len = path.size() + 1;
  uint64_t path_addr = FunctionHooker::allocate_remote(pid, path_len);
  if (path_addr == 0) {
    ProcessTracer::detach(pid);
    return 0;
  }

  if (!ProcessTracer::write_memory(pid, path_addr, path.c_str(), path_len)) {
    FunctionHooker::free_remote(pid, path_addr, path_len);
    ProcessTracer::detach(pid);
    return 0;
  }

  std::vector<uint64_t> args = {path_addr, (uint64_t)flags};
  auto result = call_remote(pid, dlopen_addr, args);

  FunctionHooker::free_remote(pid, path_addr, path_len);
  ProcessTracer::detach(pid);

  return result.success ? result.return_value : 0;
}

uint64_t MemoryInjector::remote_dlsym(int pid, uint64_t handle,
                                      const std::string &symbol) {
  uint64_t dlsym_addr =
      FunctionHooker::find_remote_symbol(pid, "libdl.so", "dlsym");
  if (dlsym_addr == 0)
    dlsym_addr =
        FunctionHooker::find_remote_symbol(pid, "libc.so", "__loader_dlsym");
  if (dlsym_addr == 0)
    return 0;

  if (!ProcessTracer::attach(pid))
    return 0;

  size_t sym_len = symbol.size() + 1;
  uint64_t sym_addr = FunctionHooker::allocate_remote(pid, sym_len);
  if (sym_addr == 0) {
    ProcessTracer::detach(pid);
    return 0;
  }

  if (!ProcessTracer::write_memory(pid, sym_addr, symbol.c_str(), sym_len)) {
    FunctionHooker::free_remote(pid, sym_addr, sym_len);
    ProcessTracer::detach(pid);
    return 0;
  }

  std::vector<uint64_t> args = {handle, sym_addr};
  auto result = call_remote(pid, dlsym_addr, args);

  FunctionHooker::free_remote(pid, sym_addr, sym_len);
  ProcessTracer::detach(pid);

  return result.success ? result.return_value : 0;
}

bool MemoryInjector::remote_dlclose(int pid, uint64_t handle) {
  uint64_t dlclose_addr =
      FunctionHooker::find_remote_symbol(pid, "libdl.so", "dlclose");
  if (dlclose_addr == 0)
    dlclose_addr =
        FunctionHooker::find_remote_symbol(pid, "libc.so", "__loader_dlclose");
  if (dlclose_addr == 0)
    return false;

  std::vector<uint64_t> args = {handle};
  auto result = call_remote(pid, dlclose_addr, args);

  return result.success && result.return_value == 0;
}

std::string MemoryInjector::remote_dlerror(int pid) {
  uint64_t dlerror_addr =
      FunctionHooker::find_remote_symbol(pid, "libdl.so", "dlerror");
  if (dlerror_addr == 0)
    return "";

  std::vector<uint64_t> args;
  auto result = call_remote(pid, dlerror_addr, args);

  if (!result.success || result.return_value == 0)
    return "";

  return read_string_remote(pid, result.return_value, 256);
}

bool MemoryInjector::inject_shellcode(int pid,
                                      const std::vector<uint8_t> &shellcode,
                                      uint64_t *exec_addr) {
  size_t size = (shellcode.size() + 4095) & ~4095;
  uint64_t addr = remote_mmap(pid, 0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS);
  if (addr == 0)
    return false;

  if (!ProcessTracer::write_memory(pid, addr, shellcode.data(),
                                   shellcode.size())) {
    remote_munmap(pid, addr, size);
    return false;
  }

  if (exec_addr)
    *exec_addr = addr;

  return true;
}

bool MemoryInjector::inject_and_run_shellcode(
    int pid, const std::vector<uint8_t> &shellcode, uint64_t *result) {
  uint64_t exec_addr;
  if (!inject_shellcode(pid, shellcode, &exec_addr))
    return false;

  std::vector<uint64_t> args;
  auto call_result = call_remote(pid, exec_addr, args);

  size_t size = (shellcode.size() + 4095) & ~4095;
  remote_munmap(pid, exec_addr, size);

  if (result)
    *result = call_result.return_value;

  return call_result.success;
}

std::vector<uint8_t>
MemoryInjector::generate_shellcode_arm64(uint64_t func_addr,
                                         const std::vector<uint64_t> &args) {
  std::vector<uint8_t> code;

  for (size_t i = 0; i < args.size() && i < 8; i++) {
    uint64_t arg = args[i];

    if (arg <= 0xFFFF) {
      uint32_t movz = 0xD2800000 | (i & 0x1F) | ((arg & 0xFFFF) << 5);
      code.insert(code.end(), (uint8_t *)&movz, (uint8_t *)&movz + 4);
    } else {

      uint32_t movz = 0xD2800000 | (i & 0x1F) | (((arg >> 0) & 0xFFFF) << 5);
      uint32_t movk1 = 0xF2A00000 | (i & 0x1F) | (((arg >> 16) & 0xFFFF) << 5);
      uint32_t movk2 = 0xF2C00000 | (i & 0x1F) | (((arg >> 32) & 0xFFFF) << 5);
      uint32_t movk3 = 0xF2E00000 | (i & 0x1F) | (((arg >> 48) & 0xFFFF) << 5);
      code.insert(code.end(), (uint8_t *)&movz, (uint8_t *)&movz + 4);
      code.insert(code.end(), (uint8_t *)&movk1, (uint8_t *)&movk1 + 4);
      code.insert(code.end(), (uint8_t *)&movk2, (uint8_t *)&movk2 + 4);
      code.insert(code.end(), (uint8_t *)&movk3, (uint8_t *)&movk3 + 4);
    }
  }

  uint32_t mov_x9[] = {
      static_cast<uint32_t>(0xD2800009 | (((func_addr >> 0) & 0xFFFF) << 5)),
      static_cast<uint32_t>(0xF2A00009 | (((func_addr >> 16) & 0xFFFF) << 5)),
      static_cast<uint32_t>(0xF2C00009 | (((func_addr >> 32) & 0xFFFF) << 5)),
      static_cast<uint32_t>(0xF2E00009 | (((func_addr >> 48) & 0xFFFF) << 5)),
  };
  for (auto inst : mov_x9)
    code.insert(code.end(), (uint8_t *)&inst, (uint8_t *)&inst + 4);

  uint32_t blr = 0xD63F0120;
  code.insert(code.end(), (uint8_t *)&blr, (uint8_t *)&blr + 4);

  uint32_t ret = 0xD65F03C0;
  code.insert(code.end(), (uint8_t *)&ret, (uint8_t *)&ret + 4);

  return code;
}

std::vector<uint8_t>
MemoryInjector::generate_shellcode_arm32(uint64_t func_addr,
                                         const std::vector<uint64_t> &args) {
  std::vector<uint8_t> code;

  for (size_t i = 0; i < args.size() && i < 4; i++) {
    uint32_t arg = (uint32_t)args[i];

    uint32_t mov = 0xE3A00000 | ((i & 0xF) << 12) | (arg & 0xFF);
    uint32_t orr1 = 0xE3800C00 | ((i & 0xF) << 12) | ((i & 0xF) << 16) |
                    ((arg >> 8) & 0xFF);
    uint32_t orr2 = 0xE3800800 | ((i & 0xF) << 12) | ((i & 0xF) << 16) |
                    ((arg >> 16) & 0xFF);
    uint32_t orr3 = 0xE3800400 | ((i & 0xF) << 12) | ((i & 0xF) << 16) |
                    ((arg >> 24) & 0xFF);
    code.insert(code.end(), (uint8_t *)&mov, (uint8_t *)&mov + 4);
    code.insert(code.end(), (uint8_t *)&orr1, (uint8_t *)&orr1 + 4);
    code.insert(code.end(), (uint8_t *)&orr2, (uint8_t *)&orr2 + 4);
    code.insert(code.end(), (uint8_t *)&orr3, (uint8_t *)&orr3 + 4);
  }

  uint32_t ldr_r12 = 0xE59FC000;
  uint32_t blx_r12 = 0xE12FFF3C;
  uint32_t bx_lr = 0xE12FFF1E;
  uint32_t addr = (uint32_t)func_addr;

  code.insert(code.end(), (uint8_t *)&ldr_r12, (uint8_t *)&ldr_r12 + 4);
  code.insert(code.end(), (uint8_t *)&blx_r12, (uint8_t *)&blx_r12 + 4);
  code.insert(code.end(), (uint8_t *)&bx_lr, (uint8_t *)&bx_lr + 4);
  code.insert(code.end(), (uint8_t *)&addr, (uint8_t *)&addr + 4);

  return code;
}

bool MemoryInjector::install_inline_hook(int pid, uint64_t target,
                                         uint64_t hook, HookInfo *info) {
  if (!info)
    return false;

  info->target_addr = target;
  info->hook_addr = hook;
  info->active = false;

  if (ProcessTracer::get_arch() == ArchMode::ARM64) {
    info->patch_size = 16;
    info->original_bytes.resize(16);

    if (!ProcessTracer::read_memory(pid, target, info->original_bytes.data(),
                                    16))
      return false;

    info->trampoline_addr = FunctionHooker::allocate_remote(pid, 32);
    if (info->trampoline_addr == 0)
      return false;

    std::vector<uint8_t> tramp(32);
    memcpy(tramp.data(), info->original_bytes.data(), 16);
    uint64_t ret_addr = target + 16;
    uint32_t jmp_back[] = {
        0x58000050,
        0xD61F0200,
    };
    memcpy(tramp.data() + 16, jmp_back, 8);
    memcpy(tramp.data() + 24, &ret_addr, 8);

    if (!ProcessTracer::write_memory(pid, info->trampoline_addr, tramp.data(),
                                     32)) {
      FunctionHooker::free_remote(pid, info->trampoline_addr, 32);
      return false;
    }

    uint32_t hook_jmp[] = {
        0x58000050,
        0xD61F0200,
    };
    std::vector<uint8_t> patch(16);
    memcpy(patch.data(), hook_jmp, 8);
    memcpy(patch.data() + 8, &hook, 8);

    if (!ProcessTracer::write_memory(pid, target, patch.data(), 16)) {
      FunctionHooker::free_remote(pid, info->trampoline_addr, 32);
      return false;
    }
  } else {
    info->patch_size = 8;
    info->original_bytes.resize(8);

    if (!ProcessTracer::read_memory(pid, target, info->original_bytes.data(),
                                    8))
      return false;

    info->trampoline_addr = FunctionHooker::allocate_remote(pid, 16);
    if (info->trampoline_addr == 0)
      return false;

    std::vector<uint8_t> tramp(16);
    memcpy(tramp.data(), info->original_bytes.data(), 8);
    uint32_t ret_addr = (uint32_t)(target + 8);
    uint32_t jmp_back[] = {0xE51FF004, ret_addr};
    memcpy(tramp.data() + 8, jmp_back, 8);

    if (!ProcessTracer::write_memory(pid, info->trampoline_addr, tramp.data(),
                                     16)) {
      FunctionHooker::free_remote(pid, info->trampoline_addr, 16);
      return false;
    }

    uint32_t hook32 = (uint32_t)hook;
    uint32_t hook_jmp[] = {0xE51FF004, hook32};
    if (!ProcessTracer::write_memory(pid, target, hook_jmp, 8)) {
      FunctionHooker::free_remote(pid, info->trampoline_addr, 16);
      return false;
    }
  }

  info->active = true;
  return true;
}

bool MemoryInjector::remove_inline_hook(int pid, const HookInfo &info) {
  if (!info.active)
    return false;

  if (!ProcessTracer::write_memory(pid, info.target_addr,
                                   info.original_bytes.data(),
                                   info.original_bytes.size()))
    return false;

  size_t tramp_size = (ProcessTracer::get_arch() == ArchMode::ARM64) ? 32 : 16;
  FunctionHooker::free_remote(pid, info.trampoline_addr, tramp_size);

  return true;
}

bool MemoryInjector::hook_got_entry(int pid, uint64_t got_addr,
                                    uint64_t new_value, uint64_t *old_value) {
  size_t ptr_size = (ProcessTracer::get_arch() == ArchMode::ARM64) ? 8 : 4;

  if (old_value) {
    if (!ProcessTracer::read_memory(pid, got_addr, old_value, ptr_size))
      return false;
  }

  return ProcessTracer::write_memory(pid, got_addr, &new_value, ptr_size);
}

bool MemoryInjector::hook_plt_entry(int pid, uint64_t base,
                                    const std::string &symbol, uint64_t hook) {
  uint64_t got_addr = find_got_entry(pid, base, symbol);
  if (got_addr == 0)
    return false;

  return hook_got_entry(pid, got_addr, hook, nullptr);
}

uint64_t MemoryInjector::find_got_entry(int pid, uint64_t base,
                                        const std::string &symbol) {

  std::vector<uint8_t> elf_data(0x10000);
  if (!ProcessTracer::read_memory(pid, base, elf_data.data(), elf_data.size()))
    return 0;

  auto entries = ElfParser::get_plt_entries(elf_data);
  for (const auto &entry : entries) {
    if (entry.symbol_name == symbol)
      return base + entry.got_offset;
  }

  return 0;
}

uint64_t MemoryInjector::find_libc_function(int pid,
                                            const std::string &func_name) {
  return FunctionHooker::find_remote_symbol(pid, "libc.so", func_name);
}

uint64_t MemoryInjector::find_linker_function(int pid,
                                              const std::string &func_name) {
  uint64_t addr =
      FunctionHooker::find_remote_symbol(pid, "linker64", func_name);
  if (addr == 0)
    addr = FunctionHooker::find_remote_symbol(pid, "linker", func_name);
  return addr;
}

bool MemoryInjector::write_string_remote(int pid, uint64_t addr,
                                         const std::string &str) {
  return ProcessTracer::write_memory(pid, addr, str.c_str(), str.size() + 1);
}

std::string MemoryInjector::read_string_remote(int pid, uint64_t addr,
                                               size_t max_len) {
  std::vector<char> buf(max_len + 1, 0);
  if (!ProcessTracer::read_memory(pid, addr, buf.data(), max_len))
    return "";

  buf[max_len] = 0;
  return std::string(buf.data());
}

std::vector<std::pair<std::string, uint64_t>>
MemoryInjector::find_jni_functions(int pid, const std::string &lib_name) {
  std::vector<std::pair<std::string, uint64_t>> jni_funcs;

  auto ranges = ProcessTracer::get_library_ranges(pid);
  uint64_t lib_base = 0;
  for (const auto &r : ranges) {
    if (r.name.find(lib_name) != std::string::npos) {
      lib_base = r.start;
      break;
    }
  }

  if (lib_base == 0)
    return jni_funcs;

  std::vector<uint8_t> elf_data(0x100000);
  if (!ProcessTracer::read_memory(pid, lib_base, elf_data.data(),
                                  elf_data.size()))
    return jni_funcs;

  auto symbols = ElfParser::get_symbols(elf_data);
  for (const auto &sym : symbols) {

    if (sym.name.find("Java_") == 0) {
      jni_funcs.push_back({sym.name, lib_base + sym.offset});
    }
  }

  return jni_funcs;
}

bool MemoryInjector::hook_jni_function(int pid, uint64_t jni_func,
                                       uint64_t hook, uint64_t *original) {
  HookInfo info;
  bool success = install_inline_hook(pid, jni_func, hook, &info);
  if (success && original)
    *original = info.trampoline_addr;
  return success;
}

std::vector<std::pair<std::string, uint64_t>>
MemoryInjector::dump_got(int pid, uint64_t base,
                         const std::vector<uint8_t> &elf_data) {
  std::vector<std::pair<std::string, uint64_t>> got_entries;

  auto plt_entries = ElfParser::get_plt_entries(elf_data);
  for (const auto &entry : plt_entries) {
    uint64_t got_addr = base + entry.got_offset;
    uint64_t got_value = 0;
    size_t ptr_size = (ProcessTracer::get_arch() == ArchMode::ARM64) ? 8 : 4;
    if (ProcessTracer::read_memory(pid, got_addr, &got_value, ptr_size)) {
      got_entries.push_back({entry.symbol_name, got_value});
    }
  }

  return got_entries;
}

SeccompInfo SeccompBypass::get_seccomp_status(int pid) {
  SeccompInfo info = {false, 0, 0, ""};

  std::ifstream status("/proc/" + std::to_string(pid) + "/status");
  std::string line;

  while (std::getline(status, line)) {
    if (line.find("Seccomp:") == 0) {
      info.seccomp_mode = atoi(line.substr(8).c_str());
      info.seccomp_enabled = (info.seccomp_mode > 0);
    }
    if (line.find("Seccomp_filters:") == 0) {
      info.filter_count = atol(line.substr(16).c_str());
    }
  }

  return info;
}

bool SeccompBypass::disable_seccomp(int pid) {

  if (!ProcessTracer::attach(pid))
    return false;

  uint64_t prctl_addr = MemoryInjector::find_libc_function(pid, "prctl");
  if (prctl_addr == 0) {
    ProcessTracer::detach(pid);
    return false;
  }

  std::vector<uint64_t> args = {22, 0, 0, 0, 0};

  auto result = MemoryInjector::call_remote(pid, prctl_addr, args);

  ProcessTracer::detach(pid);

  auto new_status = get_seccomp_status(pid);
  return !new_status.seccomp_enabled;
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
  for (const auto &r : lib_ranges) {
    if (base_addr >= r.start && base_addr < r.end) {
      ctx.self_library = r.name;
      break;
    }
  }

  auto calls = StaticRelinker::find_external_calls(elf_data, base_addr);

  const size_t max_size =
      config.max_total_size > 0 ? config.max_total_size : (64 * 1024 * 1024);

  size_t align = (ProcessTracer::get_arch() == ArchMode::ARM64) ? 16 : 4;
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

    auto sub_calls = InstructionDecoder::scan_calls(
        code.data(), code.size(), addr, ProcessTracer::get_arch());
    for (const auto &c : sub_calls) {
      if (c.target_address == 0 || c.target_address == addr)
        continue;
      uint64_t target = c.target_address;
      if (config.inline_plt_calls) {
        uint64_t resolved = InstructionDecoder::resolve_plt(
            pid, c.target_address, ProcessTracer::get_arch());
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
                            uint64_t target_local, ArchMode arch) {
  if (call_site + 4 > blob.size())
    return false;
  if (arch == ArchMode::ARM64) {
    int64_t rel = static_cast<int64_t>(target_local) -
                  static_cast<int64_t>(call_site);
    if ((rel & 0x3) != 0)
      return false;
    int64_t imm = rel / 4;
    if (imm < -0x2000000LL || imm >= 0x2000000LL)
      return false;
    uint32_t inst = 0x94000000 | (static_cast<uint32_t>(imm) & 0x03FFFFFF);
    memcpy(blob.data() + call_site, &inst, sizeof(inst));
    return true;
  }

  int64_t rel = static_cast<int64_t>(target_local) -
                static_cast<int64_t>(call_site + 8);
  uint32_t orig = 0;
  memcpy(&orig, blob.data() + call_site, sizeof(orig));

  // ARM32 BL (immediate): cond(31:28) 1011 imm24, target = pc+8 + imm24<<2
  if ((orig & 0x0F000000) == 0x0B000000) {
    if ((rel & 0x3) != 0)
      return false;
    int64_t imm = rel / 4;
    if (imm < -0x800000LL || imm >= 0x800000LL)
      return false;
    uint32_t inst =
        (orig & 0xFF000000) | (static_cast<uint32_t>(imm) & 0x00FFFFFF);
    memcpy(blob.data() + call_site, &inst, sizeof(inst));
    return true;
  }

  // ARM32 BLX (immediate): 1111 101H imm24, target = pc+8 + signext(imm24:H:0)
  if ((orig & 0xFE000000) == 0xFA000000) {
    if ((rel & 0x1) != 0)
      return false;
    int64_t imm25 = rel >> 1;
    int64_t imm24 = imm25 >> 1;
    if (imm24 < -0x800000LL || imm24 >= 0x800000LL)
      return false;
    uint32_t h = static_cast<uint32_t>(imm25 & 1);
    uint32_t inst =
        (orig & 0xFE000000) | (h << 24) |
        (static_cast<uint32_t>(imm24) & 0x00FFFFFF);
    memcpy(blob.data() + call_site, &inst, sizeof(inst));
    return true;
  }

  return false;
}

static void patch_embedded_calls(std::vector<uint8_t> &blob, int pid,
                                 const std::vector<EmbeddedFunctionInfo> &funcs,
                                 const std::map<uint64_t, uint64_t> &addr_map,
                                 ArchMode arch) {
  for (const auto &fn : funcs) {
    if (fn.local_offset + fn.size > blob.size())
      continue;
    const uint8_t *code = blob.data() + fn.local_offset;
    auto calls =
        InstructionDecoder::scan_calls(code, fn.size, fn.remote_addr, arch);
    for (const auto &call : calls) {
      if (call.call_site_offset + 4 > fn.size)
        continue;
      uint64_t target_addr = call.target_address;
      auto it = addr_map.find(target_addr);
      if (it == addr_map.end()) {
        uint64_t resolved = InstructionDecoder::resolve_plt(pid, target_addr, arch);
        if (resolved != 0 && resolved != target_addr)
          it = addr_map.find(resolved);
      }
      if (it == addr_map.end())
        continue;
      size_t call_site = static_cast<size_t>(fn.local_offset + call.call_site_offset);
      patch_call_site(blob, call_site, it->second, arch);
    }
  }
}

std::vector<uint8_t>
StaticRelinkerEx::extract_function_with_deps(int pid, uint64_t addr,
                                             int max_depth) {
  if (max_depth < 0)
    max_depth = 0;

  const ArchMode arch = ProcessTracer::get_arch();
  const size_t align = (arch == ArchMode::ARM64) ? 16 : 4;
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
                                                current_addr, arch);
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
        uint64_t plt_resolved = InstructionDecoder::resolve_plt(pid, target, arch);
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

  patch_embedded_calls(result, pid, embedded_funcs, embedded_by_remote, arch);
  return result;
}

template <typename Ehdr, typename Phdr>
static bool file_offset_to_vaddr_impl(const std::vector<uint8_t> &data,
                                      size_t file_off, uint64_t &vaddr_out) {
  if (data.size() < sizeof(Ehdr))
    return false;
  const Ehdr *ehdr = reinterpret_cast<const Ehdr *>(data.data());
  if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0 ||
      ehdr->e_phentsize != sizeof(Phdr))
    return false;
  size_t ph_end = static_cast<size_t>(ehdr->e_phoff) +
                  static_cast<size_t>(ehdr->e_phnum) * sizeof(Phdr);
  if (ph_end > data.size())
    return false;
  const Phdr *phdrs = reinterpret_cast<const Phdr *>(data.data() + ehdr->e_phoff);
  for (int i = 0; i < ehdr->e_phnum; i++) {
    const Phdr &ph = phdrs[i];
    if (ph.p_type != PT_LOAD || ph.p_filesz == 0)
      continue;
    uint64_t seg_off = ph.p_offset;
    uint64_t seg_end = ph.p_offset + ph.p_filesz;
    if (file_off < seg_off || file_off >= seg_end)
      continue;
    uint64_t delta = static_cast<uint64_t>(file_off) - seg_off;
    vaddr_out = ph.p_vaddr + delta;
    return true;
  }
  return false;
}

static bool file_offset_to_vaddr(const std::vector<uint8_t> &data, size_t file_off,
                                 uint64_t &vaddr_out) {
  if (data.size() < EI_NIDENT || data[0] != 0x7f || data[1] != 'E' ||
      data[2] != 'L' || data[3] != 'F')
    return false;
  if (data[EI_CLASS] == ELFCLASS32)
    return file_offset_to_vaddr_impl<Elf32_Ehdr, Elf32_Phdr>(data, file_off,
                                                              vaddr_out);
  if (data[EI_CLASS] == ELFCLASS64)
    return file_offset_to_vaddr_impl<Elf64_Ehdr, Elf64_Phdr>(data, file_off,
                                                              vaddr_out);
  return false;
}

bool StaticRelinkerEx::patch_relocations(
    std::vector<uint8_t> &data, const std::map<uint64_t, uint64_t> &addr_map,
    uint64_t base_addr) {
  ArchMode arch = ProcessTracer::get_arch();

  for (size_t i = 0; i + 4 <= data.size(); i += 4) {
    uint32_t inst = *(uint32_t *)(data.data() + i);
    uint64_t call_vaddr = 0;
    if (!file_offset_to_vaddr(data, i, call_vaddr))
      continue;

    if (arch == ArchMode::ARM64) {
      if ((inst & 0xFC000000) == 0x94000000) {
        int32_t offset = inst & 0x03FFFFFF;
        if (offset & 0x02000000)
          offset |= 0xFC000000;
        uint64_t target_remote =
            base_addr + call_vaddr + static_cast<int64_t>(offset) * 4;
        auto it = addr_map.find(target_remote);
        if (it != addr_map.end())
          patch_call_site(data, i, it->second, arch);
      }
    } else {
      if ((inst & 0x0F000000) == 0x0B000000) {
        int32_t imm24 = inst & 0x00FFFFFF;
        if (imm24 & 0x00800000)
          imm24 |= 0xFF000000;
        uint64_t target_remote =
            base_addr + call_vaddr + 8 + static_cast<int64_t>(imm24) * 4;
        auto it = addr_map.find(target_remote);
        if (it != addr_map.end())
          patch_call_site(data, i, it->second, arch);
      } else if ((inst & 0xFE000000) == 0xFA000000) {
        int32_t imm24 = inst & 0x00FFFFFF;
        if (imm24 & 0x00800000)
          imm24 |= 0xFF000000;
        uint32_t h = (inst >> 24) & 1;
        int64_t rel = static_cast<int64_t>(imm24) * 4 + (h << 1);
        uint64_t target_remote = base_addr + call_vaddr + 8 + rel;
        auto it = addr_map.find(target_remote);
        if (it != addr_map.end())
          patch_call_site(data, i, it->second, arch);
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
    info.key_addr = base_addr + k.offset;
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
    info.capture_time = time(nullptr);
    keys.push_back(info);
  }

  return keys;
}

static std::map<uint64_t, std::vector<uint8_t>> g_crypto_original_patches;
static std::map<uint64_t, std::pair<uint64_t, size_t>>
    g_crypto_hook_allocations;


static bool hook_aes_function(int pid, uint64_t *original,
                              const char *primary_sym, const char *nohw_sym,
                              const char *openssl_sym) {
  uint64_t func_addr =
      FunctionHooker::find_remote_symbol(pid, "libcrypto.so", primary_sym);
  if (func_addr == 0)
    func_addr =
        FunctionHooker::find_remote_symbol(pid, "libcrypto.so", nohw_sym);
  if (func_addr == 0)
    func_addr =
        FunctionHooker::find_remote_symbol(pid, "libcrypto.so", openssl_sym);

  if (func_addr == 0)
    return false;

  if (original)
    *original = func_addr;
  if (g_crypto_hook_allocations.count(func_addr))
    return true;

  size_t patch_size = (ProcessTracer::get_arch() == ArchMode::ARM64) ? 16 : 8;
  if (!g_crypto_original_patches.count(func_addr)) {
    std::vector<uint8_t> saved(patch_size);
    if (!ProcessTracer::read_memory(pid, func_addr, saved.data(), patch_size))
      return false;
    g_crypto_original_patches[func_addr] = saved;
  }

  if (ProcessTracer::get_arch() == ArchMode::ARM64) {
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

    uint32_t ldr_x10 = 0x58000050;
    uint32_t br_x10 = 0xD61F0140;
    hook_code.insert(hook_code.end(), (uint8_t *)&ldr_x10,
                     (uint8_t *)&ldr_x10 + 4);
    hook_code.insert(hook_code.end(), (uint8_t *)&br_x10,
                     (uint8_t *)&br_x10 + 4);
    hook_code.insert(hook_code.end(), (uint8_t *)&func_addr,
                     (uint8_t *)&func_addr + 8);

    uint64_t hook_addr =
        FunctionHooker::allocate_remote(pid, hook_code.size() + 64);
    if (hook_addr == 0)
      return false;

    ProcessTracer::write_memory(pid, hook_addr, hook_code.data(),
                                hook_code.size());

    HookInfo info;
    if (!MemoryInjector::install_inline_hook(pid, func_addr, hook_addr,
                                             &info)) {
      FunctionHooker::free_remote(pid, hook_addr, hook_code.size() + 64);
      return false;
    }

    if (!ProcessTracer::write_memory(pid, hook_addr + hook_code.size() - 8,
                                     &info.trampoline_addr, 8)) {
      MemoryInjector::remove_inline_hook(pid, info);
      FunctionHooker::free_remote(pid, hook_addr, hook_code.size() + 64);
      return false;
    }
    g_crypto_hook_allocations[func_addr] = {hook_addr, hook_code.size() + 64};
  } else {
    std::vector<uint8_t> hook_code;

    // Minimal ARM32 pass-through hook body: preserve a small register set and
    // branch to trampoline literal (patched after inline hook install).
    uint32_t push = 0xE92D40F0; // push {r4-r7, lr}
    uint32_t pop = 0xE8BD40F0;  // pop {r4-r7, lr}
    uint32_t ldr_pc = 0xE51FF004;
    uint32_t target_placeholder = 0;
    hook_code.insert(hook_code.end(), (uint8_t *)&push, (uint8_t *)&push + 4);
    hook_code.insert(hook_code.end(), (uint8_t *)&pop, (uint8_t *)&pop + 4);
    hook_code.insert(hook_code.end(), (uint8_t *)&ldr_pc,
                     (uint8_t *)&ldr_pc + 4);
    hook_code.insert(hook_code.end(), (uint8_t *)&target_placeholder,
                     (uint8_t *)&target_placeholder + 4);

    uint64_t hook_addr =
        FunctionHooker::allocate_remote(pid, hook_code.size() + 32);
    if (hook_addr == 0)
      return false;

    ProcessTracer::write_memory(pid, hook_addr, hook_code.data(),
                                hook_code.size());

    HookInfo info;
    if (!MemoryInjector::install_inline_hook(pid, func_addr, hook_addr,
                                             &info)) {
      FunctionHooker::free_remote(pid, hook_addr, hook_code.size() + 32);
      return false;
    }

    uint32_t tramp = static_cast<uint32_t>(info.trampoline_addr);
    if (!ProcessTracer::write_memory(pid, hook_addr + hook_code.size() - 4,
                                     &tramp, sizeof(tramp))) {
      MemoryInjector::remove_inline_hook(pid, info);
      FunctionHooker::free_remote(pid, hook_addr, hook_code.size() + 32);
      return false;
    }
    g_crypto_hook_allocations[func_addr] = {hook_addr, hook_code.size() + 32};
  }

  return true;
}

bool CryptoAnalyzer::hook_aes_encrypt(int pid, uint64_t *original) {
  return hook_aes_function(pid, original, "AES_encrypt", "aes_nohw_encrypt",
                           "OPENSSL_AES_encrypt");
}

bool CryptoAnalyzer::hook_aes_decrypt(int pid, uint64_t *original) {
  return hook_aes_function(pid, original, "AES_decrypt", "aes_nohw_decrypt",
                           "OPENSSL_AES_decrypt");
}

size_t CryptoAnalyzer::restore_aes_hooks(int pid) {
  size_t restored = 0;
  for (const auto &kv : g_crypto_original_patches) {
    if (kv.second.empty())
      continue;
    if (ProcessTracer::write_memory(pid, kv.first, kv.second.data(),
                                    kv.second.size())) {
      restored++;
    }
  }
  for (const auto &kv : g_crypto_hook_allocations) {
    uint64_t hook_addr = kv.second.first;
    size_t hook_size = kv.second.second;
    if (hook_addr != 0 && hook_size != 0)
      FunctionHooker::free_remote(pid, hook_addr, hook_size);
  }
  g_crypto_original_patches.clear();
  g_crypto_hook_allocations.clear();
  return restored;
}

std::vector<uint8_t>
MemoryInjector::generate_dlopen_shellcode_arm64(const std::string &lib_path) {
  std::vector<uint8_t> code;

  uint32_t save_regs[] = {
      0xA9BF7BFD,
      0x910003FD,
  };
  for (auto inst : save_regs)
    code.insert(code.end(), (uint8_t *)&inst, (uint8_t *)&inst + 4);

  uint32_t ldr_dlopen = 0x58000049;
  code.insert(code.end(), (uint8_t *)&ldr_dlopen, (uint8_t *)&ldr_dlopen + 4);

  uint32_t b_skip = 0x14000004;
  code.insert(code.end(), (uint8_t *)&b_skip, (uint8_t *)&b_skip + 4);

  uint64_t dlopen_placeholder = 0;
  code.insert(code.end(), (uint8_t *)&dlopen_placeholder,
              (uint8_t *)&dlopen_placeholder + 8);

  size_t string_offset = code.size() + 32;
  uint32_t adr_x0 = 0x10000000 | ((string_offset / 4) << 5);
  code.insert(code.end(), (uint8_t *)&adr_x0, (uint8_t *)&adr_x0 + 4);

  uint32_t mov_x1 = 0xD2800041;
  code.insert(code.end(), (uint8_t *)&mov_x1, (uint8_t *)&mov_x1 + 4);

  uint32_t blr_x9 = 0xD63F0120;
  code.insert(code.end(), (uint8_t *)&blr_x9, (uint8_t *)&blr_x9 + 4);

  uint32_t restore_regs[] = {
      0xA8C17BFD,
      0xD65F03C0,
  };
  for (auto inst : restore_regs)
    code.insert(code.end(), (uint8_t *)&inst, (uint8_t *)&inst + 4);

  while (code.size() % 8)
    code.push_back(0);
  code.insert(code.end(), lib_path.begin(), lib_path.end());
  code.push_back(0);

  return code;
}

std::vector<uint8_t>
MemoryInjector::generate_dlopen_shellcode_arm32(const std::string &lib_path) {
  std::vector<uint8_t> code;

  uint32_t push = 0xE92D40F0;
  code.insert(code.end(), (uint8_t *)&push, (uint8_t *)&push + 4);

  uint32_t ldr_r4 = 0xE59F4008;
  code.insert(code.end(), (uint8_t *)&ldr_r4, (uint8_t *)&ldr_r4 + 4);

  uint32_t ldr_r0 = 0xE59F0008;
  code.insert(code.end(), (uint8_t *)&ldr_r0, (uint8_t *)&ldr_r0 + 4);

  uint32_t mov_r1 = 0xE3A01002;
  code.insert(code.end(), (uint8_t *)&mov_r1, (uint8_t *)&mov_r1 + 4);

  uint32_t blx_r4 = 0xE12FFF34;
  code.insert(code.end(), (uint8_t *)&blx_r4, (uint8_t *)&blx_r4 + 4);

  uint32_t pop = 0xE8BD80F0;
  code.insert(code.end(), (uint8_t *)&pop, (uint8_t *)&pop + 4);

  uint32_t dlopen_placeholder = 0;
  code.insert(code.end(), (uint8_t *)&dlopen_placeholder,
              (uint8_t *)&dlopen_placeholder + 4);

  uint32_t path_placeholder = 0;
  code.insert(code.end(), (uint8_t *)&path_placeholder,
              (uint8_t *)&path_placeholder + 4);

  code.insert(code.end(), lib_path.begin(), lib_path.end());
  code.push_back(0);

  return code;
}
