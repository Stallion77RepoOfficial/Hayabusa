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

} 

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

bool ZygoteTracer::attach_zygote(int zygote_pid) {
  if (ptrace(PTRACE_ATTACH, zygote_pid, nullptr, nullptr) < 0) {
    int err = errno;
    if (err == EPERM) {
      std::ifstream f("/proc/" + std::to_string(zygote_pid) + "/status");
      std::string line;
      while (std::getline(f, line)) {
        if (line.find("TracerPid:") == 0) {
          int tpid = atoi(line.substr(10).c_str());
          if (tpid > 0) {
            std::ifstream tf("/proc/" + std::to_string(tpid) + "/cmdline");
            std::string tcmd;
            std::getline(tf, tcmd);
            if (tcmd.find("hayabusa") != std::string::npos) {
              std::cout << "    [!] Found zombie Hayabusa instance (PID: "
                        << tpid << "), killing it...\n";
              kill(tpid, SIGKILL);
              sleep(1); 
              
              if (ptrace(PTRACE_ATTACH, zygote_pid, nullptr, nullptr) == 0) {
                std::cout << "    [+] Successfully recovered and attached to "
                             "Zygote.\n";
                
                register_attached_pid(zygote_pid);
                int status;
                waitpid(zygote_pid, &status, 0);
                if (!WIFSTOPPED(status)) {
                  unregister_attached_pid(zygote_pid);
                  return false;
                }
                unsigned long opts = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                                     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
                ptrace(PTRACE_SETOPTIONS, zygote_pid, nullptr, opts);
                return true;
              }
            } else {
              std::cerr << "    [!] Zygote is ALREADY traced by PID " << tpid
                        << " (" << tcmd << ")\n";
              std::cerr << "    [!] Try: adb shell su -c \"kill -9 " << tpid
                        << "\"\n";
            }
          }
          break;
        }
      }
    }
    std::cerr << "    [!] ptrace attach failed: " << strerror(err) << "\n";
    return false;
  }

  
  register_attached_pid(zygote_pid);

  int status;
  waitpid(zygote_pid, &status, 0);
  if (!WIFSTOPPED(status)) {
    std::cerr << "    [!] Waitpid failed or process not stopped. Status: "
              << status << "\n";
    unregister_attached_pid(zygote_pid);
    return false;
  }

  unsigned long opts = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                       PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
  if (ptrace(PTRACE_SETOPTIONS, zygote_pid, nullptr, opts) < 0) {
    ptrace(PTRACE_DETACH, zygote_pid, nullptr, nullptr);
    unregister_attached_pid(zygote_pid);
    return false;
  }
  return true;
}

int ZygoteTracer::wait_for_fork(int zygote_pid, const std::string &target_pkg) {
  
  ptrace(PTRACE_CONT, zygote_pid, nullptr, nullptr);

  
  std::set<int> zygote_pids;
  zygote_pids.insert(zygote_pid);

  
  DIR *proc_dir = opendir("/proc");
  if (proc_dir) {
    struct dirent *ent;
    while ((ent = readdir(proc_dir))) {
      int pid = atoi(ent->d_name);
      if (pid <= 0 || pid == zygote_pid)
        continue;
      std::ifstream cmdfile("/proc/" + std::string(ent->d_name) + "/cmdline");
      std::string cmdline;
      std::getline(cmdfile, cmdline);
      if (cmdline.find("zygote") != std::string::npos) {
        
        if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == 0) {
          int status;
          waitpid(pid, &status, 0);
          unsigned long opts = PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                               PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
          ptrace(PTRACE_SETOPTIONS, pid, nullptr, opts);
          ptrace(PTRACE_CONT, pid, nullptr, nullptr);
          zygote_pids.insert(pid);
          register_attached_pid(pid); 
          std::cout << "    [DEBUG] Attached to secondary Zygote: " << pid
                    << "\n";
        } else {
          std::cerr << "    [DEBUG] Failed to attach to secondary Zygote: "
                    << pid << " (" << strerror(errno) << ")\n";
        }
      }
    }
    closedir(proc_dir);
  }

  time_t start_time = time(nullptr);
  const int TIMEOUT_SECONDS = 60;
  std::set<int> checked_children;
  std::set<int> pending_children;
  time_t last_check = 0;
  time_t last_poll = 0;

  while (time(nullptr) - start_time < TIMEOUT_SECONDS) {
    int status;
    int pid = waitpid(-1, &status, __WALL | WNOHANG);

    if (pid > 0) {
      
      if (WIFSTOPPED(status)) {
        std::cout << "    [TRACE] PID: " << pid
                  << " Stopped. Signal: " << WSTOPSIG(status);
        if (WSTOPSIG(status) == SIGTRAP)
          std::cout << " (SIGTRAP/EVENT)";
        std::cout << "\n";
      } else if (WIFEXITED(status)) {
        std::cout << "    [TRACE] PID: " << pid
                  << " Exited: " << WEXITSTATUS(status) << "\n";
      } else if (WIFSIGNALED(status)) {
        std::cout << "    [TRACE] PID: " << pid
                  << " Signaled: " << WTERMSIG(status) << "\n";
      }

      if (zygote_pids.count(pid)) {
        
        if (WIFSTOPPED(status)) {
          int sig = WSTOPSIG(status);
          int injection_sig = 0;

          if (sig == SIGTRAP) {
            int event = (status >> 16) & 0xFF;
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
              unsigned long child_pid_ul;
              ptrace(PTRACE_GETEVENTMSG, pid, nullptr, &child_pid_ul);
              int child_pid = (int)child_pid_ul;

              if (child_pid > 0 &&
                  checked_children.find(child_pid) == checked_children.end()) {
                checked_children.insert(child_pid);

                std::cout << "    [DEBUG] Fork detected! Parent: " << pid
                          << " -> New Child: " << child_pid << "\n";

                
                int child_status;
                waitpid(child_pid, &child_status, __WALL);
                ptrace(PTRACE_CONT, child_pid, nullptr, nullptr);
                pending_children.insert(child_pid);
              }
            }
          } else if (sig != SIGSTOP) {
            
            injection_sig = sig;
          }
          
          ptrace(PTRACE_CONT, pid, nullptr, (void *)(long)injection_sig);
        } else {
          if (WIFEXITED(status) || WIFSIGNALED(status)) {
            zygote_pids.erase(pid);
          }
        }
      } else if (pending_children.count(pid)) {
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
          pending_children.erase(pid);
        } else if (WIFSTOPPED(status)) {
          
          ptrace(PTRACE_CONT, pid, nullptr,
                 (void *)(long)(WSTOPSIG(status) == SIGTRAP
                                    ? 0
                                    : WSTOPSIG(status)));
        }
      } else {
        
        if (WIFSTOPPED(status))
          ptrace(PTRACE_CONT, pid, nullptr, 0);
      }
    } else {
      usleep(10000); 
    }

    
    time_t now = time(nullptr);
    if (now != last_poll) {
      last_poll = now;

      
      DIR *proc_dir = opendir("/proc");
      if (proc_dir) {
        struct dirent *ent;
        while ((ent = readdir(proc_dir))) {
          int p = atoi(ent->d_name);
          if (p <= 0)
            continue;
          
          if (zygote_pids.count(p) || pending_children.count(p))
            continue;

          std::ifstream f("/proc/" + std::to_string(p) + "/cmdline");
          std::string cmd;
          if (f.is_open())
            std::getline(f, cmd);

          if (!cmd.empty() && cmd.find(target_pkg) != std::string::npos &&
              cmd.find("hayabusa") == std::string::npos &&
              cmd.find("logcat") == std::string::npos) {
            std::cout << "    [+] Target found via polling: " << cmd
                      << " (PID: " << p << ")\n";

            
            for (int zpid : zygote_pids) {
              ptrace(PTRACE_DETACH, zpid, nullptr, nullptr);
              unregister_attached_pid(zpid);
            }
            
            for (int other : pending_children)
              ptrace(PTRACE_DETACH, other, nullptr, nullptr);

            
            
            
            
            
            
            
            
            
            return p;
          }
        }
        closedir(proc_dir);
      }
    }

    
    if (now != last_check) {
      last_check = now;
      for (auto it = pending_children.begin(); it != pending_children.end();) {
        int child_pid = *it;
        std::ifstream f("/proc/" + std::to_string(child_pid) + "/cmdline");
        std::string cmd;
        if (f.is_open()) {
          std::getline(f, cmd);
          f.close();
        }
        if (cmd.empty()) {
          
          std::ifstream fc("/proc/" + std::to_string(child_pid) + "/comm");
          if (fc.is_open()) {
            std::getline(fc, cmd);
            fc.close();
          }
        }

        if (!cmd.empty()) {
          
          if (cmd.find(target_pkg) != std::string::npos) {
            std::cout << "    [+] Target found: " << cmd
                      << " (PID: " << child_pid << ")\n";

            
            for (int zpid : zygote_pids) {
              ptrace(PTRACE_DETACH, zpid, nullptr, nullptr);
              unregister_attached_pid(zpid);
            }
            
            for (int other : pending_children) {
              if (other != child_pid)
                ptrace(PTRACE_DETACH, other, nullptr, nullptr);
            }

            
            
            
            
            
            
            

            
            
            
            
            
            
            
            

            
            
            ptrace(PTRACE_DETACH, child_pid, nullptr, nullptr);
            return child_pid;
          }
        }

        
        
        ++it;
      }
    }
  }

  
  for (int zpid : zygote_pids) {
    ptrace(PTRACE_DETACH, zpid, nullptr, nullptr);
    unregister_attached_pid(zpid);
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
  size_t page_count = (size + 4095) / 4096;
  std::vector<bool> captured(page_count, false);
  if (!attach(pid))
    return result;
  read_memory(pid, base, result.data(), size);
  for (size_t i = 0; i < page_count; i++) {
    bool has_data = false;
    size_t page_size = std::min<size_t>(4096, size - i * 4096);
    for (size_t j = 0; j < page_size && !has_data; j++) {
      if (result[i * 4096 + j] != 0)
        has_data = true;
    }
    if (!has_data) {
      set_protection(pid, base + i * 4096, page_size, PROT_NONE);
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
          size_t page_size =
              std::min<size_t>(4096, size - page_idx * 4096);
          set_protection(pid, base + page_idx * 4096, page_size,
                         PROT_READ | PROT_EXEC);
          std::vector<uint8_t> page_data(page_size);
          read_memory(pid, base + page_idx * 4096, page_data.data(),
                      page_size);
          memcpy(result.data() + page_idx * 4096, page_data.data(), page_size);
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
      set_protection(pid, base + i * 4096,
                     std::min<size_t>(4096, size - i * 4096),
                     PROT_READ | PROT_EXEC);
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





uint64_t MemoryInjector::remote_mmap(int pid, uint64_t addr, size_t size,
                                     int prot, int flags) {
  if (!ProcessTracer::attach(pid))
    return 0;

  RemoteCallResult result;
  if (ProcessTracer::get_arch() == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;

    
    regs.regs[0] = addr;
    regs.regs[1] = size;
    regs.regs[2] = prot;
    regs.regs[3] = flags;
    regs.regs[4] = (uint64_t)-1; 
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
    uint64_t ret = regs.regs[0];

    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ProcessTracer::detach(pid);

    return (ret == (uint64_t)-1) ? 0 : ret;
  } else {
    user_regs_struct_32 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;

    
    regs.regs[0] = (uint32_t)addr;
    regs.regs[1] = (uint32_t)size;
    regs.regs[2] = (uint32_t)prot;
    regs.regs[3] = (uint32_t)flags;
    regs.regs[4] = (uint32_t)-1;
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
    uint32_t ret = regs.regs[0];

    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ProcessTracer::detach(pid);

    return (ret == (uint32_t)-1) ? 0 : ret;
  }
}

bool MemoryInjector::remote_munmap(int pid, uint64_t addr, size_t size) {
  if (!ProcessTracer::attach(pid))
    return false;

  bool success = false;
  if (ProcessTracer::get_arch() == ArchMode::ARM64) {
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

    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    success = (regs.regs[0] == 0);

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

    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    success = (regs.regs[0] == 0);

    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
  }

  ProcessTracer::detach(pid);
  return success;
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
    user_regs_struct_64 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
      result.error_message = "Failed to get registers";
      ProcessTracer::detach(pid);
      return result;
    }
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
        ProcessTracer::write_memory(pid, regs.sp + (i - 8) * 8, &val, 8);
      }
    }

    
    uint64_t pc = regs.pc;
    uint32_t orig_inst;
    ProcessTracer::read_memory(pid, pc, &orig_inst, 4);

    
    uint64_t stub_addr = FunctionHooker::allocate_remote(pid, 32);
    if (stub_addr == 0) {
      result.error_message = "Failed to allocate stub";
      ProcessTracer::detach(pid);
      return result;
    }

    
    
    
    
    
    uint32_t stub_code[] = {
        0x58000049, 
        0xD63F0120, 
        0xD4200000, 
        0x00000000, 
    };
    ProcessTracer::write_memory(pid, stub_addr, stub_code, 16);
    ProcessTracer::write_memory(pid, stub_addr + 16, &func_addr, 8);

    
    regs.regs[30] = stub_addr + 8; 
    regs.pc = stub_addr;

    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    int status;
    waitpid(pid, &status, 0);

    
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    result.return_value = regs.regs[0];
    result.success = true;

    
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    FunctionHooker::free_remote(pid, stub_addr, 32);
  } else {
    user_regs_struct_32 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) < 0) {
      result.error_message = "Failed to get registers";
      ProcessTracer::detach(pid);
      return result;
    }
    regs = orig_regs;

    
    for (size_t i = 0; i < args.size() && i < 4; i++) {
      regs.regs[i] = (uint32_t)args[i];
    }

    if (args.size() > 4) {
      size_t stack_args = args.size() - 4;
      regs.regs[13] -= stack_args * 4;
      regs.regs[13] &= ~0x7; 
      for (size_t i = 4; i < args.size(); i++) {
        uint32_t val = (uint32_t)args[i];
        ProcessTracer::write_memory(pid, regs.regs[13] + (i - 4) * 4, &val, 4);
      }
    }

    uint64_t stub_addr = FunctionHooker::allocate_remote(pid, 16);
    if (stub_addr == 0) {
      result.error_message = "Failed to allocate stub";
      ProcessTracer::detach(pid);
      return result;
    }

    
    
    
    
    
    uint32_t stub_code[] = {
        0xE59FC004, 
        0xE12FFF3C, 
        0xE1200070, 
        (uint32_t)func_addr,
    };
    ProcessTracer::write_memory(pid, stub_addr, stub_code, 16);

    regs.regs[14] = (uint32_t)(stub_addr + 8); 
    regs.regs[15] = (uint32_t)stub_addr;       

    iov.iov_base = &regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);

    int status;
    waitpid(pid, &status, 0);

    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    result.return_value = regs.regs[0];
    result.success = true;

    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
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

  
  size_t path_len = path.size() + 1;
  uint64_t path_addr = FunctionHooker::allocate_remote(pid, path_len);
  if (path_addr == 0)
    return 0;

  ProcessTracer::write_memory(pid, path_addr, path.c_str(), path_len);

  
  std::vector<uint64_t> args = {path_addr, (uint64_t)flags};
  auto result = call_remote(pid, dlopen_addr, args);

  FunctionHooker::free_remote(pid, path_addr, path_len);

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

  size_t sym_len = symbol.size() + 1;
  uint64_t sym_addr = FunctionHooker::allocate_remote(pid, sym_len);
  if (sym_addr == 0)
    return 0;

  ProcessTracer::write_memory(pid, sym_addr, symbol.c_str(), sym_len);

  std::vector<uint64_t> args = {handle, sym_addr};
  auto result = call_remote(pid, dlsym_addr, args);

  FunctionHooker::free_remote(pid, sym_addr, sym_len);

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

uint64_t MemoryInjector::find_libart_base(int pid) {
  auto ranges = ProcessTracer::get_library_ranges(pid);
  for (const auto &r : ranges) {
    if (r.name.find("libart.so") != std::string::npos)
      return r.start;
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

uint64_t MemoryInjector::find_art_method(int pid, const std::string &class_name,
                                         const std::string &method_name,
                                         const std::string &signature) {
  
  
  uint64_t libart = find_libart_base(pid);
  if (libart == 0)
    return 0;

  
  return 0;
}

bool MemoryInjector::hook_art_method(int pid, uint64_t art_method,
                                     uint64_t hook, uint64_t *original_entry) {
  if (art_method == 0)
    return false;

  
  
  size_t entry_offset =
      (ProcessTracer::get_arch() == ArchMode::ARM64) ? 0x20 : 0x14;
  size_t ptr_size = (ProcessTracer::get_arch() == ArchMode::ARM64) ? 8 : 4;

  uint64_t entry_addr = art_method + entry_offset;

  if (original_entry) {
    if (!ProcessTracer::read_memory(pid, entry_addr, original_entry, ptr_size))
      return false;
  }

  return ProcessTracer::write_memory(pid, entry_addr, &hook, ptr_size);
}

std::vector<ARTMethodInfo>
MemoryInjector::enum_art_methods(int pid, const std::string &class_name) {
  std::vector<ARTMethodInfo> methods;

  
  std::string descriptor = "L" + class_name + ";";
  std::replace(descriptor.begin(), descriptor.end(), '.', '/');

  
  uint64_t art_class = ARTHooker::find_class_by_descriptor(pid, descriptor);
  if (art_class == 0) {
    
    auto all_classes = ARTHooker::enumerate_loaded_classes(pid);
    for (const auto &cls : all_classes) {
      if (cls.descriptor.find(class_name) != std::string::npos ||
          cls.descriptor == descriptor) {
        art_class = cls.class_addr;
        break;
      }
    }
  }

  if (art_class == 0)
    return methods;

  
  return ARTHooker::get_class_methods(pid, art_class);
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

bool SeccompBypass::patch_seccomp_filter(int pid) {
  
  

  auto status = get_seccomp_status(pid);
  if (!status.seccomp_enabled || status.filter_count == 0)
    return true; 

  
  

  return false; 
}

bool SeccompBypass::use_memfd_workaround(int pid) {
  
  

  if (!ProcessTracer::attach(pid))
    return false;

  
  

  ArchMode arch = ProcessTracer::get_arch();

  if (arch == ArchMode::ARM64) {
    user_regs_struct_64 orig_regs, regs;
    struct iovec iov = {&orig_regs, sizeof(orig_regs)};
    ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
    regs = orig_regs;

    
    uint64_t name_addr = FunctionHooker::allocate_remote(pid, 32);
    const char *name = "hayabusa";
    ProcessTracer::write_memory(pid, name_addr, name, strlen(name) + 1);

    regs.regs[0] = name_addr;
    regs.regs[1] = 1;   
    regs.regs[8] = 279; 

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
    int memfd = (int)regs.regs[0];

    ProcessTracer::write_memory(pid, pc, &orig_inst, 4);
    iov.iov_base = &orig_regs;
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

    FunctionHooker::free_remote(pid, name_addr, 32);
    ProcessTracer::detach(pid);

    return memfd >= 0;
  }

  ProcessTracer::detach(pid);
  return false;
}

int SeccompBypass::spawn_without_seccomp(const std::string &cmd) {
  
  pid_t pid = fork();
  if (pid == 0) {
    
    
    execl("/system/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
    _exit(1);
  }
  return pid;
}

bool SeccompBypass::inject_seccomp_disabler(int pid) {
  
  

  
  

  return false; 
}





namespace ARTOffsetFinder {

ARTOffsets get_config_offsets(int sdk_version, bool is64bit) {
  ARTOffsetConfig cfg =
      ConfigLoader::instance().get_offsets(sdk_version, is64bit);
  if (cfg.valid) {
    ARTOffsets offsets;
    offsets.runtime_class_linker = cfg.class_linker_offset;
    offsets.runtime_heap = cfg.heap_offset;
    offsets.runtime_jit = 0; 
    offsets.classlinker_dex_caches = cfg.dex_caches_offset;
    offsets.classlinker_boot_class_path = 0;
    offsets.dexcache_dex_file = cfg.dex_file_offset;
    offsets.jit_code_cache = 0;
    offsets.valid = true;
    offsets.discovered_sdk = sdk_version;
    return offsets;
  }
  return {0, 0, 0, 0, 0, 0, 0, false, sdk_version};
}

ARTOffsets get_fallback_offsets(int sdk_version, bool is64bit) {
  
  ARTOffsets config_offsets = get_config_offsets(sdk_version, is64bit);
  if (config_offsets.valid)
    return config_offsets;

  ARTOffsets offsets = {0, 0, 0, 0, 0, 0, 0, false, sdk_version};

  
  
  if (is64bit) {
    if (sdk_version >= 35) { 
      offsets.runtime_class_linker = 0x350;
      offsets.runtime_heap = 0x200;
      offsets.runtime_jit = 0x400;
      offsets.classlinker_dex_caches = 0x50;
      offsets.classlinker_boot_class_path = 0x70;
      offsets.dexcache_dex_file = 0x20;
      offsets.jit_code_cache = 0x8;
    } else if (sdk_version >= 34) { 
      offsets.runtime_class_linker = 0x348;
      offsets.runtime_heap = 0x1F8;
      offsets.runtime_jit = 0x3F0;
      offsets.classlinker_dex_caches = 0x48;
      offsets.classlinker_boot_class_path = 0x68;
      offsets.dexcache_dex_file = 0x20;
      offsets.jit_code_cache = 0x8;
    } else if (sdk_version >= 33) { 
      offsets.runtime_class_linker = 0x340;
      offsets.runtime_heap = 0x1F8;
      offsets.runtime_jit = 0x3E0;
      offsets.classlinker_dex_caches = 0x48;
      offsets.classlinker_boot_class_path = 0x68;
      offsets.dexcache_dex_file = 0x20;
      offsets.jit_code_cache = 0x8;
    } else if (sdk_version >= 31) { 
      offsets.runtime_class_linker = 0x330;
      offsets.runtime_heap = 0x1F8;
      offsets.runtime_jit = 0x3C0;
      offsets.classlinker_dex_caches = 0x40;
      offsets.classlinker_boot_class_path = 0x68;
      offsets.dexcache_dex_file = 0x20;
      offsets.jit_code_cache = 0x8;
    } else if (sdk_version >= 30) { 
      offsets.runtime_class_linker = 0x320;
      offsets.runtime_heap = 0x1F8;
      offsets.runtime_jit = 0x3A0;
      offsets.classlinker_dex_caches = 0x38;
      offsets.classlinker_boot_class_path = 0x60;
      offsets.dexcache_dex_file = 0x18;
      offsets.jit_code_cache = 0x8;
    } else { 
      offsets.runtime_class_linker = 0x310;
      offsets.runtime_heap = 0x1F8;
      offsets.runtime_jit = 0x3A0;
      offsets.classlinker_dex_caches = 0x38;
      offsets.classlinker_boot_class_path = 0x60;
      offsets.dexcache_dex_file = 0x18;
      offsets.jit_code_cache = 0x8;
    }
  } else {
    
    if (sdk_version >= 33) {
      offsets.runtime_class_linker = 0x1A0;
      offsets.runtime_heap = 0xFC;
      offsets.runtime_jit = 0x1F0;
    } else if (sdk_version >= 31) {
      offsets.runtime_class_linker = 0x198;
      offsets.runtime_heap = 0xFC;
      offsets.runtime_jit = 0x1E0;
    } else {
      offsets.runtime_class_linker = 0x188;
      offsets.runtime_heap = 0xFC;
      offsets.runtime_jit = 0x1D0;
    }
    offsets.classlinker_dex_caches = 0x20;
    offsets.classlinker_boot_class_path = 0x30;
    offsets.dexcache_dex_file = 0x10;
    offsets.jit_code_cache = 0x4;
  }

  offsets.valid = true;
  return offsets;
}

bool validate_offsets(int pid, uint64_t runtime_addr,
                      const ARTOffsets &offsets) {
  if (runtime_addr == 0 || !offsets.valid)
    return false;

  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;

  
  uint64_t class_linker = 0;
  if (!ProcessTracer::read_memory(pid,
                                  runtime_addr + offsets.runtime_class_linker,
                                  &class_linker, ptr_size)) {
    return false;
  }

  
  if (class_linker < 0x10000 || class_linker > 0x0000FFFFFFFFFFFF) {
    return false;
  }

  
  uint64_t test_val = 0;
  if (!ProcessTracer::read_memory(pid, class_linker, &test_val, ptr_size)) {
    return false;
  }

  return true;
}

ARTOffsets discover_offsets(int pid, uint64_t runtime_addr,
                            uint64_t libart_base, int sdk_version) {
  ARTOffsets offsets = get_fallback_offsets(
      sdk_version, ProcessTracer::get_arch() == ArchMode::ARM64);

  if (runtime_addr == 0 || libart_base == 0) {
    return offsets;
  }

  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;

  
  

  
  const size_t scan_size = 2048;
  std::vector<uint8_t> runtime_data(scan_size);
  if (!ProcessTracer::read_memory(pid, runtime_addr, runtime_data.data(),
                                  scan_size)) {
    return offsets; 
  }

  
  auto ranges = ProcessTracer::get_library_ranges(pid);
  uint64_t libart_end = libart_base;
  for (const auto &r : ranges) {
    if (r.name.find("libart.so") != std::string::npos) {
      if (r.end > libart_end)
        libart_end = r.end;
    }
  }

  
  
  std::vector<size_t> candidates;

  for (size_t off = 0x100; off < scan_size - ptr_size; off += ptr_size) {
    uint64_t ptr = is64 ? *(uint64_t *)(runtime_data.data() + off)
                        : *(uint32_t *)(runtime_data.data() + off);

    if (ptr < 0x10000 || ptr > 0x0000FFFFFFFFFFFF)
      continue;

    
    uint64_t vtable = 0;
    if (!ProcessTracer::read_memory(pid, ptr, &vtable, ptr_size))
      continue;

    
    if (vtable >= libart_base && vtable < libart_end) {
      candidates.push_back(off);
    }
  }

  
  
  size_t fallback_cl = offsets.runtime_class_linker;
  size_t best_offset = fallback_cl;
  size_t best_distance = 0x100;

  for (size_t off : candidates) {
    size_t distance =
        (off > fallback_cl) ? (off - fallback_cl) : (fallback_cl - off);
    if (distance < best_distance) {
      best_distance = distance;
      best_offset = off;
    }
  }

  if (best_distance < 0x30) {
    offsets.runtime_class_linker = best_offset;
  }

  
  if (validate_offsets(pid, runtime_addr, offsets)) {
    offsets.valid = true;
  }

  return offsets;
}

} 





ARTRuntimeInfo ARTHooker::find_art_runtime(int pid) {
  ARTRuntimeInfo info = {0, 0, 0, 0, 0, false, ""};

  uint64_t libart = MemoryInjector::find_libart_base(pid);
  if (libart == 0)
    return info;

  
  uint64_t instance_sym = FunctionHooker::find_remote_symbol(
      pid, "libart.so", "_ZN3art7Runtime9instance_E");

  if (instance_sym != 0) {
    ProcessTracer::read_memory(pid, instance_sym, &info.runtime_addr, 8);
  }

  
  info.sdk_version = get_sdk_version(pid);

  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;

  
  if (info.runtime_addr != 0) {
    
    ARTOffsets offsets = ARTOffsetFinder::discover_offsets(
        pid, info.runtime_addr, libart, info.sdk_version);

    if (offsets.valid) {
      
      ProcessTracer::read_memory(
          pid, info.runtime_addr + offsets.runtime_class_linker,
          &info.class_linker_addr, ptr_size);

      ProcessTracer::read_memory(pid, info.runtime_addr + offsets.runtime_heap,
                                 &info.heap_addr, ptr_size);

      
      
      size_t thread_list_offset = is64 ? 0x1E8 : 0xF4;
      ProcessTracer::read_memory(pid, info.runtime_addr + thread_list_offset,
                                 &info.thread_list_addr, ptr_size);
    } else {
      
      
      size_t class_linker_offset = 0x310;
      if (info.sdk_version >= 30)
        class_linker_offset = 0x320;
      if (info.sdk_version >= 31)
        class_linker_offset = 0x330;
      if (info.sdk_version >= 33)
        class_linker_offset = 0x340;
      if (info.sdk_version >= 34)
        class_linker_offset = 0x348;
      if (info.sdk_version >= 35)
        class_linker_offset = 0x350;

      ProcessTracer::read_memory(pid, info.runtime_addr + class_linker_offset,
                                 &info.class_linker_addr, ptr_size);

      size_t heap_offset = is64 ? 0x1F8 : 0xFC;
      ProcessTracer::read_memory(pid, info.runtime_addr + heap_offset,
                                 &info.heap_addr, ptr_size);
    }
  }

  return info;
}

int ARTHooker::get_sdk_version(int pid) {
  
  

  std::ifstream f("/system/build.prop");
  std::string line;
  while (std::getline(f, line)) {
    if (line.find("ro.build.version.sdk=") == 0) {
      return atoi(line.substr(21).c_str());
    }
  }

  
  return 29;
}

uint64_t ARTHooker::find_class_by_descriptor(int pid,
                                             const std::string &descriptor) {
  auto runtime = find_art_runtime(pid);
  if (runtime.class_linker_addr == 0)
    return 0;

  
  uint64_t find_class = FunctionHooker::find_remote_symbol(
      pid, "libart.so",
      "_ZN3art11ClassLinker9FindClassEPNS_6ThreadEPKcNS_6HandleINS_"
      "6mirror11ClassLoaderEEE");

  if (find_class == 0) {
    
    find_class = FunctionHooker::find_remote_symbol(
        pid, "libart.so",
        "_ZN3art11ClassLinker11LookupClassEPNS_6ThreadEPKcPNS_"
        "6mirror11ClassLoaderE");
  }

  if (find_class == 0)
    return 0;

  
  uint64_t desc_addr =
      FunctionHooker::allocate_remote(pid, descriptor.size() + 1);
  ProcessTracer::write_memory(pid, desc_addr, descriptor.c_str(),
                              descriptor.size() + 1);

  
  

  FunctionHooker::free_remote(pid, desc_addr, descriptor.size() + 1);
  return 0;
}

ARTClassInfo ARTHooker::get_class_info(int pid, uint64_t art_class) {
  ARTClassInfo info = {art_class, "", 0, 0, 0, 0, 0};

  if (art_class == 0)
    return info;

  int sdk = get_sdk_version(pid);
  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);

  
  
  
  

  ProcessTracer::read_memory(pid, art_class + 4, &info.access_flags, 4);

  size_t ptr_size = is64 ? 8 : 4;
  ProcessTracer::read_memory(pid, art_class + 0x10, &info.super_class,
                             ptr_size);

  return info;
}

std::vector<ARTClassInfo> ARTHooker::enumerate_loaded_classes(int pid) {
  std::vector<ARTClassInfo> classes;

  auto runtime = find_art_runtime(pid);
  if (runtime.class_linker_addr == 0)
    return classes;

  int sdk = get_sdk_version(pid);
  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;

  
  
  size_t class_table_offset = 0x48;
  if (sdk >= 30)
    class_table_offset = 0x50;
  if (sdk >= 31)
    class_table_offset = 0x58;
  if (sdk >= 33)
    class_table_offset = 0x60;

  uint64_t class_table_addr = 0;
  ProcessTracer::read_memory(pid,
                             runtime.class_linker_addr + class_table_offset,
                             &class_table_addr, ptr_size);

  if (class_table_addr == 0)
    return classes;

  
  
  uint64_t buckets_ptr = 0;
  uint32_t num_buckets = 0;

  ProcessTracer::read_memory(pid, class_table_addr, &buckets_ptr, ptr_size);
  ProcessTracer::read_memory(pid, class_table_addr + ptr_size * 2, &num_buckets,
                             4);

  if (buckets_ptr == 0 || num_buckets == 0 || num_buckets > 65536)
    return classes;

  
  for (uint32_t i = 0; i < num_buckets && classes.size() < 50000; i++) {
    uint64_t class_ptr = 0;
    ProcessTracer::read_memory(pid, buckets_ptr + i * ptr_size, &class_ptr,
                               ptr_size);

    if (class_ptr == 0 || class_ptr < 0x1000)
      continue;

    ARTClassInfo info = get_class_info(pid, class_ptr);
    if (info.class_addr != 0) {
      
      size_t desc_offset = is64 ? 0x28 : 0x1C;
      if (sdk >= 31)
        desc_offset = is64 ? 0x30 : 0x20;

      uint64_t desc_ptr = 0;
      ProcessTracer::read_memory(pid, class_ptr + desc_offset, &desc_ptr,
                                 ptr_size);

      if (desc_ptr != 0) {
        char desc_buf[256] = {0};
        ProcessTracer::read_memory(pid, desc_ptr, desc_buf, 255);
        info.descriptor = desc_buf;
      }

      classes.push_back(info);
    }
  }

  return classes;
}

std::vector<ARTMethodInfo> ARTHooker::get_class_methods(int pid,
                                                        uint64_t art_class) {
  std::vector<ARTMethodInfo> methods;

  if (art_class == 0)
    return methods;

  int sdk = get_sdk_version(pid);
  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;

  
  
  
  
  size_t methods_offset = is64 ? 0x30 : 0x20;
  if (sdk >= 31)
    methods_offset = is64 ? 0x38 : 0x24;
  if (sdk >= 33)
    methods_offset = is64 ? 0x40 : 0x28;

  uint64_t methods_ptr = 0;
  ProcessTracer::read_memory(pid, art_class + methods_offset, &methods_ptr,
                             ptr_size);

  if (methods_ptr == 0)
    return methods;

  
  uint32_t num_methods = 0;
  ProcessTracer::read_memory(pid, methods_ptr, &num_methods, 4);

  if (num_methods == 0 || num_methods > 10000)
    return methods;

  
  
  
  size_t artmethod_size = is64 ? 40 : 28;
  if (sdk >= 31)
    artmethod_size = is64 ? 48 : 32;
  if (sdk >= 33)
    artmethod_size = is64 ? 56 : 36;

  
  size_t array_offset = is64 ? 8 : 4;
  uint64_t methods_array = methods_ptr + array_offset;

  
  size_t desc_offset = is64 ? 0x28 : 0x1C;
  if (sdk >= 31)
    desc_offset = is64 ? 0x30 : 0x20;

  char class_desc[256] = {0};
  uint64_t desc_ptr = 0;
  ProcessTracer::read_memory(pid, art_class + desc_offset, &desc_ptr, ptr_size);
  if (desc_ptr != 0) {
    ProcessTracer::read_memory(pid, desc_ptr, class_desc, 255);
  }

  for (uint32_t i = 0; i < num_methods && methods.size() < 5000; i++) {
    uint64_t method_addr = methods_array + i * artmethod_size;

    ARTMethodInfo info;
    info.art_method_addr = method_addr;
    info.class_name = class_desc;

    
    ProcessTracer::read_memory(pid, method_addr + 4, &info.access_flags, 4);

    
    
    
    size_t entry_offset = is64 ? 0x20 : 0x14;
    if (sdk >= 31)
      entry_offset = is64 ? 0x28 : 0x18;

    ProcessTracer::read_memory(pid, method_addr + entry_offset,
                               &info.entry_point, ptr_size);

    
    uint32_t dex_method_idx = 0;
    ProcessTracer::read_memory(pid, method_addr, &dex_method_idx, 4);

    
    
    info.method_name = "method_" + std::to_string(dex_method_idx);
    info.signature = "()V"; 

    methods.push_back(info);
  }

  return methods;
}

uint64_t ARTHooker::find_method(int pid, const std::string &class_name,
                                const std::string &method_name,
                                const std::string &signature) {
  
  std::string descriptor = "L" + class_name + ";";
  std::replace(descriptor.begin(), descriptor.end(), '.', '/');

  uint64_t art_class = find_class_by_descriptor(pid, descriptor);
  if (art_class == 0)
    return 0;

  auto methods = get_class_methods(pid, art_class);
  for (const auto &m : methods) {
    if (m.method_name == method_name && m.signature == signature)
      return m.art_method_addr;
  }

  return 0;
}

bool ARTHooker::hook_method_entry(int pid, uint64_t art_method, uint64_t hook,
                                  uint64_t *original) {
  if (art_method == 0)
    return false;

  int sdk = get_sdk_version(pid);
  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);

  
  
  size_t entry_offset = is64 ? 0x20 : 0x14;
  if (sdk >= 31)
    entry_offset = is64 ? 0x28 : 0x18;

  size_t ptr_size = is64 ? 8 : 4;

  if (original) {
    ProcessTracer::read_memory(pid, art_method + entry_offset, original,
                               ptr_size);
  }

  return ProcessTracer::write_memory(pid, art_method + entry_offset, &hook,
                                     ptr_size);
}

bool ARTHooker::hook_method_native(int pid, uint64_t art_method,
                                   uint64_t native_func) {
  if (art_method == 0)
    return false;

  int sdk = get_sdk_version(pid);
  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);

  
  size_t data_offset = is64 ? 0x18 : 0x10;
  size_t ptr_size = is64 ? 8 : 4;

  return ProcessTracer::write_memory(pid, art_method + data_offset,
                                     &native_func, ptr_size);
}

bool ARTHooker::force_interpreter_mode(int pid, uint64_t art_method) {
  
  uint64_t bridge = FunctionHooker::find_remote_symbol(
      pid, "libart.so", "art_quick_to_interpreter_bridge");

  if (bridge == 0)
    return false;

  return hook_method_entry(pid, art_method, bridge, nullptr);
}

bool ARTHooker::force_jit_compilation(int pid, uint64_t art_method) {
  
  uint64_t jit_compile = FunctionHooker::find_remote_symbol(
      pid, "libart.so",
      "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadEb");

  if (jit_compile == 0)
    return false;

  
  

  return false;
}





JITCodeInfo JITAnalyzer::analyze_jit_code(const std::vector<uint8_t> &code,
                                          uint64_t base_addr, ArchMode arch) {
  JITCodeInfo info;
  info.addr = base_addr;
  info.size = code.size();
  info.is_osr = false;
  info.is_baseline = false;
  info.is_optimized = false;
  info.hotness_count = 0;

  
  for (size_t i = 0; i + 4 <= code.size(); i += 4) {
    uint32_t inst = *(const uint32_t *)(code.data() + i);

    if (arch == ArchMode::ARM64) {
      
      if ((inst & 0xFC000000) == 0x94000000) {
        int32_t offset = inst & 0x03FFFFFF;
        if (offset & 0x02000000)
          offset |= 0xFC000000;
        uint64_t target = base_addr + i + (int64_t)offset * 4;
        info.call_targets.push_back(target);
      }
      
      if ((inst & 0x9F000000) == 0x90000000) {
        
        int32_t immhi = ((inst >> 5) & 0x7FFFF) << 2;
        int32_t immlo = (inst >> 29) & 0x3;
        int32_t imm21 = immhi | immlo;
        if (imm21 & 0x100000)
          imm21 |= 0xFFE00000;
        uint64_t page = ((base_addr + i) & ~0xFFFULL) + ((int64_t)imm21 << 12);
        info.string_refs.push_back(page);
      }
    } else {
      
      if ((inst & 0x0F000000) == 0x0B000000) {
        int32_t offset = inst & 0x00FFFFFF;
        if (offset & 0x00800000)
          offset |= 0xFF000000;
        uint64_t target = base_addr + i + 8 + offset * 4;
        info.call_targets.push_back(target);
      }
    }
  }

  return info;
}

std::vector<JITCodeInfo>
JITAnalyzer::analyze_jit_region(const JITRegion &region, int pid) {
  std::vector<JITCodeInfo> results;

  ArchMode arch = ProcessTracer::get_arch();

  
  

  for (size_t offset = 0; offset < region.code.size();) {
    
    if (offset + 16 <= region.code.size()) {
      uint32_t inst = *(const uint32_t *)(region.code.data() + offset);

      bool is_prologue = false;
      if (arch == ArchMode::ARM64) {
        
        is_prologue = ((inst & 0xFFC003E0) == 0xA9800000) ||
                      ((inst & 0xFF0003FF) == 0xD10003FF);
      } else {
        
        is_prologue = ((inst & 0xFFFF0000) == 0xE92D0000);
      }

      if (is_prologue) {
        
        size_t func_size = InstructionDecoder::find_function_end(
            region.code.data() + offset, region.code.size() - offset, arch);

        if (func_size >= 8 && func_size <= 64 * 1024) {
          std::vector<uint8_t> func_code(region.code.data() + offset,
                                         region.code.data() + offset +
                                             func_size);
          auto info = analyze_jit_code(func_code, region.addr + offset, arch);
          results.push_back(info);
          offset += func_size;
          continue;
        }
      }
    }

    offset += 4;
  }

  return results;
}

std::string JITAnalyzer::disassemble_arm64(const uint8_t *code, size_t size,
                                           uint64_t base) {
  std::ostringstream out;

  for (size_t i = 0; i + 4 <= size; i += 4) {
    uint32_t inst = *(const uint32_t *)(code + i);
    auto decoded = InstructionDecoder::decode_arm64(inst, base + i);

    out << std::hex << std::setw(8) << std::setfill('0') << (base + i) << ": ";
    out << std::hex << std::setw(8) << std::setfill('0') << inst << "  ";

    switch (decoded.type) {
    case InstructionType::BranchLink:
      out << "BL 0x" << std::hex << decoded.target_address;
      break;
    case InstructionType::Branch:
      out << "B 0x" << std::hex << decoded.target_address;
      break;
    case InstructionType::Return:
      out << "RET";
      break;
    case InstructionType::BranchRegister:
      out << "BR X" << (int)decoded.rn;
      break;
    case InstructionType::Load:
      out << "LDR X" << (int)decoded.rd << ", [X" << (int)decoded.rn << ", #"
          << decoded.immediate << "]";
      break;
    case InstructionType::Store:
      out << "STR X" << (int)decoded.rd << ", [X" << (int)decoded.rn << ", #"
          << decoded.immediate << "]";
      break;
    case InstructionType::Adrp:
      out << "ADRP X" << (int)decoded.rd << ", 0x" << std::hex
          << decoded.target_address;
      break;
    default:
      out << ".word 0x" << std::hex << inst;
    }

    out << "\n";
  }

  return out.str();
}

std::string JITAnalyzer::disassemble_arm32(const uint8_t *code, size_t size,
                                           uint64_t base) {
  std::ostringstream out;

  for (size_t i = 0; i + 4 <= size; i += 4) {
    uint32_t inst = *(const uint32_t *)(code + i);
    auto decoded = InstructionDecoder::decode_arm32(inst, base + i);

    out << std::hex << std::setw(8) << std::setfill('0') << (base + i) << ": ";
    out << std::hex << std::setw(8) << std::setfill('0') << inst << "  ";

    switch (decoded.type) {
    case InstructionType::BranchLink:
      out << "BL 0x" << std::hex << decoded.target_address;
      break;
    case InstructionType::Branch:
      out << "B 0x" << std::hex << decoded.target_address;
      break;
    case InstructionType::Return:
      out << "BX LR";
      break;
    default:
      out << ".word 0x" << std::hex << inst;
    }

    out << "\n";
  }

  return out.str();
}

bool JITAnalyzer::hook_jit_compile(int pid, JITHook *hook) {
  if (!hook)
    return false;

  
  uint64_t compile_method = FunctionHooker::find_remote_symbol(
      pid, "libart.so",
      "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadEb");

  if (compile_method == 0) {
    
    compile_method = FunctionHooker::find_remote_symbol(
        pid, "libart.so",
        "_ZN3art3jit11JitCompiler15CompileMethodsEPNS_6ThreadENS_8ArrayRefIPNS_"
        "9ArtMethodEEE");
  }

  if (compile_method == 0)
    return false;

  hook->original_handler = compile_method;

  
  hook->compile_handler = compile_method;
  hook->active = true;

  return true;
}

bool JITAnalyzer::unhook_jit_compile(int pid, const JITHook &hook) {
  if (!hook.active)
    return false;

  
  
  return true;
}

std::vector<JITCompileEvent>
JITAnalyzer::monitor_jit_compiles(int pid, int duration_sec) {
  std::vector<JITCompileEvent> events;

  
  

  
  auto start_regions = dump_jit_code_cache(pid);

  sleep(duration_sec);

  auto end_regions = dump_jit_code_cache(pid);

  
  std::set<uint64_t> start_addrs;
  for (const auto &r : start_regions)
    start_addrs.insert(r.addr);

  time_t now = time(nullptr);
  for (const auto &r : end_regions) {
    if (start_addrs.find(r.addr) == start_addrs.end()) {
      JITCompileEvent event;
      event.code_addr = r.addr;
      event.code_size = r.size;
      event.timestamp = now;
      events.push_back(event);
    }
  }

  return events;
}

std::vector<JITCodeInfo>
JITAnalyzer::capture_jit_with_analysis(int pid, int duration_sec) {
  std::vector<JITCodeInfo> results;

  auto regions = ProcessTracer::capture_jit(pid, duration_sec);

  for (const auto &region : regions) {
    auto analyzed = analyze_jit_region(region, pid);
    results.insert(results.end(), analyzed.begin(), analyzed.end());
  }

  return results;
}

std::vector<JITRegion> JITAnalyzer::dump_jit_code_cache(int pid) {
  std::vector<JITRegion> regions;

  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;

  while (std::getline(maps, line)) {
    if ((line.find("[anon:jit-code-cache]") != std::string::npos ||
         line.find("[anon:dalvik-jit-code-cache]") != std::string::npos) &&
        line.find("x") != std::string::npos) {
      uint64_t start, end;
      if (sscanf(line.c_str(), "%lx-%lx", (unsigned long *)&start,
                 (unsigned long *)&end) == 2) {
        JITRegion region;
        region.addr = start;
        region.size = end - start;
        region.code.resize(region.size);
        if (ProcessTracer::read_memory(pid, start, region.code.data(),
                                       region.size))
          regions.push_back(region);
      }
    }
  }

  return regions;
}

bool JITAnalyzer::clear_jit_code_cache(int pid) {
  
  auto runtime_info = ARTHooker::find_art_runtime(pid);
  if (runtime_info.runtime_addr == 0)
    return false;

  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;
  int sdk = ARTHooker::get_sdk_version(pid);

  
  
  size_t jit_offset = 0x3A0;
  if (sdk >= 31)
    jit_offset = 0x3C0;
  if (sdk >= 33)
    jit_offset = 0x3E0;

  uint64_t jit_ptr = 0;
  ProcessTracer::read_memory(pid, runtime_info.runtime_addr + jit_offset,
                             &jit_ptr, ptr_size);

  if (jit_ptr == 0)
    return false;

  
  size_t cache_offset = is64 ? 0x8 : 0x4;
  uint64_t code_cache_ptr = 0;
  ProcessTracer::read_memory(pid, jit_ptr + cache_offset, &code_cache_ptr,
                             ptr_size);

  if (code_cache_ptr == 0)
    return false;

  
  uint64_t clear_func = FunctionHooker::find_remote_symbol(
      pid, "libart.so",
      "_ZN3art3jit12JitCodeCache27ClearAllExceptNativeMethodsEv");

  if (clear_func == 0) {
    
    clear_func = FunctionHooker::find_remote_symbol(
        pid, "libart.so", "_ZN3art3jit12JitCodeCache5ClearEv");
  }

  if (clear_func == 0)
    return false;

  
  std::vector<uint64_t> args = {code_cache_ptr};
  auto result = MemoryInjector::call_remote(pid, clear_func, args);

  return result.success;
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

    if (!config.exclude_libs.empty() && config.exclude_libs.count(lib))
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
      if (c.target_address != 0 && c.target_address != addr) {
        embed_recursive(c.target_address, depth + 1);
      }
    }
  };

  for (const auto &entry : calls) {
    uint64_t target = 0;
    if (StaticRelinker::resolve_symbol(pid, entry.symbol_name, &target)) {
      embed_recursive(target, 0);
    }
  }

  
  if (config.fix_relocations) {
    patch_relocations(result, embedded_addrs);
  }

  return result;
}

std::vector<uint8_t>
StaticRelinkerEx::extract_function_with_deps(int pid, uint64_t addr,
                                             int max_depth) {
  RelinkConfig config;
  config.max_depth = max_depth;
  config.max_total_size = 64 * 1024 * 1024;
  config.embed_data_refs = true;
  config.fix_relocations = true;
  config.inline_plt_calls = true;

  auto code = StaticRelinker::embed_function(pid, addr, 0);
  

  return code;
}

bool StaticRelinkerEx::patch_relocations(
    std::vector<uint8_t> &data, const std::map<uint64_t, uint64_t> &addr_map) {
  ArchMode arch = ProcessTracer::get_arch();

  
  for (size_t i = 0; i + 4 <= data.size(); i += 4) {
    uint32_t inst = *(uint32_t *)(data.data() + i);

    if (arch == ArchMode::ARM64) {
      if ((inst & 0xFC000000) == 0x94000000) { 
        int32_t offset = inst & 0x03FFFFFF;
        if (offset & 0x02000000)
          offset |= 0xFC000000;
        uint64_t target = i + (int64_t)offset * 4;

        auto it = addr_map.find(target);
        if (it != addr_map.end()) {
          int64_t new_offset = ((int64_t)it->second - (int64_t)i) / 4;
          if (new_offset >= -0x2000000 && new_offset < 0x2000000) {
            uint32_t new_inst = 0x94000000 | (new_offset & 0x03FFFFFF);
            *(uint32_t *)(data.data() + i) = new_inst;
          }
        }
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
    info.key_data.assign(k.key, k.key + k.key_size);
    info.algorithm = (k.key_size == 16)   ? "AES-128"
                     : (k.key_size == 24) ? "AES-192"
                                          : "AES-256";
    info.source = k.detection_method;
    info.confidence = k.confidence;
    info.capture_time = time(nullptr);
    keys.push_back(info);
  }

  return keys;
}

std::vector<CryptoKeyInfo>
CryptoAnalyzer::extract_runtime_keys(int pid, uint64_t base,
                                     const std::vector<uint8_t> &data) {
  std::vector<CryptoKeyInfo> keys;

  
  auto static_keys = scan_for_keys(data, base);
  keys.insert(keys.end(), static_keys.begin(), static_keys.end());

  
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;

  while (std::getline(maps, line)) {
    if (line.find("[heap]") != std::string::npos ||
        line.find("[anon:libc_malloc]") != std::string::npos) {
      uint64_t start, end;
      if (sscanf(line.c_str(), "%lx-%lx", (unsigned long *)&start,
                 (unsigned long *)&end) == 2) {
        
        const size_t chunk_size = 1024 * 1024;
        for (uint64_t addr = start; addr < end; addr += chunk_size) {
          size_t read_size = std::min(chunk_size, (size_t)(end - addr));
          std::vector<uint8_t> chunk(read_size);

          if (ProcessTracer::read_memory(pid, addr, chunk.data(), read_size)) {
            auto chunk_keys = scan_for_keys(chunk, addr);
            for (auto &k : chunk_keys) {
              k.source = "heap";
              keys.push_back(k);
            }
          }
        }
      }
    }
  }

  return keys;
}

std::vector<CryptoKeyInfo>
CryptoAnalyzer::trace_key_derivation(int pid, uint64_t crypto_func) {
  std::vector<CryptoKeyInfo> keys;

  if (crypto_func == 0)
    return keys;

  
  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);
  size_t ptr_size = is64 ? 8 : 4;

  
  uint32_t orig_inst;
  if (!ProcessTracer::read_memory(pid, crypto_func, &orig_inst, 4))
    return keys;

  
  uint32_t brk_inst = is64 ? 0xD4200000 : 0xE1200070;
  if (!ProcessTracer::write_memory(pid, crypto_func, &brk_inst, 4)) {
    return keys;
  }

  
  ProcessTracer::continue_process(pid);

  int status = 0;
  time_t start = time(nullptr);
  bool hit = false;

  
  while (time(nullptr) - start < 5) {
    if (ProcessTracer::wait_for_stop(pid, &status)) {
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        hit = true;
        break;
      }
    }
  }

  if (hit) {
    
    uint64_t key_ptr = ProcessTracer::get_register(pid, is64 ? 1 : 1);
    uint64_t key_len_hint = ProcessTracer::get_register(pid, is64 ? 2 : 2);

    
    if (key_len_hint == 0 || key_len_hint > 64)
      key_len_hint = 32; 

    if (key_ptr != 0 && key_ptr > 0x1000) {
      CryptoKeyInfo info;
      info.key_addr = key_ptr;
      info.key_data.resize(key_len_hint);

      if (ProcessTracer::read_memory(pid, key_ptr, info.key_data.data(),
                                     key_len_hint)) {
        info.algorithm = (key_len_hint == 16)   ? "AES-128"
                         : (key_len_hint == 24) ? "AES-192"
                         : (key_len_hint == 32) ? "AES-256"
                                                : "Unknown";
        info.source = "trace_key_derivation";
        info.confidence = 0.7;
        info.capture_time = time(nullptr);
        keys.push_back(info);
      }
    }
  }

  
  ProcessTracer::write_memory(pid, crypto_func, &orig_inst, 4);

  
  ProcessTracer::continue_process(pid);

  return keys;
}

std::vector<CryptoCallInfo>
CryptoAnalyzer::monitor_crypto_calls(int pid, int duration_sec) {
  std::vector<CryptoCallInfo> calls;

  struct CryptoTarget {
    std::string lib;
    std::string func;
    int key_arg_idx; 
    int len_arg_idx; 
  };

  std::vector<CryptoTarget> targets = {
      {"libcrypto.so", "EVP_EncryptInit_ex", 3, -1},
      {"libcrypto.so", "EVP_DecryptInit_ex", 3, -1},
      {"libcrypto.so", "AES_encrypt", 0, -1},
      {"libcrypto.so", "AES_decrypt", 0, -1},
      {"libcrypto.so", "AES_set_encrypt_key", 0, 1},
      {"libcrypto.so", "AES_set_decrypt_key", 0, 1},
  };

  bool is64 = (ProcessTracer::get_arch() == ArchMode::ARM64);

  
  struct Breakpoint {
    uint64_t addr;
    uint32_t orig_inst;
    CryptoTarget target;
    bool active;
  };

  std::vector<Breakpoint> breakpoints;

  for (const auto &t : targets) {
    uint64_t addr = FunctionHooker::find_remote_symbol(pid, t.lib, t.func);
    if (addr != 0) {
      Breakpoint bp;
      bp.addr = addr;
      bp.target = t;
      bp.active = false;

      if (ProcessTracer::read_memory(pid, addr, &bp.orig_inst, 4)) {
        uint32_t brk_inst = is64 ? 0xD4200000 : 0xE1200070;
        if (ProcessTracer::write_memory(pid, addr, &brk_inst, 4)) {
          bp.active = true;
          breakpoints.push_back(bp);
        }
      }
    }
  }

  if (breakpoints.empty())
    return calls;

  
  ProcessTracer::continue_process(pid);

  time_t start = time(nullptr);
  while (time(nullptr) - start < duration_sec && calls.size() < 1000) {
    int status = 0;
    if (ProcessTracer::wait_for_stop(pid, &status)) {
      if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        uint64_t pc = ProcessTracer::get_pc(pid);

        
        for (auto &bp : breakpoints) {
          if (bp.active && bp.addr == pc) {
            CryptoCallInfo info;
            info.func_addr = bp.addr;
            info.func_name = bp.target.func;

            
            int key_reg = bp.target.key_arg_idx;
            if (key_reg >= 0 && key_reg < 8) {
              uint64_t key_ptr = ProcessTracer::get_register(pid, key_reg);
              if (key_ptr != 0 && key_ptr > 0x1000) {
                info.key_data.resize(32);
                ProcessTracer::read_memory(pid, key_ptr, info.key_data.data(),
                                           32);
              }
            }

            
            if (bp.target.len_arg_idx >= 0) {
              uint64_t len =
                  ProcessTracer::get_register(pid, bp.target.len_arg_idx);
              if (len > 0 && len <= 64) {
                info.key_data.resize(len);
              }
            }

            
            uint64_t input_ptr = ProcessTracer::get_register(pid, 0);
            if (input_ptr != 0 && input_ptr > 0x1000) {
              info.input_data.resize(64);
              ProcessTracer::read_memory(pid, input_ptr, info.input_data.data(),
                                         64);
            }

            calls.push_back(info);

            
            ProcessTracer::write_memory(pid, bp.addr, &bp.orig_inst, 4);
            ProcessTracer::single_step(pid);
            uint32_t brk_inst = is64 ? 0xD4200000 : 0xE1200070;
            ProcessTracer::write_memory(pid, bp.addr, &brk_inst, 4);
            break;
          }
        }
      }
      ProcessTracer::continue_process(pid);
    }
  }

  
  for (auto &bp : breakpoints) {
    if (bp.active) {
      ProcessTracer::write_memory(pid, bp.addr, &bp.orig_inst, 4);
    }
  }

  return calls;
}

std::vector<uint8_t> CryptoAnalyzer::dump_ssl_session_keys(int pid) {
  std::vector<uint8_t> keys;

  
  uint64_t libssl = 0;
  auto ranges = ProcessTracer::get_library_ranges(pid);
  for (const auto &r : ranges) {
    if (r.name.find("libssl.so") != std::string::npos) {
      libssl = r.start;
      break;
    }
  }

  
  
  
  

  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;

  while (std::getline(maps, line)) {
    if (line.find("[heap]") != std::string::npos ||
        line.find("[anon:libc_malloc]") != std::string::npos ||
        line.find("libssl") != std::string::npos) {
      uint64_t start, end;
      if (sscanf(line.c_str(), "%lx-%lx", (unsigned long *)&start,
                 (unsigned long *)&end) != 2)
        continue;

      
      size_t scan_size =
          std::min((size_t)(end - start), (size_t)(32 * 1024 * 1024));
      std::vector<uint8_t> mem(scan_size);

      if (!ProcessTracer::read_memory(pid, start, mem.data(), scan_size))
        continue;

      
      
      
      for (size_t i = 0; i + 64 < scan_size; i += 8) {
        
        uint32_t len = *(uint32_t *)(mem.data() + i);
        if (len == 48) {
          
          const uint8_t *key_data = mem.data() + i + 4;

          
          
          int zero_count = 0;
          int printable_count = 0;
          for (int j = 0; j < 48; j++) {
            if (key_data[j] == 0)
              zero_count++;
            if (key_data[j] >= 0x20 && key_data[j] <= 0x7E)
              printable_count++;
          }

          
          if (zero_count < 10 && printable_count < 40) {
            
            
            keys.insert(keys.end(), key_data, key_data + 48);
          }
        }
      }
    }
  }

  return keys;
}

std::vector<CryptoKeyInfo> CryptoAnalyzer::extract_openssl_keys(int pid) {
  std::vector<CryptoKeyInfo> keys;

  
  uint64_t libcrypto = 0;
  auto ranges = ProcessTracer::get_library_ranges(pid);
  for (const auto &r : ranges) {
    if (r.name.find("libcrypto.so") != std::string::npos) {
      libcrypto = r.start;
      break;
    }
  }

  if (libcrypto == 0)
    return keys;

  
  size_t lib_size = 0;
  for (const auto &r : ranges) {
    if (r.name.find("libcrypto.so") != std::string::npos) {
      if (r.end > libcrypto + lib_size)
        lib_size = r.end - libcrypto;
    }
  }

  if (lib_size > 16 * 1024 * 1024)
    lib_size = 16 * 1024 * 1024;

  std::vector<uint8_t> data(lib_size);
  if (ProcessTracer::read_memory(pid, libcrypto, data.data(), lib_size)) {
    keys = scan_for_keys(data, libcrypto);
  }

  return keys;
}

std::vector<CryptoKeyInfo> CryptoAnalyzer::extract_boringssl_keys(int pid) {
  
  
  return extract_openssl_keys(pid);
}

bool CryptoAnalyzer::hook_aes_encrypt(int pid, uint64_t *original) {
  uint64_t aes_encrypt =
      FunctionHooker::find_remote_symbol(pid, "libcrypto.so", "AES_encrypt");
  if (aes_encrypt == 0) {
    
    aes_encrypt = FunctionHooker::find_remote_symbol(pid, "libcrypto.so",
                                                     "aes_nohw_encrypt");
  }

  if (aes_encrypt == 0)
    return false;

  if (original)
    *original = aes_encrypt;

  
  return true;
}

bool CryptoAnalyzer::hook_aes_decrypt(int pid, uint64_t *original) {
  uint64_t aes_decrypt =
      FunctionHooker::find_remote_symbol(pid, "libcrypto.so", "AES_decrypt");
  if (aes_decrypt == 0) {
    aes_decrypt = FunctionHooker::find_remote_symbol(pid, "libcrypto.so",
                                                     "aes_nohw_decrypt");
  }

  if (aes_decrypt == 0)
    return false;

  if (original)
    *original = aes_decrypt;

  return true;
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
