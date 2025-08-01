#pragma once

#include <cerrno>
#include <cstdint>
#include <stdexcept>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>

namespace Ptrace {
inline user_regs_struct get_regs(pid_t pid) {
  struct user_regs_struct regs{};
  errno = 0;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1 or errno != 0) {
    throw std::runtime_error("ptrace peek registers failed");
  }
  return regs;
}

inline void set_regs(pid_t pid, user_regs_struct regs) {
  errno = 0;
  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1 or errno != 0) {
    throw std::runtime_error("ptrace poke registers failed");
  }
}

inline uint64_t get_memory(pid_t pid, uint64_t address) {
  errno = 0;
  const uint64_t code = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
  if (errno != 0) {
    throw std::runtime_error("ptrace peek code failed");
  }
  return code;
}

inline void set_memory(pid_t pid, uint64_t address, uint64_t code) {
  errno = 0;
  if (ptrace(PTRACE_POKETEXT, pid, address, code) == -1 or errno != 0) {
    throw std::runtime_error("ptrace poke code failed");
  }
}

inline void single_step(pid_t pid) {
  errno = 0;
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1 or errno != 0) {
    throw std::runtime_error("ptrace step failed");
  }
}

inline void cont(pid_t pid) {
  errno = 0;
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1 or errno != 0) {
    throw std::runtime_error("ptrace continue failed");
  }
}
} // namespace Ptrace
