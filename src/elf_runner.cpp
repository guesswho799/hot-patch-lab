#include "elf_runner.hpp"
#include "elf_reader.hpp"
#include "ptrace_utils.hpp"

#include <iostream>
#include <algorithm>
#include <cstdint>
#include <fcntl.h>
#include <format>
#include <fstream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <unistd.h>

ElfRunner::ElfRunner(pid_t pid)
    : _pid(pid), _base_address(_get_base_address(pid)), _breakpoints(),
      _runtime_regs(), _runtime_stacks(), _runtime_arguments(),
      _is_dead(false) {}

uint64_t ElfRunner::_get_base_address(pid_t pid) {
  ElfReader exe_file{std::format("/proc/{}/exe", pid)};
  if (!exe_file.is_position_independent())
    return 0;

  const std::regex pattern("([0-9a-f]+)-.*");
  std::ifstream mapping_file(std::format("/proc/{}/maps", pid));
  std::string line;
  std::smatch match;
  std::getline(mapping_file, line);
  if (std::regex_match(line, match, pattern)) {
    return _hex_to_int(match[1].str());
  }

  _is_dead = true;
  return 0;
}

void ElfRunner::run_functions(const std::vector<NamedSymbol> &functions) {
  const int child_status = _get_child_status();
  if (_check_child_status(child_status))
    return;

  if (_breakpoints.empty()) {
    for (const auto &function : functions) {
      _breakpoints.emplace_back(function.value, _pid);
    }
    Ptrace::cont(_pid);
    return;
  }

  const auto breakpoint = std::find_if(_breakpoints.begin(), _breakpoints.end(),
                                       [&](const BreakpointHook &b) {
                                         return b.is_hit(child_status);
                                       });
  if (breakpoint == _breakpoints.end())
    return;

  _log_function_arguments(functions, breakpoint->get_address());

  // resume child regular flow
  struct user_regs_struct regs = Ptrace::get_regs(_pid);
  regs.rip--;
  Ptrace::set_regs(_pid, regs);
  breakpoint->unhook();
  _log_step();
  breakpoint->hook();
  Ptrace::cont(_pid);
}

void ElfRunner::run_function(const NamedSymbol &function,
                             const std::vector<Address> &calls) {
  const int child_status = _get_child_status();
  if (_check_child_status(child_status))
    return;

  if (_breakpoints.empty()) {
    _breakpoints.emplace_back(function.value, _pid);
    for (const auto &call : calls) {
      _breakpoints.emplace_back(call, _pid);
    }
    Ptrace::cont(_pid);
    return;
  }

  const auto breakpoint = std::find_if(_breakpoints.begin(), _breakpoints.end(),
                                       [&](const BreakpointHook &b) {
                                         return b.is_hit(child_status);
                                       });
  if (breakpoint == _breakpoints.end())
    return;

  // resume child regular flow
  struct user_regs_struct regs = Ptrace::get_regs(_pid);
  regs.rip--;
  Ptrace::set_regs(_pid, regs);
  breakpoint->unhook();
  while (regs.rip >= function.value and
         regs.rip <= function.value + function.size) {
    _log_step();
    regs = Ptrace::get_regs(_pid);
  }
  breakpoint->hook();
  Ptrace::cont(_pid);
}

void ElfRunner::_log_step() {
  struct user_regs_struct regs = Ptrace::get_regs(_pid);
  regs.rip -= _base_address;
  _runtime_regs.push_back(regs);

  const auto base_stack = regs.rbp;
  std::array<StackElement, stack_size> stack{};
  if (base_stack != 0)
    for (int i = 0; i < stack_size; i++)
      stack[i] = static_cast<StackElement>(Ptrace::get_memory(
          _pid, base_stack - (i * sizeof(StackElement))));
  _runtime_stacks.emplace_back(base_stack, stack);

  int child_status = 0;
  Ptrace::single_step(_pid);
  if (wait(&child_status) == -1) {
    throw std::runtime_error("wait failed");
  }
  if (WIFEXITED(child_status) or WIFSIGNALED(child_status)) {
    throw std::runtime_error("child died");
  }
}

void ElfRunner::_log_function_arguments(
    const std::vector<NamedSymbol> &functions, Address function_address) {
  const auto get_function_by_address = [&](NamedSymbol function) {
    return function.value == function_address;
  };
  const auto iterator =
      std::find_if(functions.begin(), functions.end(), get_function_by_address);
  if (iterator == functions.end())
    throw std::runtime_error("unable to find function");

  const auto regs = Ptrace::get_regs(_pid);
  _runtime_arguments[iterator->name] = {regs.rdi, regs.rsi, regs.rdx};
}

int ElfRunner::_get_child_status() {
  int child_status = 0;
  int status = waitpid(_pid, &child_status, WNOHANG | WUNTRACED);
  if (status == -1) {
    throw std::runtime_error("wait failed");
  }
  if (status != 0) {
    _update_is_dead(child_status);
  }
  return child_status;
}

bool ElfRunner::_check_child_status(int child_status) {
  return is_dead() or !WIFSTOPPED(child_status);
}

void ElfRunner::_update_is_dead(int child_status) {
  if (_is_dead)
    return;

  _is_dead = WIFEXITED(child_status);
}

bool ElfRunner::is_dead() const { return _is_dead; }

ElfRunner::RuntimeArguments ElfRunner::get_runtime_arguments() const {
  return _runtime_arguments;
}

ElfRunner::RuntimeRegs ElfRunner::get_runtime_regs() const {
  return _runtime_regs;
}

ElfRunner::RuntimeStacks ElfRunner::get_runtime_stacks() const {
  return _runtime_stacks;
}

pid_t ElfRunner::get_pid() const { return _pid; }

uint64_t ElfRunner::_hex_to_int(const std::string &s) {
  uint64_t result = 0;
  std::stringstream ss;
  ss << std::hex << s;
  ss >> result;
  return result;
}
