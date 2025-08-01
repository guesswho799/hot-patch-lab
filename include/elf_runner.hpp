#pragma once

#include "breakpoint_hook.hpp"
#include "elf_header.hpp"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <sys/types.h>
#include <sys/user.h>
#include <vector>

class ElfRunner {
public:
  using Address = uint64_t;
  using RuntimeRegs = std::vector<struct user_regs_struct>;
  using RuntimeArguments =
      std::map<std::string, std::tuple<int64_t, int64_t, int64_t>>;

  static constexpr int stack_size = 10;
  using StackElement = uint32_t;
  using RuntimeStack = std::pair<Address, std::array<StackElement, stack_size>>;
  using RuntimeStacks = std::vector<RuntimeStack>;

public:
  explicit ElfRunner(pid_t pid);
  ElfRunner(const ElfRunner &other) = delete;
  ElfRunner &operator=(const ElfRunner &other) = delete;
  ElfRunner(ElfRunner &&other) = default;
  ElfRunner &operator=(ElfRunner &&other) = default;
  ~ElfRunner() = default;

public:
  void run_functions(const std::vector<NamedSymbol> &functions);
  void run_function(const NamedSymbol &function,
                    const std::vector<Address> &calls);

  bool is_dead() const;
  RuntimeArguments get_runtime_arguments() const;
  RuntimeRegs get_runtime_regs() const;
  RuntimeStacks get_runtime_stacks() const;
  pid_t get_pid() const;

private:
  uint64_t _get_base_address(pid_t pid);
  void _update_is_dead(int child_status);
  void _log_step();
  void _log_function_arguments(const std::vector<NamedSymbol> &functions,
                               Address function_address);
  int _get_child_status();
  bool _check_child_status(int child_status);
  static uint64_t _hex_to_int(const std::string &s);

private:
  pid_t _pid;
  uint64_t _base_address;
  std::vector<BreakpointHook> _breakpoints;
  RuntimeRegs _runtime_regs;
  RuntimeStacks _runtime_stacks;
  RuntimeArguments _runtime_arguments;
  bool _is_dead;
};
