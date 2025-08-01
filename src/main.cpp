#include "crow.h"
#include "crow/mustache.h"
#include "disassembler.hpp"
#include "elf_reader.hpp"
#include "elf_runner.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <ostream>
#include <ranges>
#include <sched.h>
#include <stdexcept>

std::vector<std::string> get_processes() {
  const auto is_directory = [](const auto &entry) {
    return entry.is_directory();
  };
  const auto is_process = [](const auto &entry) {
    const auto filename = entry.path().filename().string();
    return std::ranges::all_of(filename, ::isdigit);
  };

  std::vector<std::string> result;
  for (const auto &entry : std::filesystem::directory_iterator("/proc") |
                               std::views::filter(is_directory) |
                               std::views::filter(is_process)) {

    // Try to open /proc/[PID]/comm
    std::ifstream comm_file(entry.path() / "comm");
    if (!comm_file)
      continue;

    std::string process_name;
    std::getline(comm_file, process_name);
    if (!process_name.empty())
      result.push_back(process_name);
  }

  return result;
}

std::vector<std::string> get_functions(const std::string &process) {
  const auto is_directory = [](const auto &entry) {
    return entry.is_directory();
  };
  const auto is_process = [](const auto &entry) {
    const auto filename = entry.path().filename().string();
    return std::ranges::all_of(filename, ::isdigit);
  };
  const auto is_specific_process = [&process](const auto &entry) {
    std::ifstream comm_file(entry.path() / "comm");
    if (!comm_file)
      return false;

    std::string process_name;
    std::getline(comm_file, process_name);
    return process_name == process;
  };

  auto it = std::filesystem::directory_iterator("/proc") |
            std::views::filter(is_directory) | std::views::filter(is_process) |
            std::views::filter(is_specific_process);
  if (it.begin() == it.end()) {
    throw std::runtime_error("no process found");
  }

  std::string executable_simlink =
      std::format("{}/exe", it.begin()->path().string());
  std::string process_executable_path =
      std::filesystem::read_symlink(executable_simlink);
  ElfReader exe_file{process_executable_path};
  const auto functions =
      exe_file.get_functions() |
      std::views::transform([](const Function &f) { return f.name; });
  return std::vector(functions.begin(), functions.end());
}

std::string get_code(const std::string &process, const std::string &function) {
  const auto is_directory = [](const auto &entry) {
    return entry.is_directory();
  };
  const auto is_process = [](const auto &entry) {
    const auto filename = entry.path().filename().string();
    return std::ranges::all_of(filename, ::isdigit);
  };
  const auto is_specific_process = [&process](const auto &entry) {
    std::ifstream comm_file(entry.path() / "comm");
    if (!comm_file)
      return false;

    std::string process_name;
    std::getline(comm_file, process_name);
    return process_name == process;
  };

  auto it = std::filesystem::directory_iterator("/proc") |
            std::views::filter(is_directory) | std::views::filter(is_process) |
            std::views::filter(is_specific_process);
  if (it.begin() == it.end()) {
    throw std::runtime_error("no process found");
  }

  std::string executable_simlink =
      std::format("{}/exe", it.begin()->path().string());
  std::string process_executable_path =
      std::filesystem::read_symlink(executable_simlink);

  ElfReader exe_file{process_executable_path};
  Disassembler disassembler;

  auto lines = exe_file.get_function_code_by_name(function);
  std::stringstream stream;

  for (const auto &line :
       lines | std::views::transform([](const Disassembler::Line &line) {
         return line.instruction + line.arguments;
       })) {
    stream << line << "\n";
  }
  return stream.str();
}

int main() {
  try {
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    ([]() {
      auto page = crow::mustache::load("index.html");
      crow::mustache::context ctx;
      ctx["processes"] = get_processes();
      return crow::response(crow::mustache::load("index.html").render(ctx));
    });

    CROW_ROUTE(app, "/<string>")
        .methods("POST"_method)([](std::string process) {
          auto page = crow::mustache::load("function_selector.html");
          crow::mustache::context ctx;
          ctx["process"] = process;
          ctx["functions"] = get_functions(process);
          return crow::response(
              crow::mustache::load("function_selector.html").render(ctx));
        });

    CROW_ROUTE(app, "/<string>/<string>")
        .methods("POST"_method)([](std::string process, std::string function) {
          auto page = crow::mustache::load("function_selector.html");
          crow::mustache::context ctx;
          ctx["process"] = process;
          ctx["function"] = function;
          ctx["assembly"] = get_code(process, function);
          return crow::response(crow::mustache::load("code.html").render(ctx));
        });

    app.port(18080).run();

  } catch (const std::exception &exception) {
    std::cerr << exception.what() << std::endl;
    return 1;
  }

  return 0;
}
