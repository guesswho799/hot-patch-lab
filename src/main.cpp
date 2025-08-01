#include "crow.h"
#include "crow/mustache.h"
#include "elf_reader.hpp"
#include "elf_runner.hpp"
#include <filesystem>
#include <iostream>
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

  std::string executable_simlink = std::format("{}/exe", it.begin()->path().string());
  std::string process_executable_path = std::filesystem::read_symlink(executable_simlink);
  ElfReader exe_file{process_executable_path};
  const auto functions = exe_file.get_functions() |
         std::views::transform([](const Function &f) { return f.name; });
  return std::vector(functions.begin(), functions.end());
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
          // ElfRunner runner{pid};
          return std::format("Selected process: {}, function: {}", process, function);
        });

    app.port(18080).run();

  } catch (const std::exception &exception) {
    std::cerr << exception.what() << std::endl;
    return 1;
  }

  return 0;
}
