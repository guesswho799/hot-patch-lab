#include "crow.h"
#include "crow/logging.h"
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
#include <unordered_map>

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

std::filesystem::path process_name_to_path_in_proc(const std::string &process) {
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
  return it.begin()->path();
}

pid_t process_name_to_pid(const std::string &process) {
  return std::stoi(process_name_to_path_in_proc(process).filename().string());
}

std::string process_name_to_binary_path(const std::string &process) {
  const auto path = process_name_to_path_in_proc(process);
  std::string executable_simlink = std::format("{}/exe", path.string());
  return std::filesystem::read_symlink(executable_simlink);
}

std::vector<std::string> get_functions(const std::string &process) {
  ElfReader exe_file{process_name_to_binary_path(process)};
  const auto functions =
      exe_file.get_functions() |
      std::views::transform([](const Function &f) { return f.name; });
  return std::vector(functions.begin(), functions.end());
}

std::string get_code(const std::string &process, const std::string &function) {
  ElfReader exe_file{process_name_to_binary_path(process)};
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

std::vector<std::string> supported_actions() {
  return {"Counter Log", "Time Log", "Custom"};
}

int main() {
  try {
    crow::SimpleApp app;
    std::mutex mtx;
    // websocket connection is owned by internal crow logic
    // I store it as a pointer to not take ownership
    std::unordered_map<crow::websocket::connection *,
                       std::pair<ElfRunner, std::string>>
        connections;

    CROW_ROUTE(app, "/")
    ([]() {
      auto page = crow::mustache::load("index.html");
      crow::mustache::context ctx;
      ctx["processes"] = get_processes();
      return crow::response(crow::mustache::load("index.html").render(ctx));
    });

    CROW_ROUTE(app, "/favicon.ico")
    ([]() {
      std::ifstream in("templates/favicon.ico", std::ios::binary);
      if (!in)
        return crow::response(404);

      std::ostringstream contents;
      contents << in.rdbuf();
      auto resp = crow::response(contents.str());
      resp.set_header("Content-Type", "image/x-icon");
      return resp;
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
        .methods("POST"_method)([](const crow::request &req,
                                   std::string process, std::string function) {
          auto page = crow::mustache::load("function_selector.html");
          crow::mustache::context ctx;

          std::string host = req.get_header_value("Host");
          auto colon_pos = host.find(':');
          if (colon_pos != std::string::npos) {
            host = host.substr(0, colon_pos);
          }
          ctx["servername"] = host;
          ctx["process"] = process;
          ctx["function"] = function;
          ctx["assembly"] = get_code(process, function);
          ctx["actions"] = supported_actions();
          return crow::response(crow::mustache::load("code.html").render(ctx));
        });

    CROW_WEBSOCKET_ROUTE(app, "/ws")
        .onopen([&](crow::websocket::connection &conn) {
          CROW_LOG_INFO << "new websocket connection from "
                        << conn.get_remote_ip();
        })
        .onclose(
            [&](crow::websocket::connection &conn, const std::string &reason) {
              CROW_LOG_INFO << "websocket connection closed: " << reason;
              std::lock_guard<std::mutex> _(mtx);
              if (connections.contains(&conn)) {
                connections.erase(&conn);
              }
            })
        .onmessage([&](crow::websocket::connection &conn,
                       const std::string &data, bool is_binary) {
          CROW_LOG_INFO << "websocket data: " << data;
          std::lock_guard<std::mutex> _(mtx);
          if (not connections.contains(&conn)) {
            auto space_pos = data.find(' ');
            if (space_pos == std::string::npos) {
              CROW_LOG_ERROR << "invalid data";
              return;
            }
            auto process = data.substr(0, space_pos);
            auto function = data.substr(space_pos, data.size());
            connections.emplace(&conn,
                                std::pair<ElfRunner, std::string>{
                                    process_name_to_pid(process), function});
          } else {
            const auto supported = supported_actions();
            if (std::find(supported.begin(), supported.end(), data) ==
                    supported.end() and
                data != "Back") {
              CROW_LOG_ERROR << "unsupported action!";
              return;
            }
            // TODO: handle data
          }
        });

    app.port(18080).run();

  } catch (const std::exception &exception) {
    std::cerr << exception.what() << std::endl;
    return 1;
  }

  return 0;
}
