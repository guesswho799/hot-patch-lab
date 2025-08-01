#include "elf_reader.hpp"
#include "elf_header.hpp"
#include <cctype>
#include <ranges>
#include <algorithm>
#include <cstdint>
#include <elf.h>
#include <format>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

// constructors
ElfReader::ElfReader(std::string file_name)
    : _file(std::ifstream(file_name)), _file_name(file_name),
      _header(header_factory()), _sections(sections_factory()),
      _static_symbols(static_symbols_factory()), _strings(strings_factory()) {}

ElfReader::ElfReader(ElfReader &&other)
    : _file(std::ifstream(other._file_name)), _file_name(other._file_name),
      _header(other.get_header()), _sections(other.get_sections()),
      _static_symbols(other.get_static_symbols()),
      _strings(other.get_strings()) {}

ElfReader &ElfReader::operator=(ElfReader &&other) {
  _file = std::ifstream(other._file_name);
  _file_name = other._file_name;
  _header = other.get_header();
  _sections = other.get_sections();
  _static_symbols = other.get_static_symbols();
  _strings = other.get_strings();
  return *this;
}

ElfReader::~ElfReader() { _file.close(); }

// geters
ElfHeader ElfReader::get_header() const { return _header; }

std::vector<NamedSection> ElfReader::get_sections() const { return _sections; }

std::vector<NamedSymbol> ElfReader::get_static_symbols() const {
  return _static_symbols;
}

std::vector<ElfString> ElfReader::get_strings() const { return _strings; }

// filtered geters
bool ElfReader::is_position_independent() const {
  return _header.file_type == ET_DYN;
}

bool ElfReader::does_section_exist(const std::string_view &section_name) const {
  for (const auto &section : _sections) {
    if (section.name == section_name) {
      return true;
    }
  }
  return false;
}

NamedSection
ElfReader::get_section(const std::string_view &section_name) const {
  for (const auto &section : _sections) {
    if (section.name == section_name) {
      return section;
    }
  }

  throw std::runtime_error(std::format("missing section: {}", section_name));
}

std::vector<unsigned char>
ElfReader::get_section_data(const std::string_view &section_name) const {
  const NamedSection section_info = get_section(section_name);
  std::vector<unsigned char> section_data(section_info.size);
  _file.seekg(static_cast<long>(section_info.unloaded_offset));
  _file.read(reinterpret_cast<char *>(section_data.data()),
             section_data.size());

  return section_data;
}

size_t
ElfReader::get_section_index(const std::string_view &section_name) const {
  size_t index = 0;
  for (const auto &section : _sections) {
    if (section.name == section_name) {
      return index;
    }
    index++;
  }

  throw std::runtime_error(std::format("missing section: {}", section_name));
}

NamedSection ElfReader::get_section(std::size_t section_index) const {
  if (_sections.size() < section_index) {
    throw std::runtime_error("section search out of bounds: " + section_index);
  }

  return _sections[section_index];
}

std::vector<NamedSymbol> ElfReader::get_non_file_symbols() const {
  const auto symbol_filter = [&](const NamedSymbol &symbol) {
    return (symbol.type & SymbolType::file) == 0;
  };

  std::vector<NamedSymbol> symbols{};
  for (const auto &symbol :
       _static_symbols | std::views::filter(symbol_filter)) {
    symbols.push_back(symbol);
  }

  return symbols;
}

NamedSymbol ElfReader::get_symbol(const std::string &name) const {
  const auto function_filter = [&](const NamedSymbol &symbol) {
    return symbol.name == name;
  };
  const auto iterator = std::find_if(_static_symbols.begin(),
                                     _static_symbols.end(), function_filter);
  if (iterator == _static_symbols.end())
    throw std::runtime_error("missing function: " + name);

  return *iterator;
}

Function ElfReader::get_function(const std::string &name) const {
  const auto function = get_symbol(name);
  const uint64_t offset =
      function.value + _sections[function.section_index].unloaded_offset -
      _sections[function.section_index].loaded_virtual_address;

  // because bug in gcc? sybols missing size, must set by hand
  uint64_t actual_size = function.size;
  if (name == "__do_global_dtors_aux" or name == "frame_dummy" or
      name == "register_tm_clones" or name == "deregister_tm_clones") {
    actual_size = 0x40;
  } else if (name == "_fini") {
    actual_size = 0xd;
  } else if (name == "_init") {
    actual_size = 0x1b;
  } else if (name == "__restore_rt") {
    actual_size = 0x9;
  }
  _file.seekg(static_cast<long>(offset));
  std::vector<unsigned char> buffer(actual_size);
  _file.read(reinterpret_cast<char *>(buffer.data()), buffer.size());

  return {.name = function.name,
          .address = function.value,
          .size = actual_size,
          .opcodes = buffer};
}

std::vector<Function> ElfReader::get_functions() const {
  const auto text_section = get_section(code_section_name);
  const auto init_section = get_section(init_section_name);
  const auto fini_section = get_section(fini_section_name);

  const auto is_in_section = [](const NamedSection &section,
                                const NamedSymbol &symbol) {
    return symbol.value >= section.loaded_virtual_address and
           symbol.value + symbol.size <=
               section.loaded_virtual_address + section.size;
  };
  const auto function_filter = [&](const NamedSymbol &symbol) {
    return is_in_section(text_section, symbol) or
           is_in_section(init_section, symbol) or
           is_in_section(fini_section, symbol);
  };

  std::vector<Function> functions{};
  for (const auto &symbol :
       _static_symbols | std::views::filter(function_filter)) {
    functions.push_back(get_function(symbol.name));
  }

  return functions;
}

// factories
ElfHeader ElfReader::header_factory() {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  ElfHeader elf_header{};
  _file.read(reinterpret_cast<char *>(&elf_header), sizeof elf_header);

  return elf_header;
}

std::vector<NamedSection> ElfReader::sections_factory() {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  _file.seekg(static_cast<long>(_header.section_table_address));

  std::vector<SectionHeader> sections{};
  for (int i = 0; i < _header.section_table_entry_count; i++) {
    SectionHeader section{};
    _file.read(reinterpret_cast<char *>(&section), sizeof section);

    sections.push_back(section);
  }

  std::vector<NamedSection> named_sections{};
  for (const auto &section : sections) {
    _file.seekg(sections[_header.section_table_name_index].unloaded_offset +
                section.name_offset);
    std::string name;
    std::getline(_file, name, '\0');
    named_sections.emplace_back(
        name, section.type, section.attributes, section.loaded_virtual_address,
        section.unloaded_offset, section.size, section.associated_section_index,
        section.extra_information, section.required_alinment,
        section.entry_size);
  }

  return named_sections;
}

std::vector<NamedSymbol>
ElfReader::symbols_factory(const std::string_view &section_name,
                           const std::string_view &string_table_name) {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  const NamedSection symbol_table = get_section(section_name);

  _file.seekg(symbol_table.unloaded_offset);

  std::vector<ElfSymbol> symbols{};
  while (static_cast<uint64_t>(_file.tellg()) <
         symbol_table.unloaded_offset + symbol_table.size) {
    ElfSymbol symbol{};
    _file.read(reinterpret_cast<char *>(&symbol), sizeof symbol);
    symbols.push_back(symbol);
  }

  const NamedSection str_table = get_section(string_table_name);
  std::vector<NamedSymbol> named_symbols{};
  for (const auto &symbol : symbols) {
    _file.seekg(str_table.unloaded_offset + symbol.name);
    std::string name;
    std::getline(_file, name, '\0');
    named_symbols.emplace_back(name, static_cast<SymbolType>(symbol.type),
                               symbol.section_index, symbol.value, symbol.size);
  }

  return named_symbols;
}

template <typename It>
std::pair<int, size_t> ElfReader::find_next_start_of_function(It begin,
                                                              It end) {
  int amount_of_instructions = 0;
  size_t function_size = 0;
  int amount_of_function_begin_passed = 0;
  for (; begin != end; ++begin) {
    if (begin->instruction == start_of_function_instruction)
      if (++amount_of_function_begin_passed == 2)
        break;

    amount_of_instructions++;
    function_size += begin->opcodes.end() - begin->opcodes.begin();
  }
  return std::make_pair(amount_of_instructions, function_size);
}

std::vector<NamedSymbol> ElfReader::static_symbols_factory() {
  return symbols_factory(static_symbol_section_name,
                         static_symbol_name_section_name);
}

std::vector<Function> ElfReader::get_rela_functions() {
  const auto functions = get_functions();
  const auto relocation_info_section =
      get_section(relocation_plt_symbol_info_section_name);
  ElfRelocation relocation_info{};
  std::vector<Function> rela_functions;

  _file.seekg(static_cast<long>(relocation_info_section.unloaded_offset));
  while (static_cast<uint64_t>(_file.tellg()) <
         relocation_info_section.unloaded_offset +
             relocation_info_section.size) {
    _file.read(reinterpret_cast<char *>(&relocation_info),
               sizeof relocation_info);
    for (const auto &function : functions) {
      if (function.address == relocation_info.function_address) {
        rela_functions.emplace_back(function);
        break;
      }
    }
  }

  return rela_functions;
}

std::vector<Function> ElfReader::get_functions_from_array_section(
    const std::string_view &section_name) {
  const auto section = get_section(section_name);
  const auto functions = get_functions();
  std::vector<Function> result;
  uint64_t address;

  _file.seekg(static_cast<long>(section.unloaded_offset));
  while (static_cast<uint64_t>(_file.tellg()) <
         section.unloaded_offset + section.size) {
    _file.read(reinterpret_cast<char *>(&address), sizeof(uint64_t));
    for (const auto &function : functions) {
      if (function.address == address) {
        result.emplace_back(function);
        break;
      }
    }
  }

  return result;
}

std::vector<ElfString> ElfReader::strings_factory() {
  if (!_file.is_open())
    throw std::runtime_error("binary open failed");

  const NamedSection string_section = get_section(".rodata");
  _file.seekg(static_cast<long>(string_section.unloaded_offset));
  std::vector<ElfString> strings;
  while (static_cast<uint64_t>(_file.tellg()) <
         string_section.unloaded_offset + string_section.size) {
    const auto address = static_cast<uint64_t>(_file.tellg());
    const auto value = get_next_string(string_section);
    if (_is_valid_string(value)) {
      strings.emplace_back(std::string{value.begin(), value.end()}, address);
    }
  }

  return strings;
}

std::vector<char>
ElfReader::get_next_string(const NamedSection &string_section) {
  char byte_read;
  std::vector<char> result;
  while (static_cast<uint64_t>(_file.tellg()) <
         string_section.unloaded_offset + string_section.size) {
    _file.read(reinterpret_cast<char *>(&byte_read), sizeof byte_read);

    if (byte_read == 0)
      break;

    result.push_back(byte_read);
  }
  return result;
}

bool ElfReader::_is_valid_string(const std::vector<char> &s) {
  if (s.size() == 0)
    return false;

  bool is_all_whitespace = true;
  for (const auto &character : s) {
    if (!std::isprint(character) and character != '\n')
      return false;

    if (is_all_whitespace) {
      is_all_whitespace = isspace(character);
    }
  }

  if (is_all_whitespace)
    return false;

  return true;
}
