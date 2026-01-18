#include "config.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>

ConfigLoader &ConfigLoader::instance() {
  static ConfigLoader instance;
  return instance;
}




bool ConfigLoader::load_config(const std::string &path) {
  std::ifstream f(path);
  if (!f.is_open())
    return false;

  std::string line;
  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#')
      continue;

    
    

    size_t first_colon = line.find(':');
    size_t second_colon = line.find(':', first_colon + 1);
    size_t eq_pos = line.find('=');

    if (first_colon == std::string::npos || second_colon == std::string::npos ||
        eq_pos == std::string::npos)
      continue;

    std::string bitness_str = line.substr(0, first_colon);
    std::string sdk_str =
        line.substr(first_colon + 1, second_colon - first_colon - 1);
    std::string key = line.substr(second_colon + 1, eq_pos - second_colon - 1);
    std::string val_str = line.substr(eq_pos + 1);

    int bitness = 0;
    int sdk = 0;

    try {
      bitness = std::stoi(bitness_str);
      sdk = std::stoi(sdk_str);
    } catch (...) {
      continue;
    }

    uint64_t val = 0;
    try {
      val = std::stoull(val_str, nullptr, 16);
    } catch (...) {
      continue;
    }

    auto &target_map = (bitness == 64) ? offsets_64 : offsets_32;
    ARTOffsetConfig &cfg = target_map[sdk];
    cfg.sdk_version = sdk;
    cfg.valid = true;

    if (key == "class_linker")
      cfg.class_linker_offset = val;
    else if (key == "heap")
      cfg.heap_offset = val;
    else if (key == "thread_list")
      cfg.thread_list_offset = val;
    else if (key == "dex_caches")
      cfg.dex_caches_offset = val;
    else if (key == "dex_file")
      cfg.dex_file_offset = val;
    else if (key == "methods")
      cfg.methods_offset = val;
    else if (key == "entry_point")
      cfg.entry_point_offset = val;
  }
  return true;
}

ARTOffsetConfig ConfigLoader::get_offsets(int sdk_version, bool is_64bit) {
  auto &map = is_64bit ? offsets_64 : offsets_32;
  if (map.find(sdk_version) != map.end()) {
    return map[sdk_version];
  }
  return {sdk_version, 0, 0, 0, 0, 0, 0, 0, false};
}
