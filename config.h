#pragma once

#include <map>
#include <string>
#include <vector>

struct ARTOffsetConfig {
  int sdk_version;
  uint64_t class_linker_offset;
  uint64_t heap_offset;
  uint64_t thread_list_offset;
  uint64_t dex_caches_offset;
  uint64_t dex_file_offset;
  uint64_t methods_offset;
  uint64_t entry_point_offset;
  bool valid;
};

class ConfigLoader {
public:
  static ConfigLoader &instance();

  // Loads simple key-value config
  // format: 64:34:class_linker=0x348
  bool load_config(const std::string &path);
  ARTOffsetConfig get_offsets(int sdk_version, bool is_64bit);

private:
  ConfigLoader() = default;
  std::map<int, ARTOffsetConfig> offsets_64;
  std::map<int, ARTOffsetConfig> offsets_32;
};
