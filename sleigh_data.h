#pragma once
#include <cstddef>

// The AArch64 sleigh language definition, compiled into the binary. See
// cross/embed_sleigh.py for how sleigh_data.cpp is generated.
namespace sleigh_data {

struct File {
  const char *name;
  const unsigned char *bytes;
  size_t size;
};

const File *files();
size_t file_count();

} // namespace sleigh_data
