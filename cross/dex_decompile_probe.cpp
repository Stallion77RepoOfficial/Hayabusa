#include "rizin_bridge.h"

#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace {

size_t count_occurrences(std::string_view haystack, std::string_view needle) {
  size_t count = 0;
  for (size_t offset = 0;
       (offset = haystack.find(needle, offset)) != std::string_view::npos;
       offset += needle.size())
    ++count;
  return count;
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  std::ifstream input(argv[1], std::ios::binary);
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(input)), {});
  rzb::set_analysis_level(rzb::AnalysisLevel::Full);
  auto image = rzb::Image::open(data);
  if (!image) {
    std::cerr << "open failed\n";
    return 3;
  }
  size_t attempted = 0;
  size_t succeeded = 0;
  std::string decompiled;
  for (const auto &klass : image->bin_classes()) {
    for (const auto &method : klass.methods) {
      if (!method.vaddr || !method.paddr || !method.size)
        continue;
      attempted++;
      const std::string source =
          image->decompile_dex_method(method.vaddr, method.size);
      std::cout << "=== " << klass.name << "." << method.name << " @0x"
                << std::hex << method.vaddr << std::dec << " ===\n";
      if (source.empty()) {
        std::cout << "ERROR: " << image->decompiler_error() << "\n";
      } else {
        succeeded++;
        decompiled.append(source).push_back('\n');
        std::cout << source << "\n";
      }
    }
  }

  constexpr std::array<std::string_view, 4> resolved_evidence = {
      "T4_DEX_TOKEN_",     // string_id
      "->counter",         // field_id
      "->append",          // method_id
      "new t4.T4Secrets",  // type_id
  };
  size_t resolved = 0;
  for (std::string_view evidence : resolved_evidence)
    resolved += decompiled.find(evidence) != std::string::npos;
  const size_t unknown_refs = count_occurrences(decompiled, "UNKNOWNREF");

  std::cout << "RESOLVED " << resolved << "/" << resolved_evidence.size()
            << "\n";
  std::cout << "UNKNOWNREF " << unknown_refs << "\n";
  std::cout << "SUMMARY " << succeeded << "/" << attempted << "\n";
  constexpr size_t expected_methods = 7;
  return attempted == expected_methods && succeeded == attempted &&
                 resolved == resolved_evidence.size() && unknown_refs == 0
             ? 0
             : 1;
}
