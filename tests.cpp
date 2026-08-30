#include "memory.h"
#include "rizin_bridge.h"
#include "tracer.h"

#include <array>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

int failures = 0;

void check(bool condition, const char *name) {
  if (condition) {
    std::cout << "[PASS] " << name << "\n";
    return;
  }
  std::cerr << "[FAIL] " << name << "\n";
  ++failures;
}

std::vector<uint8_t> read_file(const char *path) {
  std::ifstream input(path, std::ios::binary);
  return {(std::istreambuf_iterator<char>(input)),
          std::istreambuf_iterator<char>()};
}

size_t count_occurrences(std::string_view haystack, std::string_view needle) {
  size_t count = 0;
  for (size_t offset = 0;
       (offset = haystack.find(needle, offset)) != std::string_view::npos;
       offset += needle.size())
    ++count;
  return count;
}

std::vector<uint8_t> make_elf(int64_t bind_tag, uint64_t bind_value) {
  constexpr size_t kDynamicOffset = 0x200;
  std::vector<uint8_t> image(0x400, 0);

  Elf64_Ehdr header{};
  memcpy(header.e_ident, ELFMAG, SELFMAG);
  header.e_ident[EI_CLASS] = ELFCLASS64;
  header.e_ident[EI_DATA] = ELFDATA2LSB;
  header.e_ident[EI_VERSION] = EV_CURRENT;
  header.e_type = ET_DYN;
  header.e_machine = EM_AARCH64;
  header.e_version = EV_CURRENT;
  header.e_ehsize = sizeof(header);
  header.e_phoff = sizeof(header);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = 3;
  memcpy(image.data(), &header, sizeof(header));

  Elf64_Phdr segments[3]{};
  segments[0].p_type = PT_LOAD;
  segments[0].p_flags = PF_R | PF_X;
  segments[0].p_offset = 0;
  segments[0].p_vaddr = 0;
  segments[0].p_filesz = image.size();
  segments[0].p_memsz = image.size();
  segments[0].p_align = 0x1000;
  segments[1].p_type = PT_GNU_RELRO;
  segments[1].p_offset = 0x300;
  segments[1].p_vaddr = 0x300;
  segments[1].p_filesz = 0x40;
  segments[1].p_memsz = 0x40;
  segments[1].p_flags = PF_R;
  segments[2].p_type = PT_DYNAMIC;
  segments[2].p_offset = kDynamicOffset;
  segments[2].p_vaddr = kDynamicOffset;
  segments[2].p_filesz = 2 * sizeof(Elf64_Dyn);
  segments[2].p_memsz = segments[2].p_filesz;
  segments[2].p_flags = PF_R | PF_W;
  memcpy(image.data() + header.e_phoff, segments, sizeof(segments));

  Elf64_Dyn dynamic[2]{};
  dynamic[0].d_tag = bind_tag;
  dynamic[0].d_un.d_val = bind_value;
  dynamic[1].d_tag = DT_NULL;
  memcpy(image.data() + kDynamicOffset, dynamic, sizeof(dynamic));
  return image;
}

void make_loader_mutated_fixture(std::vector<uint8_t> *runtime,
                                 std::vector<uint8_t> *disk) {
  constexpr size_t kRuntimeSize = 0x400;
  constexpr size_t kRelocationOffset = 0x180;
  constexpr size_t kDynamicOffset = 0x200;
  constexpr size_t kGotOffset = 0x380;
  constexpr size_t kStringOffset = 0x480;
  constexpr size_t kSectionOffset = 0x500;
  disk->assign(0x600, 0);

  Elf64_Ehdr header{};
  memcpy(header.e_ident, ELFMAG, SELFMAG);
  header.e_ident[EI_CLASS] = ELFCLASS64;
  header.e_ident[EI_DATA] = ELFDATA2LSB;
  header.e_ident[EI_VERSION] = EV_CURRENT;
  header.e_type = ET_DYN;
  header.e_machine = EM_AARCH64;
  header.e_version = EV_CURRENT;
  header.e_ehsize = sizeof(header);
  header.e_phoff = sizeof(header);
  header.e_phentsize = sizeof(Elf64_Phdr);
  header.e_phnum = 3;
  header.e_shoff = kSectionOffset;
  header.e_shentsize = sizeof(Elf64_Shdr);
  header.e_shnum = 2;
  header.e_shstrndx = 1;
  memcpy(disk->data(), &header, sizeof(header));

  Elf64_Phdr segments[3]{};
  segments[0].p_type = PT_LOAD;
  segments[0].p_flags = PF_R | PF_W | PF_X;
  segments[0].p_filesz = kRuntimeSize;
  segments[0].p_memsz = kRuntimeSize;
  segments[0].p_align = 0x1000;
  segments[1].p_type = PT_LOAD;
  segments[1].p_flags = PF_R | PF_W;
  segments[1].p_offset = 0x1000;
  segments[1].p_vaddr = 0x1000;
  segments[1].p_filesz = 0;
  segments[1].p_memsz = 0x1000;
  segments[1].p_align = 0x1000;
  segments[2].p_type = PT_DYNAMIC;
  segments[2].p_flags = PF_R | PF_W;
  segments[2].p_offset = kDynamicOffset;
  segments[2].p_vaddr = kDynamicOffset;
  segments[2].p_filesz = 4 * sizeof(Elf64_Dyn);
  segments[2].p_memsz = segments[2].p_filesz;
  segments[2].p_align = 8;
  memcpy(disk->data() + header.e_phoff, segments, sizeof(segments));

  Elf64_Dyn dynamic[4]{};
  dynamic[0].d_tag = DT_JMPREL;
  dynamic[0].d_un.d_ptr = kRelocationOffset;
  dynamic[1].d_tag = DT_PLTRELSZ;
  dynamic[1].d_un.d_val = sizeof(Elf64_Rela);
  dynamic[2].d_tag = DT_PLTREL;
  dynamic[2].d_un.d_val = DT_RELA;
  dynamic[3].d_tag = DT_NULL;
  memcpy(disk->data() + kDynamicOffset, dynamic, sizeof(dynamic));

  Elf64_Rela relocation{};
  relocation.r_offset = kGotOffset;
  relocation.r_info = ELF64_R_INFO(0, R_AARCH64_JUMP_SLOT);
  memcpy(disk->data() + kRelocationOffset, &relocation, sizeof(relocation));

  static constexpr char section_names[] = "\0.shstrtab\0";
  memcpy(disk->data() + kStringOffset, section_names, sizeof(section_names));
  Elf64_Shdr sections[2]{};
  sections[1].sh_name = 1;
  sections[1].sh_type = SHT_STRTAB;
  sections[1].sh_offset = kStringOffset;
  sections[1].sh_size = sizeof(section_names);
  sections[1].sh_addralign = 1;
  memcpy(disk->data() + kSectionOffset, sections, sizeof(sections));

  runtime->assign(disk->begin(), disk->begin() + kRuntimeSize);
  const uint64_t loader_address = 0x7a0000123456ULL;
  memcpy(runtime->data() + kGotOffset, &loader_address, sizeof(loader_address));
}

void test_patterns() {
  const std::vector<uint8_t> text = {'x', 'f', 'o', 'o', ' ', 'b', 'a', 'r'};
  check(ElfParser::pattern_width("text:foo bar") == 7,
        "text pattern width includes spaces");
  auto text_matches = ElfParser::pattern_scan(text, "text:foo bar");
  check(text_matches.size() == 1 && text_matches[0].offset == 1,
        "text pattern match");

  const std::vector<uint8_t> bytes = {0xde, 0xad, 0x11, 0xef, 0xde, 0xad};
  auto wildcard = ElfParser::pattern_scan(bytes, "hex:de ad ?? ef");
  check(wildcard.size() == 1 && wildcard[0].offset == 0, "hex wildcard match");
  check(ElfParser::pattern_width("hex:de ad 0g") == 0,
        "malformed hex rejected");
  check(ElfParser::pattern_width("hex:100") == 0,
        "oversized hex byte rejected");
  check(ElfParser::pattern_width("") == 0, "empty pattern rejected");
}

void test_elf_security_and_repair() {
  auto flags = make_elf(DT_FLAGS, DF_BIND_NOW);
  auto flags1 = make_elf(DT_FLAGS_1, DF_1_NOW);
  auto tag = make_elf(DT_BIND_NOW, 0);
  auto partial = make_elf(DT_FLAGS, 0);

  check(ElfParser::has_relro(flags), "GNU RELRO detected");
  check(ElfParser::has_full_relro(flags), "DF_BIND_NOW detected");
  check(ElfParser::has_full_relro(flags1), "DF_1_NOW detected");
  check(ElfParser::has_full_relro(tag), "DT_BIND_NOW detected");
  check(!ElfParser::has_full_relro(partial), "partial RELRO not overstated");

  auto bss_snapshot = partial;
  Elf64_Ehdr bss_header{};
  Elf64_Phdr bss_segment{};
  memcpy(&bss_header, bss_snapshot.data(), sizeof(bss_header));
  memcpy(&bss_segment, bss_snapshot.data() + bss_header.e_phoff,
         sizeof(bss_segment));
  bss_segment.p_offset = 0x1000;
  bss_segment.p_filesz = 0;
  bss_segment.p_memsz = 0x1000;
  memcpy(bss_snapshot.data() + bss_header.e_phoff, &bss_segment,
         sizeof(bss_segment));
  Elf64ProgramHeaders parsed_bss;
  check(parse_elf64_program_headers(bss_snapshot, &parsed_bss),
        "pure-BSS load beyond snapshot has no file range");

  bool repaired = false;
  auto fixed = SoFixer::repair(partial, 0, nullptr, &repaired);
  check(repaired && fixed.size() > partial.size() && ElfParser::is_elf(fixed),
        "valid ELF repair reports success");
  rzb::set_analysis_level(rzb::AnalysisLevel::None);
  if (const char *scratch = std::getenv("HAYABUSA_TEST_SCRATCH"))
    rzb::set_scratch_directory(scratch);
  auto rizin_image = rzb::Image::open(fixed, 0);
  check(static_cast<bool>(rizin_image), "Rizin opens synthetic repaired ELF");

  std::vector<uint8_t> system_elf = read_file("/system/lib64/libc.so");
  check(!system_elf.empty(), "Android system libc fixture is readable");
  auto system_image = rzb::Image::open(system_elf, 0);
  check(static_cast<bool>(system_image), "Rizin opens Android system libc");

  rzb::AnalysisLimits limits;
  limits.module_timeout_seconds = 30;
  limits.table_timeout_seconds = 30;
  limits.pointer_scan_bytes = 64U * 1024U * 1024U;
  limits.pointer_slots = 100000;
  limits.pointer_tables = 10000;
  limits.analysis_targets = 100000;
  rzb::set_analysis_limits(limits);
  rzb::set_analysis_level(rzb::AnalysisLevel::Basic);
  std::vector<uint8_t> sleep_elf = read_file("/system/bin/sleep");
  auto analyzed = rzb::Image::open(sleep_elf, 0);
  check(static_cast<bool>(analyzed), "Rizin opens Android sleep fixture");
  if (analyzed) {
    analyzed->analyze();
    auto functions = analyzed->functions();
    check(!analyzed->analysis_failed(), "Rizin basic analysis completes");
    check(!functions.empty(), "Rizin recovers native functions");

    std::string decompiled;
    for (size_t i = 0; i < functions.size() && i < 32; ++i) {
      if (analyzed->function_size(functions[i]) < 8)
        continue;
      decompiled = analyzed->decompile(functions[i]);
      if (!decompiled.empty())
        break;
    }
    check(!decompiled.empty(), "Ghidra decompiles a recovered function");
  }

  std::vector<uint8_t> invalid = {0x7f, 'E', 'L', 'F'};
  repaired = true;
  std::string failure_reason;
  auto unchanged =
      SoFixer::repair(invalid, 0, nullptr, &repaired, &failure_reason);
  check(!repaired && unchanged == invalid && !failure_reason.empty(),
        "failed ELF repair is explicit and lossless");

  std::vector<uint8_t> loader_runtime;
  std::vector<uint8_t> loader_disk;
  make_loader_mutated_fixture(&loader_runtime, &loader_disk);
  failure_reason.clear();
  repaired = false;
  auto restored = SoFixer::repair(loader_runtime, 0, &loader_disk, &repaired,
                                  &failure_reason);
  check(repaired && restored == loader_disk,
        "loader-mutated ELF restores exact disk baseline");

  const char *runtime_path = std::getenv("HAYABUSA_TEST_RUNTIME_ELF");
  const char *disk_path = std::getenv("HAYABUSA_TEST_DISK_ELF");
  if ((runtime_path == nullptr) != (disk_path == nullptr)) {
    check(false, "real ELF fixture requires both runtime and disk paths");
  } else if (runtime_path && disk_path) {
    auto runtime = read_file(runtime_path);
    auto disk = read_file(disk_path);
    failure_reason.clear();
    repaired = false;
    restored = SoFixer::repair(runtime, 0, &disk, &repaired, &failure_reason);
    if (!repaired)
      std::cerr << "[INFO] baseline repair rejection: " << failure_reason
                << "\n";
    check(repaired && restored == disk,
          "real loader-mutated ELF restores exact disk baseline");
  } else {
    std::cout << "[SKIP] optional real runtime/disk ELF fixture not supplied\n";
  }
}

void test_dex_decompilation() {
  const char *path = std::getenv("HAYABUSA_TEST_T4_DEX");
  if (!path) {
    std::cout << "[SKIP] optional T4 DEX fixture not supplied\n";
    return;
  }

  const auto data = read_file(path);
  rzb::set_analysis_level(rzb::AnalysisLevel::Full);
  auto image = rzb::Image::open(data);
  check(static_cast<bool>(image), "T4 DEX fixture opens");
  if (!image)
    return;

  size_t attempted = 0;
  size_t succeeded = 0;
  std::string decompiled;
  for (const auto &klass : image->bin_classes()) {
    for (const auto &method : klass.methods) {
      if (!method.vaddr || !method.paddr || !method.size)
        continue;
      ++attempted;
      const std::string source =
          image->decompile_dex_method(method.vaddr, method.size);
      if (source.empty())
        continue;
      ++succeeded;
      decompiled.append(source).push_back('\n');
    }
  }

  constexpr std::array<std::string_view, 4> resolved_evidence = {
      "T4_DEX_TOKEN_", "->counter", "->append", "new t4.T4Secrets"};
  size_t resolved = 0;
  for (std::string_view evidence : resolved_evidence)
    resolved += decompiled.find(evidence) != std::string::npos;
  check(attempted == 7, "T4 DEX concrete method count");
  check(succeeded == attempted, "T4 DEX methods decompile");
  check(resolved == resolved_evidence.size(),
        "T4 DEX constant-pool references resolve");
  check(count_occurrences(decompiled, "UNKNOWNREF") == 0,
        "T4 DEX emits no unresolved references");
}

void test_entropy() {
  std::vector<uint8_t> uniform(256, 0);
  check(ElfParser::calculate_entropy(uniform.data(), uniform.size()) == 0.0,
        "uniform entropy is zero");

  std::vector<uint8_t> balanced(512);
  for (size_t i = 0; i < balanced.size(); ++i)
    balanced[i] = static_cast<uint8_t>(i);
  check(ElfParser::calculate_entropy(balanced.data(), 256) > 7.99,
        "balanced byte entropy is eight bits");
  auto regions = ElfParser::find_high_entropy_regions(balanced, 256, 7.9, 8);
  check(regions.size() == 1 && regions[0].offset == 0 &&
            regions[0].size == balanced.size(),
        "overlapping entropy windows retain full region span");
}

void test_demangling_and_decoder() {
  check(ElfParser::demangle_symbol("_Z3foov") == "foo()",
        "Itanium symbol demangles through libc++abi");
  check(ElfParser::demangle_symbol("_Zbad") == "_Zbad",
        "invalid mangling remains unchanged");

  const DecodedInstruction branch =
      InstructionDecoder::decode(0x94000002u, 0x1000);
  check(branch.type == InstructionType::BranchLink &&
            branch.target_address == 0x1008,
        "AArch64 BL target decode");
  const DecodedInstruction ret =
      InstructionDecoder::decode(0xd65f03c0u, 0x2000);
  check(ret.type == InstructionType::Return, "AArch64 RET decode");
}

void test_proc_maps_identity() {
  auto maps = Memory::read_maps(getpid());
  check(!maps.empty(), "/proc/self/maps parsed");
  bool found_file_identity = false;
  for (const auto &mapping : maps) {
    if (mapping.start >= mapping.end || mapping.perms.empty()) {
      check(false, "parsed mapping ranges are coherent");
      return;
    }
    if (!mapping.name.empty() && mapping.name.front() == '/' &&
        mapping.inode != 0)
      found_file_identity = true;
  }
  check(true, "parsed mapping ranges are coherent");
  check(found_file_identity, "mapped file device/inode identity retained");
}

} // namespace

int main() {
  test_patterns();
  test_elf_security_and_repair();
  test_dex_decompilation();
  test_entropy();
  test_demangling_and_decoder();
  test_proc_maps_identity();
  if (failures != 0) {
    std::cerr << failures << " test(s) failed\n";
    return 1;
  }
  std::cout << "All Hayabusa production-linked tests passed.\n";
  return 0;
}
