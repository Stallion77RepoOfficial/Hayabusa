#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

// Disassembly and decompilation, backed by rizin and the Ghidra decompiler.
//
// Both are linked in statically, so nothing here loads a plugin from disk. The
// hand-written AArch64 decoder this replaces covered a couple of dozen
// encodings and could not do dataflow at all; rizin brings a complete
// disassembler, function recovery and cross-references, and rz-ghidra turns
// that into C.
namespace rzb {

// How much analysis rizin runs per module. There is no automatic downgrade
// between these: if a level cannot run, the call fails and says so rather than
// quietly producing the weaker result.
enum class AnalysisLevel {
  None,  // load and parse only; no function/RTTI/table recovery side effects
  Basic, // rizin `aa` -- functions, but no data cross-references
  Full,  // rizin `aaa` -- adds data/string cross-references and type matching
};

// Applies to every Image opened afterwards. Set once at startup.
void set_analysis_level(AnalysisLevel level);

// Directory used only for the content-addressed embedded Sleigh cache. The
// caller supplies a trusted, private directory before opening the first image;
// module bytes themselves stay in anonymous memfd storage.
void set_scratch_directory(const std::string &directory);

// Instruction types hayabusa actually branches on. rizin distinguishes far more
// than this -- the rest all arrive as Other.
enum class InsnType {
  Other,
  Branch,
  ConditionalBranch,
  Call,
  Return,
  Load,
  Store,
  Adrp,
  Add,
};

struct Insn {
  uint64_t addr = 0;
  uint32_t raw = 0;      // the 4 encoded bytes
  std::string text;      // "bl sym.foo"
  InsnType type = InsnType::Other;
  uint64_t target = 0;   // branch/call destination, 0 when there is none
  bool is_call = false;
  bool is_return = false;
  bool is_indirect = false;
};

struct Call {
  uint64_t site = 0;     // address of the calling instruction
  uint64_t target = 0;
  std::string symbol;    // empty when the target has no name
};

// An ELF image opened for analysis. Analysis is deferred: the constructor only
// loads the image, and the expensive passes run on first use of anything that
// needs them, because a dump run opens hundreds of modules and most reports
// never ask for function-level detail.
class Image {
public:
  // `data` is a whole ELF image; `base` is its load address when it came from a
  // memory dump, or 0 for a file. Returns null when rizin cannot load it.
  static std::unique_ptr<Image> open(const std::vector<uint8_t> &data,
                                     uint64_t base = 0);
  ~Image();

  Image(const Image &) = delete;
  Image &operator=(const Image &) = delete;

  // Runs rizin's function/xref analysis at the configured level. Idempotent.
  void analyze();
  // True when the requested analysis level or an address translation needed by
  // it did not complete. Analysis-backed queries still answer from the partial
  // database, but their results are incomplete rather than "no findings".
  bool analysis_failed() const;

  // The address the module is mapped at in the target, or 0 when unknown.
  // rizin always holds the image at zero; this is what relocated pointers read
  // out of the image have to be measured against.
  uint64_t base() const;
  void adopt_base(uint64_t base);

  // `max_bytes` bounds the walk to a known function or method body; 0 means
  // "until `count` instructions have been decoded".
  std::vector<Insn> disassemble(uint64_t addr, size_t count,
                                size_t max_bytes = 0);

  // C for one function. Empty when the decompiler is unavailable -- check
  // decompiler_error() for why. Requires analyze().
  std::string decompile(uint64_t addr);

  // C for one concrete DEX method. Rizin does not always promote constructors
  // and tiny methods to analysis functions, so this explicitly defines the
  // method entry before invoking the Dalvik decompiler. `vaddr` must fit the
  // 32-bit Dalvik Sleigh address space.
  std::string decompile_dex_method(uint64_t vaddr, uint64_t size);
  const std::string &decompiler_error() const;

  // Entry addresses of every function rizin recovered. Requires analyze().
  std::vector<uint64_t> functions();
  // Byte length of the function containing `addr`, or 0 when unknown.
  uint64_t function_size(uint64_t addr);
  // Name rizin has for `addr` (symbol, import stub, or its generated fcn.*).
  std::string name_at(uint64_t addr);

  // Every call site that reaches an imported symbol, across the whole image.
  std::vector<Call> import_call_sites();

  struct RttiClass {
    uint64_t typeinfo_vaddr = 0;
    uint64_t vtable_vaddr = 0;
    std::string name;
    std::vector<uint64_t> vfuncs;
  };
  std::vector<RttiClass> rtti_classes();

  // Classes exactly as the bin plugin reports them, with no C++ assumptions.
  // This is what a DEX gives back: the format carries class, method and field
  // names outright, so nothing has to be inferred from vtables or mangling.
  struct BinClass {
    std::string name;
    std::string super;
    struct Method {
      std::string name;
      uint64_t paddr = 0; // file offset of the code item
      uint64_t vaddr = 0; // what rizin's own analysis is keyed on
      uint64_t size = 0;  // bytes of bytecode, 0 when unknown
    };
    std::vector<Method> methods;
    std::vector<std::string> fields;
  };
  std::vector<BinClass> bin_classes();

  struct Import {
    uint64_t got_vaddr = 0;  // slot the loader writes
    uint64_t stub_vaddr = 0; // PLT stub a call branches to, 0 when unknown
    std::string symbol;
  };
  // Every relocation that binds an imported symbol.
  std::vector<Import> imports();

  // Code addresses that reference `target`, from rizin's cross-reference
  // database. Covers every way an address can be formed, not just the
  // ADRP/ADD pair a hand-written scanner can recognise.
  std::vector<uint64_t> xrefs_to(uint64_t target, size_t max_results,
                                 size_t *examined_remaining,
                                 bool *truncated = nullptr);

  // File offset to virtual address, as rizin loaded the image. hayabusa's own
  // parsers report string and symbol positions as file offsets, which are not
  // the addresses rizin's cross-reference database is keyed on. Both return
  // UINT64_MAX when no backed binary mapping contains the input; there is no
  // identity fallback because that would turn an unmapped file offset into a
  // plausible but unrelated analysis address.
  uint64_t offset_to_vaddr(uint64_t file_offset);
  uint64_t vaddr_to_offset(uint64_t vaddr);

  struct Str {
    uint64_t paddr = 0; // file offset, the key hayabusa's reports use
    uint64_t vaddr = 0; // what the cross-reference database is keyed on
    std::string text;
  };
  // rizin's own string table. Using it rather than translating hayabusa's
  // offsets keeps both halves of a cross-reference lookup in the same address
  // space, which p2v cannot guarantee on a dumped image with no section table.
  std::vector<Str> strings(size_t max_results = 100000,
                           size_t max_retained_bytes = 16U * 1024U * 1024U);

  // Byte pattern for a function with position-dependent operands wildcarded to
  // 0xFF in `mask`. Which operands those are comes from rizin's decoder rather
  // than from a fixed list of instruction encodings.
  bool signature(uint64_t addr, size_t length, std::vector<uint8_t> *bytes,
                 std::vector<bool> *mask);

  struct PointerRun {
    uint64_t vaddr = 0;
    size_t count = 0;
    // What the slots point at, module-relative, in table order.
    std::vector<uint64_t> targets;
  };
  // Runs of consecutive pointers that all land in executable memory. The
  // targets are defined as functions as a side effect: a helper reached only
  // through a dispatch table has nothing branching to it, so analysis has no
  // other way to find it. `truncated` is also set when module analysis failed,
  // because an empty/partial table result is then not authoritative.
  std::vector<PointerRun> function_tables(size_t min_run = 4,
                                          bool *truncated = nullptr);

  // 64-bit constants materialised inside a function by MOVZ/MOVK chains, in the
  // order they are completed. A single MOVZ only ever carries 16 bits, so an
  // AES key or a magic constant is always assembled from several instructions;
  // looking at MOVZ alone -- as the previous scanner did -- sees one quarter of
  // each value and misses the rest entirely.
  std::vector<uint64_t> materialised_constants(uint64_t func_addr,
                                               size_t max_insns = 256);

  // Run a function under rizin's IL virtual machine and report what each
  // general-purpose register ends up holding.
  //
  // This replaces guessing at MOVZ/MOVK chains from the disassembly text. The
  // VM executes the lifted semantics, so a value assembled by arithmetic,
  // rotated, loaded from a literal pool or built across a loop comes out the
  // same as one written by immediates -- none of which pattern matching sees.
  struct RegValue {
    std::string reg;
    uint64_t value = 0;
  };
  std::vector<RegValue> emulate(uint64_t func_addr, size_t max_steps = 512);

  struct FieldAccess {
    uint64_t offset = 0;
    uint32_t width = 0;
    bool written = false;
    uint32_t hits = 0;
  };
  // Offsets reached through x0 inside `func_addr`, i.e. `this` field accesses.
  std::vector<FieldAccess> field_accesses(uint64_t func_addr);

private:
  Image();
  struct Impl;
  std::unique_ptr<Impl> p;
};

// A worker-local Image for one module buffer. Repeated queries over the same
// bytes share one heavyweight analysis database.
Image *shared_image(const std::vector<uint8_t> &data, uint64_t base = 0);

// Drop the current worker's module session while the caller still holds the
// process-wide Rizin engine lock.
void release_shared_image();

// Decode a single instruction without opening an image -- used on bytes read
// straight out of a live process, where there is no ELF to analyse.
bool decode_one(const uint8_t *bytes, size_t len, uint64_t addr, Insn *out);

// Unpacks the embedded sleigh files to a scratch directory on first call and
// returns its path, or an empty string on failure. Callers do not normally need
// this; Image::decompile() handles it.
const std::string &sleigh_home();

} // namespace rzb
