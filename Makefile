ANDROID_NDK ?= $(if $(ANDROID_NDK_HOME),$(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT))
HOST_OS := $(shell uname -s)
NDK_HOST_TAG ?= $(if $(filter Darwin,$(HOST_OS)),darwin-x86_64,linux-x86_64)
NDK ?= $(ANDROID_NDK)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin
CXX = $(NDK)/aarch64-linux-android36-clang++
STRIP = $(NDK)/llvm-strip
TARGET = hayabusa
.DEFAULT_GOAL := $(TARGET)
SOURCES = main.cpp memory.cpp tracer.cpp rizin_bridge.cpp rizin_elf.cpp sleigh_data.cpp
HEADERS = memory.h tracer.h rizin_bridge.h sleigh_data.h

# Everything analysis-related is statically linked in: rizin for parsing and
# disassembly, rz-ghidra for decompilation. The result depends only on
# libc/libm/libdl, so it is a single file to push to a device -- no plugin
# directory, no .so to keep in step with the binary.
# See cross/README.md for how the two prefixes below are produced.
RZ_PREFIX  = third_party/prefix-android
RZG_BUILD  = third_party/rz-ghidra/build-android
RZG_ARCH_MAP = third_party/rz-ghidra/src/ArchMap.cpp
RZG_ARCHITECTURE = third_party/rz-ghidra/src/RizinArchitecture.cpp

RZ_INCLUDES = -I$(RZ_PREFIX)/include/librz -I$(RZ_PREFIX)/include/librz/sdb

# Sleigh's AArch64 language definition, compiled by the host-side sleighc and
# embedded so the decompiler has no external data directory to find.
SLEIGH_SRC = $(RZG_BUILD)/../build-host/ghidra/sleigh
SLEIGH_DIR = third_party/sleigh-aarch64
SLEIGH_STAMP = $(SLEIGH_DIR)/.prepared
SLEIGH_PROCESSORS = third_party/rz-ghidra/ghidra/ghidra/Ghidra/Processors
SLEIGH_AARCH64_LANG = $(SLEIGH_PROCESSORS)/AARCH64/data/languages
SLEIGH_DALVIK_LANG = $(SLEIGH_PROCESSORS)/Dalvik/data/languages
SLEIGH_JVM_LANG = $(SLEIGH_PROCESSORS)/JVM/data/languages
SLEIGH_SLA_INPUTS = $(SLEIGH_SRC)/AARCH64.sla \
                    $(wildcard $(SLEIGH_SRC)/Dalvik_*.sla) \
                    $(SLEIGH_SRC)/JVM.sla
SLEIGH_SPEC_INPUTS = cross/AARCH64-Android.ldefs \
                     $(SLEIGH_AARCH64_LANG)/AARCH64.cspec \
                     $(SLEIGH_AARCH64_LANG)/AARCH64.pspec \
                     $(SLEIGH_DALVIK_LANG)/Dalvik.ldefs \
                     $(SLEIGH_DALVIK_LANG)/Dalvik_Base.cspec \
                     $(SLEIGH_DALVIK_LANG)/Dalvik_Base.pspec \
                     $(SLEIGH_JVM_LANG)/JVM.cspec \
                     $(SLEIGH_JVM_LANG)/JVM.ldefs \
                     $(SLEIGH_JVM_LANG)/JVM.pspec

# core_ghidra is the decompiler. asm_ghidra and analysis_ghidra -- rz-ghidra's
# sleigh-based disassembler -- are deliberately not linked: rizin's own AArch64
# disassembler is already complete, and those two each compile their own copy of
# SleighAsm.cpp, which collides once the archives are pulled in whole instead of
# being loaded as separate shared objects.
#
# core_ghidra must be whole-archived. It registers its C output format through a
# static initialiser in RizinPrintC.cpp, and nothing else references that object,
# so ordinary archive semantics drop it and every decompile then fails with
# "Unknown print language: rizin-c-language".
RZG_WHOLE = $(RZG_BUILD)/core_ghidra.a

RZG_LIBS = \
  $(RZG_BUILD)/ghidra/libghidra_libdecomp.a \
  $(RZG_BUILD)/ghidra/libghidra_decompiler.a \
  $(RZG_BUILD)/ghidra/libghidra_sleigh.a \
  $(RZG_BUILD)/ghidra/libghidra_base.a \
  $(RZG_BUILD)/third-party/libpugixml.a \
  $(RZG_BUILD)/_deps/zlib-build/libz.a

RZ_LIBS = $(wildcard $(RZ_PREFIX)/lib/*.a)

CXXFLAGS = -O3 -std=c++23 -static-libstdc++ -ffunction-sections \
           -fdata-sections $(RZ_INCLUDES)
# rizin's modules and the ghidra archives reference each other both ways, so the
# whole set goes in one --start-group rather than being ordered by hand.
LDFLAGS = -Wl,--whole-archive $(RZG_WHOLE) -Wl,--no-whole-archive \
          -Wl,--start-group $(RZG_LIBS) $(RZ_LIBS) -Wl,--end-group \
          -Wl,--gc-sections -ldl -lm

sleigh_data.cpp: cross/embed_sleigh.py $(SLEIGH_STAMP)
	python3 cross/embed_sleigh.py $(SLEIGH_DIR) $@

$(TARGET): $(SOURCES) $(HEADERS) $(RZ_LIBS) $(RZG_LIBS) $(RZG_WHOLE)
	$(CXX) $(CXXFLAGS) $(SOURCES) $(LDFLAGS) -o $(TARGET)
	$(STRIP) $(TARGET)

# Sleigh language definitions the decompiler needs.
#
# AARCH64 for native code, and every Dalvik variant plus JVM for the Java side:
# Ghidra ships one Dalvik spec per Android release because the bytecode changes
# between them, and picking the wrong one decompiles to nonsense. All of Dalvik
# plus JVM is about 300 KB, against 483 KB for AARCH64 alone, so carrying the
# whole set is cheaper than getting the version detection wrong.
#
# AARCH64BE and AARCH64_AppleSilicon are left out -- neither describes a target
# hayabusa supports.
sleigh-data: $(SLEIGH_STAMP)

$(SLEIGH_STAMP): Makefile $(SLEIGH_SLA_INPUTS) $(SLEIGH_SPEC_INPUTS)
	mkdir -p $(SLEIGH_DIR)
	find $(SLEIGH_DIR) -mindepth 1 -maxdepth 1 -type f -delete
	cp $(SLEIGH_SRC)/AARCH64.sla $(SLEIGH_DIR)/
	cp $(SLEIGH_SRC)/Dalvik_*.sla $(SLEIGH_SRC)/JVM.sla $(SLEIGH_DIR)/
	cp cross/AARCH64-Android.ldefs $(SLEIGH_DIR)/AARCH64.ldefs
	cp $(SLEIGH_AARCH64_LANG)/AARCH64.cspec \
	  $(SLEIGH_AARCH64_LANG)/AARCH64.pspec $(SLEIGH_DIR)/
	cp $(SLEIGH_DALVIK_LANG)/Dalvik.ldefs \
	  $(SLEIGH_DALVIK_LANG)/Dalvik_Base.cspec \
	  $(SLEIGH_DALVIK_LANG)/Dalvik_Base.pspec $(SLEIGH_DIR)/
	cp $(SLEIGH_JVM_LANG)/JVM.cspec $(SLEIGH_JVM_LANG)/JVM.ldefs \
	  $(SLEIGH_JVM_LANG)/JVM.pspec $(SLEIGH_DIR)/
	@du -sh $(SLEIGH_DIR)
	@touch $@

check-deps:
	@test -x $(CXX) || \
	  { echo "missing Android compiler $(CXX) -- set ANDROID_NDK, NDK, or CXX"; exit 1; }
	@test -f $(RZ_PREFIX)/lib/librz_core.a || \
	  { echo "missing $(RZ_PREFIX)/lib/librz_core.a -- see cross/README.md"; exit 1; }
	@test -f $(RZG_WHOLE) || \
	  { echo "missing $(RZG_BUILD)/core_ghidra.a -- see cross/README.md"; exit 1; }
	@grep -q '^#define RZ_DEX_VIRT_ADDRESS  *0x20000000$$' \
	  third_party/rizin/librz/bin/format/dex/dex.h || \
	  { echo "rizin DEX address patch is missing -- see cross/README.md"; exit 1; }
	@grep -qF -- 'static std::string DalvikFlavorFromMagic' $(RZG_ARCH_MAP) && \
	  grep -qF -- 'rz_io_read_at_mapped(core->io, 0, magic, sizeof(magic))' $(RZG_ARCH_MAP) && \
	  grep -qF -- 'return DalvikFlavorFromMagic(core);' $(RZG_ARCH_MAP) || \
	  { echo "rz-ghidra Dalvik magic-version selection patch is missing -- reapply cross/rz-ghidra-dalvik.patch"; exit 1; }
	@for mapping in \
	  'case 35: return "Marshmallow";' \
	  'case 37: return "DEX_Nougat";' \
	  'case 38: return "DEX_Oreo";' \
	  'case 39: return "DEX_Pie";' \
	  'case 40: return "DEX_Android10";' \
	  'case 41: return "DEX_Android13";'; do \
	    grep -qF -- "$$mapping" $(RZG_ARCH_MAP) || \
	      { echo "missing Dalvik magic mapping: $$mapping -- reapply cross/rz-ghidra-dalvik.patch"; exit 1; }; \
	  done
	@grep -qF -- 'class RizinDalvikConstantPool final : public ConstantPool' $(RZG_ARCHITECTURE) && \
	  grep -qF -- 'size_t decodeDexMutf8' $(RZG_ARCHITECTURE) && \
	  grep -qF -- 'RecordDescription resolveField' $(RZG_ARCHITECTURE) && \
	  grep -qF -- 'RecordDescription resolveMethod' $(RZG_ARCHITECTURE) && \
	  grep -qF -- 'vector<uint1> resolveString' $(RZG_ARCHITECTURE) && \
	  grep -qF -- 'bin->get_name(bin->bin, kind, checkedIndex(index))' $(RZG_ARCHITECTURE) && \
	  grep -qF -- "bin->get_offset(bin->bin, 's', checkedIndex(index))" $(RZG_ARCHITECTURE) && \
	  grep -qF -- 'cpool = new RizinDalvikConstantPool(this);' $(RZG_ARCHITECTURE) || \
	  { echo "rz-ghidra Dalvik constant-pool resolver patch is missing -- reapply cross/rz-ghidra-dalvik.patch"; exit 1; }
	@for definition in \
	  'kDexCpoolMethod = 0;' \
	  'kDexCpoolField = 1;' \
	  'kDexCpoolStaticField = 2;' \
	  'kDexCpoolStaticMethod = 3;' \
	  'kDexCpoolString = 4;' \
	  'kDexCpoolClass = 5;' \
	  'kDexCpoolArrayLength = 6;' \
	  'kDexCpoolSuper = 7;' \
	  'kDexCpoolInstanceOf = 8;'; do \
	    grep -qF -- "constexpr uintb $$definition" $(RZG_ARCHITECTURE) || \
	      { echo "missing Dalvik constant-pool definition: $$definition -- reapply cross/rz-ghidra-dalvik.patch"; exit 1; }; \
	  done
	@for kind in Method Field StaticField StaticMethod String Class ArrayLength Super InstanceOf; do \
	    grep -qF -- "case kDexCpool$$kind:" $(RZG_ARCHITECTURE) || \
	      { echo "missing Dalvik constant-pool kind: kDexCpool$$kind -- reapply cross/rz-ghidra-dalvik.patch"; exit 1; }; \
	  done
	@set -- $(SLEIGH_SRC)/Dalvik_*.sla; test -f "$$1" || \
	  { echo "Dalvik Sleigh specifications are missing -- see cross/README.md"; exit 1; }
	@test -f $(SLEIGH_SRC)/JVM.sla || \
	  { echo "JVM Sleigh specification is missing -- see cross/README.md"; exit 1; }
	@echo "rizin and rz-ghidra static libraries present"

clean:
	rm -f $(TARGET) sleigh_data.cpp $(SLEIGH_STAMP)

.PHONY: clean sleigh-data check-deps
