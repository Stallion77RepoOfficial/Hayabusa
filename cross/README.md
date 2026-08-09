# Building the rizin / rz-ghidra static libraries

hayabusa links rizin and the Ghidra decompiler directly into its binary. The
result depends only on `libc`, `libm` and `libdl`, so deploying it is one `adb
push` — there is no plugin directory to keep in sync and nothing to `dlopen` at
runtime.

Everything below lands in `third_party/`, which is git-ignored. Pinned
revisions: **rizin `v0.9.1`**, **rz-ghidra `a34410f`**.

## Prerequisites

Android NDK (r30-beta2 is the validated revision), plus `meson`, `ninja` and
`cmake` on the host.

The Makefile contains no host SDK path. Set `ANDROID_NDK=/path/to/ndk` and,
when needed, `NDK_HOST_TAG` (for example `linux-x86_64`) instead of editing the
file.

Export the same toolchain for Meson before the commands below:

```bash
export ANDROID_NDK=/path/to/android-ndk
export NDK_HOST_TAG=darwin-x86_64   # linux-x86_64 on Linux
export PATH="$ANDROID_NDK/toolchains/llvm/prebuilt/$NDK_HOST_TAG/bin:$PATH"
```

## 1. Fetch sources

```bash
mkdir -p third_party
git clone --depth 1 --branch v0.9.1 --recurse-submodules --shallow-submodules \
  https://github.com/rizinorg/rizin.git third_party/rizin
git clone https://github.com/rizinorg/rz-ghidra.git third_party/rz-ghidra
git -C third_party/rz-ghidra checkout a34410f77e6b17d317dfa4ca4a58db3576b5e608
git -C third_party/rz-ghidra submodule update --init --recursive --depth 1
git -C third_party/rizin apply ../../cross/rizin-dex-32bit.patch
git -C third_party/rz-ghidra apply ../../cross/rz-ghidra-static.patch
git -C third_party/rz-ghidra apply ../../cross/rz-ghidra-dalvik.patch
```

The small rizin patch keeps its synthetic DEX data and relocation windows
inside Dalvik Sleigh's 32-bit address space.  Without it, native DEX parsing and
disassembly work but every rz-ghidra method decompilation overflows at 4 GiB.

`rz-ghidra-static.patch` does two things upstream has no switch for:

* adds `RZ_GHIDRA_STATIC`, which builds the three rizin plugins as static
  archives and defines `CORELIB`. The sources already support this — each
  plugin guards its `RzLibStruct rizin_plugin` loader shim with `#ifndef
  CORELIB` and exports the bare plugin struct otherwise — so nothing else has
  to change;
* adds `SLASPEC_PROCESSORS`, which restricts the sleigh build to named
  processor directories. Upstream compiles all ~40 Ghidra architectures.

## 2. rizin, cross-compiled and static

```bash
(
  cd third_party/rizin
  meson setup build-android \
    --cross-file ../../cross/android-aarch64.ini \
    --prefix="$PWD/../prefix-android" \
    --default-library=static -Dstatic_runtime=true \
    -Denable_tests=false -Denable_rz_test=false -Dinstall_sigdb=false \
    -Duse_sys_capstone=disabled
  ninja -C build-android
  ninja -C build-android install
)
```

## 3. rz-ghidra, stage A: sleigh specs on the host

`sleighc` compiles `.slaspec` sources into the `.sla` files the decompiler
loads. It has to *run*, so it is built for the host, not for Android. AArch64,
Dalvik and JVM are compiled because Hayabusa analyzes both native and managed
containers.

```bash
(
  cd third_party/rz-ghidra
  cmake -S . -B build-host -G Ninja \
    -DRizin_DIR="$PWD/../../cross" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SLASPECS=ON -DSLASPEC_PROCESSORS='AARCH64;Dalvik;JVM' \
    -DBUILD_SLEIGH_PLUGIN=OFF
  ninja -C build-host sla
)
```

`CMAKE_POLICY_VERSION_MINIMUM` is needed because rz-ghidra still declares
`cmake_minimum_required(VERSION 3.0...3.5)` and CMake 4 refuses that outright.

## 4. rz-ghidra, stage B: plugins for Android

`BUILD_SLASPECS=OFF` here — the specs already exist from stage A and sleighc
cannot run on the build host as an Android binary.

```bash
(
  cd third_party/rz-ghidra
  cmake -S . -B build-android -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-36 \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Release \
    -DRizin_DIR="$PWD/../../cross" \
    -DRZ_GHIDRA_STATIC=ON -DBUILD_SLASPECS=OFF \
    -DBUILD_SLEIGH_PLUGIN=ON -DUSE_SYSTEM_ZLIB=OFF
  ninja -C build-android core_ghidra asm_ghidra analysis_ghidra
)
```

## 5. Sleigh data and the binary

```bash
make sleigh-data   # collects AARCH64.sla + cspec/ldefs/pspec (~570 KB)
make check-deps
make
```

## Why `cross/RizinConfig.cmake` exists

rizin's `librz/meson.build` wraps its whole CMake-config generation in `if not
is_static_libs_only`, so a `--default-library=static` build installs pkg-config
files and nothing else. rz-ghidra's `find_package(Rizin REQUIRED Core)` would
fail. Reimplementing rizin's real config — 25 modules, each with its own
dependency graph — is unnecessary: rz-ghidra reads exactly `Rizin::Core` and
`Rizin_PLUGINDIR` from it, and since every rz-ghidra target is static, CMake
never runs a link step for them. Only the include directories matter. The final
link is hayabusa's own `Makefile`, which names the archives explicitly.

## Registering the plugins

With `CORELIB` defined there is no loader shim, so the plugin structs are
ordinary symbols and must be registered by hand once per `RzCore`:

```c
extern "C" {
extern RzCorePlugin rz_core_plugin_ghidra;
extern RzAsmPlugin rz_asm_plugin_ghidra;
extern RzAnalysisPlugin rz_analysis_plugin_ghidra;
}

rz_core_plugin_add(core, &rz_core_plugin_ghidra);
rz_asm_plugin_add(core->rasm, &rz_asm_plugin_ghidra);
rz_analysis_plugin_add(core->analysis, &rz_analysis_plugin_ghidra);
```

Then point the decompiler at the embedded sleigh data before first use:

```c
rz_config_set(core->config, "ghidra.sleighhome", extracted_dir);
```
