# Minimal stand-in for the RizinConfig.cmake that rizin does NOT install.
#
# rizin's librz/meson.build guards the whole cmake-config generation with
# `if not is_static_libs_only`, so a --default-library=static build ships only
# pkg-config files. rz-ghidra's CMakeLists does `find_package(Rizin REQUIRED
# Core)` and would fail outright.
#
# Reimplementing rizin's real config (25 modules, each with its own dependency
# graph) is not necessary here: rz-ghidra touches exactly two things from it,
# `Rizin::Core` and `Rizin_PLUGINDIR`. And because every rz-ghidra target is
# built as a STATIC library, CMake never runs a link step for them -- only the
# include directories actually matter. hayabusa's own Makefile does the final
# link and names the archives explicitly, in dependency order.

set(Rizin_VERSION 0.9.1)

get_filename_component(RIZIN_ANDROID_PREFIX
    "${CMAKE_CURRENT_LIST_DIR}/../third_party/prefix-android" ABSOLUTE)

if(NOT EXISTS "${RIZIN_ANDROID_PREFIX}/include/librz/rz_core.h")
  message(FATAL_ERROR
    "rizin headers not found under ${RIZIN_ANDROID_PREFIX}. "
    "Build and install rizin first (see cross/README.md).")
endif()

if(NOT TARGET Rizin::Core)
  add_library(Rizin::Core INTERFACE IMPORTED)
  set_target_properties(Rizin::Core PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES
      "${RIZIN_ANDROID_PREFIX}/include/librz;${RIZIN_ANDROID_PREFIX}/include/librz/sdb")
endif()

# Unused -- nothing is installed as a loadable plugin -- but rz-ghidra reads it.
set(Rizin_PLUGINDIR "${RIZIN_ANDROID_PREFIX}/lib/rizin/plugins")

set(Rizin_FOUND TRUE)
