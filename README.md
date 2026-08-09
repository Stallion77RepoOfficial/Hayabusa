# Hayabusa

Hayabusa is a single-binary, root-side Android/AArch64 memory-analysis and
instrumentation tool. It snapshots live native and Dalvik artifacts, analyzes
them with statically linked Rizin and rz-ghidra, captures executable mappings
as they are created, and provides narrowly scoped live instrumentation
commands.

Use it only on software and devices you own or are authorized to assess.

## What it does

`dump` is the main analysis pipeline. It can:

- find one or more processes by package/cmdline prefix and optionally launch a
  command before capture;
- snapshot named ELF mappings and readable anonymous regions;
- rebuild dumped shared objects and emit symbol, import, PLT/GOT, string/xref,
  pointer-table, function, CFG, RTTI/vtable, structure-layout, entropy,
  signature, disassembly, and decompilation evidence;
- compare memory with the on-disk image and retain runtime-only content;
- validate standard DEX/ODEX containers, carve validated standard DEX payloads
  from VDEX, unpack APK/JAR multidex, and recover runtime anonymous DEX data;
- recover Dalvik classes, fields, methods, Modified UTF-8 strings, listings,
  and concrete-method decompilation with resolved constant-pool references;
- recognize CDEX safely and preserve its raw bytes without pretending that the
  standard-Dex parser supports compact code/shared-data semantics;
- detect exact forward-encryption AES-128/192/256 expanded key schedules in
  FIPS byte order, including unaligned writable runtime copies, and recover
  their input keys;
- structurally validate runtime PKCS#1 RSA private-key DER and canonical PEM
  candidates, reject malformed decoys, and recover cross-region
  `JNINativeMethod` registration entries;
- run opt-in, work-budgeted runtime string deobfuscation with explicit
  truncation evidence instead of silently consuming unbounded resources.

`unpack` starts a target under `PTRACE_SEIZE` before its first `exec`, follows
threads and fork/vfork/clone descendants, traces `mmap`/`mprotect`, and saves
regions at executable transitions. This is intended for native loaders and
self-unpacking code whose plaintext does not exist in the file.

The live commands are:

- `hook`: install a verified AArch64 logging trampoline on a named function,
  collect its first four arguments, then restore it on Ctrl+C/SIGTERM;
- `stub`: temporarily replace a named function with an immediate return and
  restore it on Ctrl+C/SIGTERM;
- `inject`: call the target linker to load an Android `.so`;
- `scan`: search mapped native/Dalvik files for text, `text:...`, or byte
  patterns such as `hex:de ad ?? ef`;
- `extract`: save a named function and bounded direct dependencies.

Temporary executable patches use a fail-closed transaction: original bytes
and detach state must both be verified. If rollback becomes ambiguous, the
patched target is killed instead of being allowed to continue with unknown
instructions. The tracer uses `PTRACE_SEIZE`/`PTRACE_INTERRUPT`, preserves
real signal-delivery and group-stop state, and supervises fork, vfork, clone,
and child-stop ordering while remote calls and live patches exist. A separate
address-space child is contained before it can escape with copied temporary
code; same-process thread clones remain traced.

## Build

The checked-in Makefile is currently configured for `arm64-v8a`, Android API
36, and NDK r30-beta2. Rizin/rz-ghidra source and build products are deliberately
ignored; follow [cross/README.md](cross/README.md) once to create the pinned
static dependency trees and embedded AArch64/Dalvik/JVM Sleigh data.

```sh
make check-deps
make -j2
```

Set `ANDROID_NDK=/path/to/ndk` (or `ANDROID_NDK_HOME`/
`ANDROID_NDK_ROOT`). No developer-machine SDK path or NDK version is embedded
in the build. Override `NDK_HOST_TAG`, `NDK`, or `CXX` only for a custom
toolchain layout.

`make check-deps` also verifies the required Rizin DEX address patch,
magic-versioned Dalvik language selection, constant-pool resolver, and embedded
Sleigh inputs. The resulting `hayabusa` has no companion plugin directory.

## Run

The target device must be AArch64, rooted, and permit ptrace and `/proc/<pid>/mem`
access. A typical deployment is:

```sh
adb push hayabusa /data/local/tmp/hayabusa
adb shell "su -c 'chmod 755 /data/local/tmp/hayabusa'"
adb shell "su -c '/data/local/tmp/hayabusa dump com.example.app --timeout 30'"
```

For a native fixture or executable, pass its cmdline/path prefix directly:

```sh
adb shell "su -c 'cd /data/local/tmp && ./hayabusa dump \
  /data/local/tmp/target --launch-cmd /data/local/tmp/run_target.sh \
  --only libtarget.so --snapshots 2 --interval 250 --rz-analysis full'"

adb shell "su -c 'cd /data/local/tmp && ./hayabusa unpack \
  /data/local/tmp/target --launch-cmd /data/local/tmp/run_target.sh \
  --timeout 15'"
```

`--launch` is the safer direct-exec path: Hayabusa opens the non-symlink target
once, validates that descriptor, clears supplementary groups and capability
inheritance, enables `no_new_privs`, drops from root to the file owner (or
Android shell UID 2000 for a root-owned executable), and executes that same
descriptor with a fixed minimal Android environment and `/dev/null` standard
streams; the root analyzer's tokens, preload controls, home directory, open
descriptors, and other environment values are not inherited. `--launch-cmd`
is an explicit root shell and therefore retains the caller's standard streams
as part of that trusted shell contract. Both launch paths are owned by a
dedicated subreaper supervisor:
closing its private control pipe on normal teardown, SIGINT/SIGTERM, or analyzer
death makes it pidfd-kill and reap adopted descendants, including ordinary
children that leave the original process group with `setsid()`. Completion is
withheld if that teardown cannot be proved. `--launch-cmd` intentionally runs
the exact user-supplied command through a root shell; use it only when that
root-code boundary is wanted. It is not a sandbox against deliberately hostile
root code, which has the same authority to attack Hayabusa or its supervisor.

Run `hayabusa` without enough arguments to print the complete command-line
usage. Analysis outputs are written under
`/data/local/hayabusa/<target-leaf>_analysis/`; unpack outputs go to
`/data/local/hayabusa/<target-leaf>_unpack/`. The root-owned mode-0700 anchor
keeps Android's shell user from renaming or substituting the authoritative
result tree. Each command pins an owner-verified mode-0700 run directory,
rejects unsafe existing entries, safely replaces the previous contents of that
same target leaf, writes private mode-0600 files through its descriptor, and
publishes stable `/data/local/hayabusa/...` paths in reports. Export private
results through a privileged channel (for example `su -c tar`); the tool does
not relax the authoritative tree merely to make an unprivileged `adb pull`
work.

Set `HAYABUSA_OUTPUT_ROOT` to another absolute directory when the default
location is unsuitable. Its parent must already be owned by the invoking UID
and not be group/other-writable; Hayabusa creates and validates the final
private anchor itself. Embedded module images are passed to Rizin through
anonymous `memfd` descriptors, so analysis leaves no per-module temp files.

The most important `dump` controls are:

- `--only a.so,b.so`: capture only matching mapped module names/SONAMEs;
- `--rz-analysis off|basic|full`: parse only, run function analysis, or run the
  full xref/type pass;
- `--analysis-timeout N`: one shared per-module budget for the primary Rizin
  pass and every dependent RTTI/xref/table/emulation/decompilation query;
  `0` disables this deadline;
- `--memory-limit N`: aggregate readable anonymous/writable snapshot MiB;
  `0` removes the policy limit (device storage and addressability still apply);
- `--image-limit N`: maximum reconstructed module/container MiB; `0` removes
  the policy limit;
- `--string-limit N`, `--limit N`, `--listing N`: retained string bytes,
  records printed per report category, and functions/methods decompiled;
- `--deobf --deobf-timeout N --deobf-probes N`: enable and budget speculative
  string deobfuscation;
- `--relink --relink-limit N --rd N`: enable dependency relinking and set its
  aggregate MiB and recursion depth;
- `--require-complete`: return failure if any requested module is absent or a
  capture/analysis budget makes the result partial.

`extract` accepts `--d N` for dependency depth and `--size-limit N` for the
aggregate extracted MiB. `scan` streams every eligible mapping in overlapping
chunks, so large OAT/DEX/SO mappings are not silently skipped because of their
size.

`raw/name.so` is the exact file-layout view reconstructed from stopped process
memory. For an uncompressed ELF stored inside an APK, `name.so.disk` is read
from the exact backing APK inode/entry and includes section metadata that is
not mapped into memory. `name_fixed.so` combines the runtime image with the
complete file layout and normalizes loader relocations. A raw image can
therefore be intentionally section-truncated while `.disk` and `_fixed.so`
must pass an ELF section/dynamic-symbol reader.

## Verification

This checkout does not currently bundle the old `testbed/tiers` fixture tree,
so do not treat nonexistent tier commands as evidence. The reproducible checks
available in this repository are dependency validation, a strict compile, and
device-side artifact validation:

```sh
make check-deps
make -j2

# After a device dump, validate every rebuilt ELF with the NDK toolchain:
llvm-readelf -h -S --dyn-syms path/to/module_fixed.so
```

For a real application, also verify that the target PID survives capture, every
requested mapped module has raw/disk/fixed artifacts, every `_fixed.so` passes
the command above without diagnostics, missing `--only` names are explicitly
reported, and the final status says either `COMPLETE` or `PARTIAL RESULT` rather
than inferring success from non-empty files.

## Honest limits

- This build is Android/AArch64-specific. It is not an iOS, x86, kernel, or
  remote-agent framework.
- Root does not override every vendor SELinux/ptrace policy; a production
  device can still deny required access.
- AES recovery currently recognizes forward-encryption schedules in FIPS byte
  order; it does not claim reversed, decryption-round-key, or vendor-specific
  layouts. RSA DER/PEM validation is strict structural validation, not a proof
  of mathematical relations such as `n = p*q`. Hayabusa does not magically
  decrypt proprietary formats, hardware-backed keys, white-box crypto, or
  secrets that are never simultaneously readable.
- Standard DEX is parsed and decompiled. CDEX is intentionally raw-only until a
  real compact-Dex code/shared-data implementation exists.
- Static analysis and decompilation remain bounded heuristics. Virtualization,
  control-flow flattening, opaque predicates, JIT-only code, anti-debug logic,
  and very short plaintext lifetimes can require target-specific work.
- A whole-process anonymous snapshot can be several GiB even when the selected
  libraries are small. Reaching `--memory-limit` does not invalidate the exact
  selected-module ELF capture, but it does make the overall process snapshot
  partial. Raise the limit only after checking free device storage, or use
  `--require-complete` when partial results are unacceptable.
- `hook`, `stub`, and `extract` resolve named functions in mapped `.so` files;
  stripped private routines first need an address-aware workflow or analysis
  result rather than a nonexistent symbol name.
- Direct launch removes root UID/GID and capability inheritance, but it is not
  a full Android app sandbox or a new SELinux domain. Treat analyzed code as
  hostile and prefer a disposable rooted test device.
- The launch supervisor provides lifecycle containment, not kernel isolation.
  In particular, a deliberately hostile root `--launch-cmd` payload remains
  outside its trust guarantee; use `--launch` for untrusted executables.

Successful compilation and one device run are regression evidence, not proof
that every Android binary or adversarial schedule is handled.
