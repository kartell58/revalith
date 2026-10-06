# Android

Android is a bundle of formats and runtimes. Treat it as one supported
environment among several, not as the primary target.

## Layers

```
APK / AAB            zip container
├── AndroidManifest.xml   binary XML: permissions, components
├── classes.dex           Dalvik bytecode
├── lib/<abi>/*.so        native ELF libraries
└── res/, assets/
```

Investigate the layer that actually holds the behaviour. Native logic lives
in `.so` files, which are ELF and use the tooling in `elf.md` and `arm64.md`.

## DEX

Dalvik bytecode, not machine code. Disassembling DEX as ARM instructions
produces nonsense.

```sh
file classes.dex
unzip -o -d out/ app.apk          # extract
```

Tools: `jadx` (decompiles to Java), `apktool` (decodes resources and
manifest), `baksmali`/`smali` (DEX disassembly), `dexdump` (from the SDK).

For native interop, use DEX only to find the bridge: which class declares
`native`, and which library is loaded.

## Native loading

- `System.loadLibrary("foo")` loads `libfoo.so`
- `System.load("/path/to/lib.so")` loads an absolute path
- Both trigger `JNI_OnLoad` if present
- `dlopen`/`dlsym` load code at runtime from native code or NDK code

`JNI_OnLoad` is the first native code that runs and is a good entry point:
it registers methods, so the function names it references are the native
implementations of Java methods. Mapping JNI names back to Java classes is
often the fastest route from an API to its implementation.

The JNI naming convention is `Java_<package>_<Class>_<method>`. When symbols
are stripped, this convention still helps you guess, and registration in
`JNI_OnLoad` confirms it.

## Bionic, not glibc

Android uses **bionic**, a distinct libc. Do not assume Linux desktop
behaviour:

- the dynamic linker is `/system/bin/linker` (32-bit) or `/system/bin/linker64`
- library search paths and the default namespace differ
- available symbols differ; a function present in glibc may be absent here
- some glibc internals have no equivalent

Analysing an Android `.so` against glibc headers produces wrong conclusions
about which functions exist. Check the actual `DT_NEEDED` and dynsym.

## APK layout

```
/data/app/<package>-<hash>/base.apk       the installed APK
/data/data/<package>/                      app private data (debuggable only)
/data/user/<user>/<package>/              per-user data
```

Since Android 9 the app's private directory is inaccessible to other apps and
to adb without root or a debuggable build. Many techniques that assume readable
app data simply do not work.

`/proc/<pid>/maps` is the reliable way to see which `.so` files a running
process actually loaded, and their load addresses. Readable for your own
processes and for debuggable apps with `run-as`; restricted otherwise.

## Debugging a device

```sh
adb shell                       # device shell
adb shell run-as <package> ls   # private dir, debuggable apps only
adb push <binary> /data/local/tmp/
adb forward tcp:8000 tcp:8000   # for gdbserver / frida-server
```

Attaching a debugger requires a debuggable build (`android:debuggable="true"`)
or root. Release builds are not debuggable, and without root there is no
supported way to attach. Say so instead of promising a trace.

`run-as` works only for debuggable apps and is the most common way to reach
app-private data without root.

## Multi-ABI

An APK ships one `.so` per ABI:

```
lib/arm64-v8a/libfoo.so
lib/armeabi-v7a/libfoo.so
lib/x86_64/libfoo.so
```

Choose one and say which. Differences between ABIs are usually build
configuration, not logic — but they are also a common source of
"the behaviour differs between devices". If a finding holds only on one ABI,
that is worth stating explicitly.

## ART

The runtime. `libart.so` implements it. Relevant behaviours:

- **AOT/JIT**: code may be compiled at runtime, so the on-disk `.so` is not
  always what executes.
- **dex2oat** produces `.odex`/`.vdex` with ahead-of-time compiled native code
  that may differ from the `.so`.
- **Interpreted then compiled**: a function may run as Dalvik bytecode before
  being JIT-compiled, so breakpoints set on native addresses can miss the
  first execution.

If native breakpoints behave inconsistently, this is usually the reason.

## Native crash reports

`tombstones` under `/data/tombstones/` and logcat both carry native backtraces
with load addresses. A tombstone is an excellent source of call stacks without
any debugger:

```sh
adb shell ls /data/tombstones/
adb logcat -b crash
```

## Tools

`apktool`, `jadx`, `baksmali`, `dexdump`, `aapt`/`aapt2`, `readelf`,
`objdump`, `llvm-objdump`, plus the general reverse engineering suites. None of
them are guaranteed present; probe first (`tooling.md`).

## Common missteps

- Treating DEX as native code.
- Assuming glibc semantics for a bionic binary.
- Expecting `/data/data` to be readable without root or a debuggable build.
- Ignoring the ABI and reporting a 32-bit finding as if it covered 64-bit.
- Expecting static addresses to survive loading; use the load base from
  `/proc/<pid>/maps`.