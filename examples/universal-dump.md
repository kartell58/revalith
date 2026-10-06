# Example: triage with universal-dump

Using the orchestrator to answer "what is this, and where do I start?" before
committing to a deep investigation.

> Target data is **synthetic**. The commands are real and runnable.

## The question

> A build arrived from an unknown source. We need to know what it is, what it
> links against, and which two files deserve attention first.

This is exactly what `universal-dump.py` is for: it orients you, it does not
conclude.

## Before anything else — what can this machine do?

```sh
scripts/universal-dump.py /tmp --tools-only
```

```
group            status     detail
file             available   /usr/bin/file   (file-5.48)
readelf          available   /usr/bin/readelf   (GNU Binutils 2.44)
objdump          available   /usr/bin/objdump
re_suite         MISSING     tried: radare2, r2, rizin, rz-bin
decompiler       MISSING     tried: ghidra, analyzeHeadless, binaryninja
android          MISSING     tried: aapt, aapt2, apktool, jadx…
```

The `MISSING` rows change what you can do. With no disassembler, deep
analysis of native code is off the table for now — say that in the notes rather
than silently skipping it. The dump still identifies files, extracts strings
and indicators, and ranks targets.

## The run

```sh
scripts/universal-dump.py ./target.apk -o dump/
```

```
target    : ./target.apk
type      : android-apk
architectures: arm64-v8a, armeabi-v7a

FILES
  count        : 1483
  by format    : zip=1, elf=6, dex=2, png=311, json=44, text=892
  by category  : binary=6, text=1044, image=311, config=44, archive=1
  unidentified : 12
  high entropy : 2 (entropy >= 7.5 and size >= 4 KiB)

ANDROID
  kind           : apk
  members        : 1483
  ABIs           : arm64-v8a, armeabi-v7a
  DEX files      : classes.dex, classes2.dex
  native libs    : 6
  signing        : META-INF/EXAMPLE.RSA, META-INF/EXAMPLE.SF
  manifest:
    package        : com.example.game
    version_name   : 3.2.1
    version_code   : 321
    min_sdk        : 24 (Android 7.0)
    target_sdk     : 33 (Android 13)
    debuggable     : False
    permissions    : 14
    activities     : 3
```

**Observed.** Package name, version, SDK levels, ABI set, native library
count. `debuggable: False` is worth recording early: it means no debugger can
attach, which constrains every dynamic plan.

## What it could not determine, and why

This section matters as much as the findings:

```
  manifest:
    decoded=True
    network_security_config : @0x7f0a0120
  unidentified : 12
  coverage
    files string-scanned : 417
    files not scanned    : 1066
    note: images and already-parsed formats were not string-scanned
```

The network security config is a resource *reference* (`@0x7f0a0120`), not
content. The dump names it; decoding it needs the resource table, which is a
separate step. Recorded as unresolved rather than guessed.

1066 files were not string-scanned — mostly images. That is recorded in
`coverage` so nobody reads silence as "checked, nothing found".

## Unity detection

```
UNITY / IL2CPP
  detected: yes   il2cpp: yes   mono: no
    - member lib/arm64-v8a/libil2cpp.so: IL2CPP runtime library name
    - member assets/bin/Data/global-metadata.dat: the conventional IL2CPP
      metadata filename
  metadata global-metadata.dat
    size 14725184  standard_magic=yes
    status standard_header_present  confidence=high
    version_field 29
    version_guess  Unity 2022.x / 2023.x (metadata v29)
  dumper: attempted=yes tool=Cpp2IL ok=true
    produced 4 file(s)
```

The standard magic is present and the version field maps to a range. The
dumper ran, and the report records which tool, with its version and argv.

Two honest limits here. The version is a **range**, not a build number — a
30 MB metadata file does not tell you the patch release. And detection came
from *names*, so "IL2CPP" means "these conventional filenames are present",
not "the runtime has been confirmed to be IL2CPP".

## Network indicators, with provenance

```
NETWORK INDICATORS
  url: 47
  domain: 112
  ipv4: 6
  api_path: 89
```

```
# value  <- source  offset  confidence
https://api.example.com/v4/matchmaking  <- lib/arm64-v8a/libgame.so  @0x3a1c4  [medium]
https://telemetry.example.com/v1/e     <- lib/arm64-v8a/libgame.so  @offset:unknown  [low]
```

Every entry names the file it came from. The first has a real offset; the
second shows `offset:unknown` because it came from an extracted archive member
where the offset within the original file could not be established. That is
recorded as unknown rather than invented, because a wrong offset sends the
next person to the wrong place.

The `confidence: low` on the second is because the host came from a fragment.

## The ranking — the actual deliverable

```
NEXT STEPS (ranked from observed evidence only)
  1. [HIGH] lib/arm64-v8a/libgame.so  (binary)
      reason : ELF AArch64; symbols stripped; 18 JNI export(s); large
               (28.4 MB); libgame.so: conventional game-logic library name
      action : run scripts/elf-summary.py and scripts/strings-map.py --xrefs
  2. [HIGH] lib/arm64-v8a/libil2cpp.so  (binary)
      reason : ELF AArch64; symbols stripped; 412 JNI export(s); large
      action : the IL2CPP dumper already produced symbol output; start there
  3. [HIGH] assets/bin/Data/global-metadata.dat  (metadata)
      reason : metadata size 14725184; status=standard_header_present
      action : run the recorded dumper and compare against dump/unity/il2cpp
  4. [MEDIUM] unidentified files  (category)
      reason : 12 file(s) of unidentified format; largest: assets/obf.dat
               (1048576B)
      action : check magic at non-zero offsets and look for a length prefix
  5. [MEDIUM] indicators  (indicators)
      reason : 47 URL(s); 112 domain(s)
      action : review strings/urls.txt; each carries source and offset
```

Each entry names the observations behind it. Disagree with a rank and you can
see exactly which fact to argue with.

Note what is *not* claimed: nothing says "this is a Unity game that talks to
a C2 server". It says what was in the files and what deserves attention.

## Reading it as an analyst

The ranking says `libgame.so` first, for reasons that are checkable:

- 18 JNI exports — it is called from Java, so it is the bridge layer
- stripped, so names are unavailable and structure has to be recovered
- 28 MB, so it holds most of the logic
- `libgame.so` is a convention, which is a *weak* hint and is labelled as such

`libil2cpp.so` is also large, but the IL2CPP path is already partly solved:
the dumper ran and produced symbols. Starting there is cheaper than starting
with a fully stripped 28 MB library.

## Working the queue

```sh
scripts/elf-summary.py dump/extracted/lib/arm64-v8a/libgame.so \
    --hash --sections --symbols exports
```

```
binaries: libgame.so
  ELF AArch64 64-bit little-endian, position-independent, stripped
  entry 0x2a4c0   soname libgame.so
  needs: libc.so, liblog.so, libandroid.so, libil2cpp.so
  symbols 612 (dyn 612, static 0)   exports 18   imports 594
  JNI exports: 18
```

`libil2cpp.so` appears in `DT_NEEDED`. That confirms a link between the two
libraries — observed, and useful. It does not tell you which is more
semantically central, so do not conclude that.

## When the dump is not enough

`universal-dump.py` is an orchestrator. It deliberately does not:

- decompile (use Ghidra, radare2, Binary Ninja — see the tool references)
- dump IL2CPP (it delegates; see `references/unity` guidance below)
- decode Android binary resources
- run the target

When the ranking points at something those cover, that is the signal to switch
tools, and to record the switch.

## Comparing builds

```sh
scripts/universal-dump.py v1/game.apk -o dump-v1 -q
scripts/universal-dump.py v2/game.apk -o dump-v2 -q
scripts/dump-diff.py dump-v1/report.json dump-v2/report.json
```

See `examples/compare-binaries.md` for reading that output.

## Next investigation step

Write it down before stopping. For this dump:

- `libgame.so` JNI exports: map each back to its Java declaration to
  establish the bridge surface. That is the highest-information next step
  because it turns stripped native code into named Java methods.
- The 12 unidentified files: check `assets/obf.dat` first (largest). A length
  prefix or a pointer table at offset 0 is the usual explanation.