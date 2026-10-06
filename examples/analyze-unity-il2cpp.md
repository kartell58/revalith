# Example: Unity / IL2CPP investigation

Detecting Unity, establishing what the IL2CPP metadata actually is, and
deciding what to do when it does not parse.

> Target data is **synthetic**. Commands are real and runnable.

## The question

> We have an Android app with a very large `libmain.so` and no readable
> symbols. Is it Unity? Is it IL2CPP? Can we recover names?

## 1. Detect

```sh
scripts/universal-dump.py ./game.apk -o dump/
```

```
UNITY / IL2CPP
  detected: yes   il2cpp: yes   mono: no
    - member lib/arm64-v8a/libil2cpp.so: IL2CPP runtime library name
    - member assets/bin/Data/global-metadata.dat: the conventional IL2CPP
      metadata filename
    - member assets/bin/Data/boot.config: Unity's conventional data
      directory layout
  metadata global-metadata.dat
    size 14725184  standard_magic=yes
    status standard_header_present  confidence=high
    version_field 29
    version_guess  Unity 2022.x / 2023.x (metadata v29)
    note: header field at 0x08 = 0x11c40, within the file
```

Four indicators, four independent sources. The metadata magic is a *content*
check, not a filename check, which is what makes the `il2cpp: yes` claim
defensible.

**Two things this does not say.** The version is a range, not a build: many
Unity patch releases share metadata version 29. And the ABI was not determined
from the metadata — `lib/arm64-v8a` is the path.

## 2. Understand what the numbers mean

```
version_field 29  ->  Unity 2022.x / 2023.x
```

That mapping came from the metadata version, which correlates with Unity
releases. It is `confidence: low` for the exact patch and is labelled as such
in the report. The 14 MB metadata file does not record the Unity version
directly; the version strings live in `globalgamemanagers` or `boot.config`.

For the exact build:

```sh
strings dump/extracted/assets/bin/Data/globalgamemanagers | grep -oE '2[0-9]{3}\.[0-9]+\.[0-9]+[abfp][0-9]+' | head
```

```
2022.3.42f1
```

A version string in a data file. Useful, still `confidence: medium` — confirm it
against the app's own `versionName` before treating it as established.

## 3. Delegate, do not reimplement

The orchestrator does not dump IL2CPP. It records the attempt:

```
  dumper: attempted=yes tool=Cpp2IL ok=true
    argv: Cpp2IL <lib>/libil2cpp.so <metadata> dump/unity/il2cpp
    produced 4 file(s)
```

`report.json` carries the full record: tool name, version, argv, return code,
stderr tail, and every produced file with its size. If the dump is ever
questioned, the evidence for how it was produced is in the report.

Find available dumpers yourself:

```sh
command -v Il2CppDumper Cpp2IL Il2CppInspector il2cpp_dumper
```

None of these are Python and none are bundled. Install one if name recovery
matters; otherwise work from the metadata directly.

## 4. When the metadata does not parse

This is the case worth understanding, because the wrong response is to declare
the metadata broken.

```
  metadata global-metadata.dat
    size 8294400  standard_magic=no
    status obfuscated_or_custom  confidence=medium
    observed_magic: 4a5f0000...
    note: the standard IL2CPP magic af1bb1fa was not found at offset 0
          (found 4a5f0000 instead)
    note: header field at 0x08 = 4194304, outside the file: consistent with
          a non-standard layout
  dumper: attempted=no tool=unknown ok=false
    error: non-standard metadata header; delegation skipped
    note: the standard IL2CPP metadata magic is absent. A dumper is very
          unlikely to parse this file, so none was run. Treat the metadata
          as obfuscated or in a custom format until proven otherwise.
```

Four observations, and the conclusions they do **not** license:

- The standard magic is absent → the header is not stock.
- The observed magic is unknown → we do not know what it is.
- A header field points outside the file → the layout is not the standard one.
- No dumper ran → we did not test whether a dumper would work; we decided it
  would not, and said why.

**Not established:** that the metadata is encrypted. That it is obfuscated is
a hypothesis at `confidence: medium`. It could be a custom format, a modified
loader, or a re-packed build. Any of those is consistent with what was seen.

## 5. Test the "encrypted" hypothesis properly

```markdown
### The IL2CPP metadata is encrypted

Status:     open
Confidence: low

Evidence:
  - standard magic absent at offset 0 (found 4a5f0000)
  - a 32-bit header field points past the end of the file
  - entropy of the first 4 KiB: 7.9 bits/byte

Alternative explanations not yet ruled out:
  - a custom metadata layout (loader was modified)
  - the file is compressed, not encrypted
  - this is not the metadata file at all, but something named similarly

Next test: find the IL2CPP binary's metadata loader and locate the
           transformation applied before the header is validated.
           `strings-map.py --xrefs` on libil2cpp.so for "global-metadata"
           will locate the open() call site.
```

Entropy of 7.9 is not evidence of encryption. It is evidence of
low compressibility, which encryption, compression, and a custom format all
produce.

## 6. Find the metadata loader anyway

Even with unusable metadata, the *binary* is normal. The string that opens it:

```sh
scripts/find-xrefs.py dump/extracted/lib/arm64-v8a/libil2cpp.so \
    --string "global-metadata.dat" --containing-funcs
```

```
target 0xa1f3c  (string 'global-metadata.dat')
  section   : .rodata
  references: 1
    instruction 0x4b21c  add	x1, x1, #0x13c
  containing functions: MetadataCache_InitFromBinary
```

One containing function. That is the loader: the code that opens, transforms
and caches the metadata. It is often not stripped even when the metadata is
protected, because the runtime needs it.

Read it. The transformation applied to the header between `open()` and the
magic check is the thing that makes the metadata usable, and it is exactly what
`status: obfuscated_or_custom` is telling you exists.

## 7. What IL2CPP changes about the analysis

Once names are recovered, the shape of the work differs from ordinary native
analysis:

- The real code is in `libil2cpp.so`, stripped and enormous. Recovered names
  come from metadata, not from the binary's symbols.
- Struct layouts come from metadata records, which are more reliable than
  inferring them from load/store offsets.
- Virtual dispatch goes through `Il2CppVirtualInvokeData`, so the method table
  is data you can read rather than code you must trace.
- Generic instantiations and inlining mean one managed method may correspond to
  several native functions, or none separable.

This is why "libil2cpp.so: large, stripped" ranks below "the dumper already
produced symbols" in the dump's next steps. The cheap path was already taken.

## 8. Document

```markdown
## Unity / IL2CPP analysis: game.apk 1.9.2

Observed:
  - lib/arm64-v8a/libil2cpp.so present
  - assets/bin/Data/global-metadata.dat, 14,725,184 bytes
  - standard magic af1bb1fa present at offset 0
  - metadata version field 29
  - version string "2022.3.42f1" in globalgamemanagers
  - Unity data directory layout present

Conclusion: Unity build with the IL2CPP scripting backend.
            Confidence: high — four independent indicators, one of which
            (the magic) is a content check rather than a filename match.

Version:   2022.3.42f1, confidence medium — a string in a data file,
           not yet reconciled with the app's own versionName.

Metadata:  standard header, version 29, offset table within the file.
Dumper:    Cpp2IL ran and produced 4 files; see report.json for argv.

Not investigated: AssetBundle contents; scripting backend behaviour under
                  obfuscation; whether Managed/ is present (it is not, which
                  is consistent with IL2CPP rather than Mono).
```

## Next investigation step

- Reconcile `2022.3.42f1` with the app's `versionName` and the ABI set, then
  confirm the metadata version against that release's known mapping. That
  converts the version from a range to a specific build.
- If the dumper produced `script.json`, read it for method and field names
  that the string evidence suggested (`Crypto.decrypt`-style JNI names, API
  host strings), and treat each as a hypothesis to test in the native code.