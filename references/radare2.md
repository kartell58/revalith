# radare2 / rizin

Scriptable, fast, headless-friendly. Best when analysis must be automated or
replayed exactly. Cutter is the GUI.

## Command model

Two commands do most of the work:

```sh
r2 -q -A -c 'axt @ 0x2a4c0' ./libfoo.so    # xrefs TO 0x2a4c0
r2 -q -A -c 'axf @ 0x2a4c0' ./libfoo.so    # xrefs FROM 0x2a4c0
```

`axt`/`axf` are the commands to memorise. Almost every investigation starts
by asking who references a thing.

## Common commands

```sh
r2 -q -c 'aaa; afl' ./libfoo.so        # analyse, list functions
r2 -q -c 'aaa; s 0x2a4c0; pdf' ./libfoo.so   # disassemble function
r2 -q -c 'aaa; iS' ./libfoo.so         # sections
r2 -q -c 'aaa; ii' ./libfoo.so         # imports
r2 -q -c 'aaa; iE' ./libfoo.so         # exports
r2 -q -c 'aaa; iz~login' ./libfoo.so  # strings in .data
r2 -q -c 'aaa; pds @ sym.func' ./libfoo.so  # decompile (pdg/pdc)
r2 -q -c 'aaa; agC @ main' ./libfoo.so     # call graph as dot
r2 -q -c 'aflj' ./libfoo.so           # list functions as JSON
```

JSON output modes (`aflj`, `iij`, `izj`) make radare2 easy to drive from a
script, which is the main reason to prefer it over a GUI for automation.

Analysis levels, cheapest first: `aa` (functions from symbols), `aaa`
(autoanalysis), `aaaa` (experimental, slow, more aggressive). Use `aa` when
you only need function boundaries and `aaa` when you need xrefs.

## Flagging

```sh
r2 -q -c 'aaa; f sym.parse_header 0x2a4c0' ./libfoo.so
```

Names persist in the project, which makes cross-session work coherent. Keep
flagging conventions consistent — `sym.`, `loc.`, `str.` prefixes let you tell
renamed from original later.

## Structure and type

```sh
r2 -q -c 'aa; afij @ fcn.00101234' ./libfoo.so
r2 -q -c 'aaa; pf x 4z name size @ 0x405000' ./libfoo.so   # define a struct
r2 -q -c 'aaa; t.' ./libfoo.so                            # list types
```

Type definitions and function signatures (`af` + `afs`) propagate through
xrefs, so setting a signature once improves every call site.

## Pros

- Excellent headless scripting; reproducible pipelines
- Fast; usable over SSH on large binaries
- MIT-licensed and lightweight
- rizin is the actively maintained fork with a similar command set

## Cons

- Default analysis finds fewer functions than Ghidra; expect to run `aaa`
  and occasionally fix boundaries manually
- The decompiler (pdg, via Ghidra-based r2dec, or r2ghidra) is not always
  present or as accurate as Ghidra's
- Output formats are terse and sometimes need `-q` and explicit separators

## When to choose it

Automated triage, repeatable scripted analysis, or working in an environment
where Ghidra's GUI or JVM is impractical. For interactive deep analysis with
decompilation, Ghidra or Binary Ninja is usually faster.