# Binary Ninja

Commercial, closed-source, with a fast decompiler and an unusually good
Python API. Best interactive experience when licensed; not something to
install mid-investigation.

## Concepts

- **Binary View** — the disassembly
- **IL** — an intermediate language lifting each architecture into, which is
  why decompilation is fast and uniform
- **Function** — with a recovered calling convention and MLIL/HLIL
- **Types** — structures and unions, applied globally
- **Dataflow Analysis** — a taint-like layer that resolves indirect calls

The **IL** is the distinguishing feature: lifting x86 and AArch64 into the
same intermediate language means analysis scripts transfer across
architectures, and the type system applies without per-architecture work.

## Types and structure recovery

Types are defined once and propagate to every use.

```python
# Creating a structure programmatically
bv = current_view
st = bv.get_type("Structure") or bv.create_structure("Player")
st.add_member(0x00, bv.get_type("uint32_t"), "unknown")
bv.add_type(st)
```

Good workflow: let the decompiler guess, then correct. Binary Ninja's
`Structure Editor` applies a change across every function that touches the
structure, which makes iterative struct refinement fast.

## MLIL and HLIL

- **MLIL** — microcode per function, with expression-level arithmetic and
  branch conditions resolved
- **HLIL** — higher-level, roughly C-like

```
MLIL:  x0 = x1 + 8
HLIL:  *(int32_t *)(arg1 + 8) = ...
```

Reading HLIL first and dropping to MLIL for anything unclear is the fastest
path. HLIL is an interpretation, not proof — verify against MLIL or the raw
bytes before concluding.

## Python API

```python
for func in bv.functions:
    print(hex(func.start), func.name)
    for ref in func.callees:
        print("   ->", ref.name)

# rename and retype across the whole database
func.name = "parse_header"
func.type = TypeFunction("int32_t", [TypePointer(TypeStruct("Player"))])
```

The API is the strongest argument for the tool: analysis written once can be
re-run across an entire corpus of binaries.

## Strengths

- Fastest interactive decompiler; the UI keeps up with large binaries
- Uniform IL across architectures
- Excellent type system and propagation
- Strong scripting API
- Dataflow analysis can resolve some indirect calls automatically

## Weaknesses

- Commercial licence; not universally available
- Closed source — behaviour cannot be verified externally, so treat
  decompiler output as inference and confirm in the Binary View
- Heuristic analysis occasionally misidentifies function boundaries; on
  obfuscated or hand-written assembly this is more frequent

## Comparison

| Need | Better choice |
| --- | --- |
| Decompiler accuracy on tricky code | Ghidra (free) or Binary Ninja |
| Batch automated triage | radare2/rizin |
| Free option with a decompiler | Ghidra |
| Licensing and budget | Binary Ninja if available, else Ghidra |

Whatever is installed, verify decompiler claims against the disassembly
before recording a finding. That rule is tool-independent.