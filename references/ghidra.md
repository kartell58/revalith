# Ghidra

Free, multi-architecture, with the strongest free decompiler. Use it when
analysis needs C-like output rather than raw assembly.

## Setup and headless use

```sh
analyzeHeadless <project_dir> <project_name> -import ./libfoo.so \
    -postScript DecompileAll.java -scriptPath ./scripts
```

Headless matters for automation: it can import, analyse and script without a
GUI, which is what makes batch triage of many binaries practical.

## Concepts

- **Program** — the loaded binary
- **Listing** — the address space
- **Symbol tree** — symbols, classes, labels
- **Defined data** — recognised structures and arrays
- **Function** — a discovered code region
- **References** — computed xrefs from code and data

Auto-analysis finds functions, strings, imports and many cross-references on
import. Trust it as a starting point, not as ground truth: it can merge two
functions, split one, or invent a boundary.

## Defining types

Structures are the point of Ghidra. Once a struct exists, every
`[reg+0x10]` shows `player->health` instead of a displacement, and the
signature propagates.

Ways to get one:

1. **Auto-create from use** — right-click a parameter, "Auto Create Structure".
   Start here; it is usually close.
2. **From a decompiler signature** — drag a type onto a variable.
3. **Import from a header** — parse an existing struct definition, the most
   accurate route when a matching header exists.
4. **From a debugger** — dump the structure from a live process.

Renaming fields before you understand them is a common mistake; the wrong
name then propagates through every signature that uses it. Use `field_08`
until you have evidence, then rename.

## Scripting

Java (Ghidra API) or Python (Jython) or PyGhidra.

```java
// Print every function and its callers
FunctionManager fm = currentProgram.getFunctionManager();
ReferenceManager rm = currentProgram.getReferenceManager();
for (Function f : fm.getFunctions(true)) {
    println(f.getName() + " @" + f.getEntryPoint());
    for (Reference r : rm.getReferencesTo(f.getEntryPoint()))
        println("    <- " + r.getFromAddress());
}
```

Useful batch operations: dump all xrefs, export the call graph, list
functions by size, rename systematically, apply a script's rename across a
program database.

## Decompiler notes

The decompiler reconstructs C from machine code. Its output is **a hypothesis
about the code, not the code**. Specific failures:

- inlined functions are inlined in the output and cannot be recovered
- `switch` becomes a chain of comparisons when the jump table is not found
- struct types are guessed and frequently wrong
- virtual calls appear as indirect calls with no target
- optimised code confuses loop bounds and variable lifetimes

When the decompiler and the disassembly disagree, the disassembly is closer
to truth. Verify anything that matters against the instruction listing.

## Strengths and limits

Strongest at: whole-program orientation, call graphs, structure recovery,
bulk renaming, decompiling many functions quickly.

Weak at: unusual or obfuscated code, self-modifying code, hand-written
assembly, packed binaries, tightly optimised code. If analysis is stuck, check
the raw bytes before believing the decompiler.

## Interoperation

Projects are `.gpr` plus `.rep` directories and can be version-controlled.
Ghidra can import and diff projects (Version Tracking) for binary comparison
— the basis of Diaphora.