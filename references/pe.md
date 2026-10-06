# PE/COFF

Windows executables, DLLs and drivers. Layout differs substantially from ELF,
and the differences matter when transferring a technique.

## Structure

```
DOS header (MZ)          e_lfanew at 0x3C -> offset of PE signature
PE signature "PE\0\0"
COFF file header         machine, section count, timestamp, characteristics
Optional header          magic 0x10b (PE32) or 0x20b (PE32+), entry RVA,
                         ImageBase, data directories
Section table            name, VirtualSize, VirtualAddress, SizeOfRawData,
                         PointerToRawData, characteristics
```

Note the split between **RVA** (relative virtual address) and raw file
offset. `ImageBase + RVA` is the loaded address; the RVA maps to a file offset
through the section table. Any tool that reports "the entry point" may mean
either — check which.

## Useful fields

`readelf` and `nm` do not read PE. Use `objdump`, `llvm-readobj` or
`dumpbin`:

```sh
objdump -x ./app.exe                    # all headers
objdump -p ./app.exe                    # private headers incl. directories
objdump -h ./app.exe                    # sections
objdump -t ./app.exe                    # symbols
objdump -d ./app.exe                    # disassembly
objdump -p ./app.exe | grep -A5 'DLL Name'
llvm-readobj --coff-imports ./app.exe
llvm-readobj --coff-exports ./app.dll
```

Characteristics worth checking: `IMAGE_FILE_DLL` (is it a DLL),
`RELOCS_STRIPPED` (fixed base, no ASLR), `DEBUG_STRIPPED`.

PE files are *not* position-independent by default. `ImageBase` is typically
`0x140000000` for x64 executables. ASLR is opt-in and frequently absent,
which makes addresses stable across runs — convenient for analysis, and a
sign the target predates modern hardening.

## Imports

The import directory is an array of `IMAGE_IMPORT_DESCRIPTOR`, each naming a
DLL and pointing at two arrays: the Import Lookup Table (names, as stored on
disk) and the Import Address Table (slots the loader patches at load time).

The distinction is important for analysis:

- **ILT** — names as written by the compiler; stable on disk.
- **IAT** — slots; before binding they mirror the ILT, afterwards they hold
  resolved addresses.

Calls to imports usually go through `call qword ptr [rip+disp]` targeting an
IAT slot. To identify the called function, compute the slot's address, then
look up which descriptor and ILT entry owns it.

Delay-loaded imports live in their own directory and resolve on first call. A
function called through a delay-import slot behaves differently before and
after first use.

## Exports

The export directory names the DLL and points at parallel arrays:
`AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals`. A name index
maps to an ordinal index, which indexes the function array.

A non-zero function RVA inside the export directory range is a **forwarder**:
a string naming another DLL's export, not code. Concluding "this is a
function" from an export table alone gets this case wrong.

## Sections and metadata

`.text`, `.rdata`, `.data`, `.rsrc`, `.pdata`. `.pdata` is the x64 exception
table: like ELF's `.eh_frame`, it records function start/end pairs and
survives in stripped binaries. It is the most reliable way to recover
function boundaries.

PE also has:

- `.reloc` — base relocation table; its absence means no ASLR
- `.CRT`, `.tls` — initialisation and thread-local storage
- a COFF symbol table, sometimes retained even in "stripped" binaries
- rich header, deleted by MSVC-linked binaries

## Managed code

A PE with a CLI header is .NET. The interesting parts are in metadata and IL,
not x86. Disassembling the native stub tells you nothing about the program's
logic.

Check for it:

```sh
objdump -x ./app.exe | grep -i "cli\|cor20\|_CorExeMain"
```

If present, use a managed disassembler. The native entry point is just a
runtime bootstrapper.

## Packed binaries

Common in malware. Indicators: small `.text`, high-entropy sections, few
imports (only `LoadLibrary`/`GetProcAddress`), a `.rsrc` holding a large blob.
Most PE packers resolve imports at runtime, so a low import count plus those
APIs is the classic combination.

## Cross-format differences worth remembering

| Concern | ELF | PE |
| --- | --- | --- |
| Position independence | usual for libs and PIE | fixed `ImageBase` by default |
| Function boundaries when stripped | `.eh_frame` | `.pdata` |
| Late binding | GOT/PLT | IAT |
| Interprocedural calls | direct | usually through IAT slot |
| Import enumeration | `readelf --dyn-syms` | `llvm-readobj --coff-imports` |

## Signing

Authenticode is a PE certificate in the security directory. It does not
change the code, but a signature that does not match the hash indicates
post-signing modification — worth noting before drawing behavioural
conclusions.