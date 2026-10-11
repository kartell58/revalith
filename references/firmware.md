# Firmware

Firmware is compiled software with no operating system under it, shipped as a
raw image with no container format. Everything the binary workflow relies on —
program headers, a dynamic loader, a process, `/proc` — is absent.

That absence is the whole difficulty, and it is a content-identification
problem, not a tooling problem. The filename tells you nothing: `fw.bin`,
`update.img`, `rom0` and `flash.bin` are all guesses.

## What you are looking at

Before anything else, establish what kind of artefact this is, because each
kind implies a different next step:

| Kind | How to tell | Next step |
| --- | --- | --- |
| Raw flash image | no header; entropy varies by region | map it, find the reset vector |
| Container with an update wrapper | magic at 0, length field, CRC | strip the wrapper |
| Filesystem image | superblock magic at a known offset | mount or extract |
| Archive | ZIP/gzip/cpio/… magic | unpack, then re-examine |
| Encrypted or compressed blob | uniform high entropy, no magic | find the key, or find the code that uses it |

The last row is the one that ends investigations early, because a blob with no
structure is not a format you failed to parse — it is evidence that the image
is encrypted or compressed, and the next step is to find the code that
processes it, not to try harder parsers.

```sh
file firmware.bin
xxd -l 64 firmware.bin
python3 scripts/universal-dump.py firmware.bin -o dump/
```

`universal-dump.py` reports indicators with offsets and provenance, which is
the right first pass: it names what it found and where, and it does not claim
to have decoded anything it did not.

## Establishing the architecture

There is no ELF header to read. Identify by content, in this order of
reliability:

**A vector table.** The strongest evidence. Firmware for ARM, AVR, MSP430,
MIPS, RISC-V and most others begins with a jump table: a stack pointer
followed by reset and interrupt handlers.

```
  offset 0x00: initial stack pointer
  offset 0x04: reset handler
  offset 0x08: NMI / unhandled interrupt
  ...
```

Two ARM vectors are recognisable from a byte pattern alone — `b reset` is
`EA00 00xx`, and the table is a sequence of branch instructions whose
displacements are small and forward. Finding that pattern is strong evidence
of ARM firmware; it is not proof, so confirm with at least one more indicator.

What the stack pointer tells you: it points to the top of RAM, and on most
targets that value is recognisable — typically a round number just below a
power of two, which bounds the RAM size from below. That is enough to work out
the flash↔RAM address relationship, which is what you need to read a `const`
table correctly. It is a bound, not a measurement: a part with more RAM than
the stack pointer suggests is entirely possible.

**Strings.** Vendor names, part numbers, build paths, `FreeRTOS`, `newlib`,
copyright lines naming a toolchain. Weak on their own — a string can be
anything — but a string naming the exact part family is close to decisive.

**Code shape at the reset vector.** Read a few instructions. An unconditional
branch into a prologue, a push of several registers, a stack frame being set
up: ordinary code that a disassembler will read without complaint, once it
knows the architecture.

**Timing and instruction mix.** A table of `0x0000` and `0xFFFF` blocks
suggests erased flash. 16-bit architectures show more alignment padding.

Record which indicators agreed and how many. "ARM firmware" from one branch
pattern is a hypothesis; from a vector table, a plausible stack pointer, a
vendor string and readable code, it is established.

```
Architecture:  ARM 32-bit little-endian (thumb code)
Basis:         vector table at 0x0000; SP 0x20008000 (top of 512K RAM);
               reset handler 0x0000290D is a thumb branch, entry state SP set
               and bit 0 of PC clear; "STM32F4" in a copyright string at 0x2f10
Confidence:    high
```

## A memory map without a process

There is no `/proc/<pid>/maps`. The map comes from three sources instead:

**The reset vector.** The initial stack pointer marks the top of RAM.

**The linker script, if you can find it.** Often present as strings or as a
build artefact; `MEMORY { RAM ... FLASH ... }` is unmistakable when present.

**Cross-references between regions.** A constant-table address in the code
that matches an offset in a data region gives the load address directly.

Then classify each region, and say what the classification rests on:

| Region | Evidence | Not yet established |
| --- | --- | --- |
| flash, `x` | addressed by the reset vector's code; no writes observed | that nothing writes it |
| RAM, `rw` | the stack pointer points here; written at boot | its size, unless the SP implies it |
| vector table | at offset 0; jump targets all land in one region | which entries are actually wired up |
| MMIO | addresses far outside RAM; access is word-width and sparse | which peripheral, without the datasheet |

The last row is the trap. A region at 0x40000000 accessed sparsely is
*consistent with* MMIO and is almost certainly MMIO, but "almost certainly" is
not a peripheral identification. Mapping it to a specific device needs the
datasheet, the SoC name, or an observed side effect — a bit that changes, an
interrupt that fires. Record the basis.

## The boot sequence

Worth reconstructing explicitly, because "it does not run" is almost always
"it does not run *yet*":

```
reset vector
   ↓
  startup: copy .data from flash to RAM, zero .bss
   ↓          ← observe this; it tells you which regions are writable and
   ↓            which are load-address-relative
  main()
   ↓
  init: clocks, pin mux, peripherals
   ↓
  main loop
```

The `.data` copy is the step most often missed. A global that is initialised
non-zero is stored in flash at its *load* address and lives at a different
*run* address in RAM. Reading it from flash gives you the initial value and
nothing about the current one, and the offset between the two is in the
vector table's neighbourhood or the linker script.

## Finding content inside the image

| What you find | How it was found | Next step |
| --- | --- | --- |
| filesystem magic | at an offset, with a plausible size field | extract; do not guess the offset |
| archive magic | repeated at intervals | unpack, re-examine each member |
| high-entropy region | measured, with boundaries | treat as compressed or encrypted |
| all-zero region | large and aligned | erased flash, padding, or a cleared buffer |
| code-like region | disassembles cleanly at that offset | record the offset; it is the entry point |

Entropy is a measurement and the boundary between "compressed" and "encrypted"
is not a line entropy can draw. Both look uniform. What separates them is
whether anything consumes the data: find the code that reads the region, and
watch what it does with the values. If they become plaintext, it was
compression. If they become a key schedule, it was encryption.

`scripts/universal-dump.py` reports these regions with offsets and entropy.
It names what it measured; it does not decide what the region is.

## Getting it to run

This is where `emulation.md` takes over, and it is the step most likely to
need a whole afternoon:

1. Establish the architecture and the memory map (above).
2. Pick the emulator: `qemu-system` with a machine close to the real SoC, or
   a Unicorn harness for a single routine.
3. Provide the peripherals the boot actually touches. A target that
   initialises three registers and then waits will run in almost any model; one
   that configures a timer and polls it will not.
4. Establish that it reaches your code before treating anything it does as
   evidence.

Confirming "it booted" is a real step. An image that never reaches `main()` has
told you about the harness, not the firmware.

## Tools

Check before assuming any of them exist (`tooling.md`):

| Tool | Does | If absent |
| --- | --- | --- |
| `binwalk` | signature scan, extraction | `universal-dump.py` for magic and entropy |
| `qemu-system-<arch>` | full-system execution | a Unicorn harness for one function |
| `readelf`/`objdump` | if the image has an ELF wrapper | not applicable to raw flash |
| `strings` | vendor and build identification | `strings-map.py` with offsets |
| Ghidra, radare2 | loading raw images at a chosen architecture | load with an explicit arch |

A raw image in a disassembler is worth more than nothing: specify the
architecture and the base address explicitly, or the addresses you then read
will be wrong in a way that is easy to miss.

## What firmware analysis does not deliver

- **The build system.** Compiler version and flags are often inferable from
  emitted code patterns, never certain.
- **Schematic-level intent.** MMIO at 0x40012400 is a GPIO port; which pin,
  and what it is wired to, is not in the image.
- **Runtime behaviour of peripherals.** You will be running a model. See
  `emulation.md` for what that does not prove.
- **Anything the image does not contain.** A stripped-down image with no
  symbols, no version string and no filesystem still has a reset vector, and
  that is where you start.

## Recording

The shape below is illustrative: the format is what to copy, the values are an
example and not a measurement from a real device.

```markdown
Target:      router-firmware.bin, sha256:3c1a..., 4 MiB
Container:   raw flash, no header; magic search found nothing
Architecture: ARM 32-bit LE (thumb)
Basis:       vector table at 0x0; SP 0x20020000 (top of 128K RAM);
             reset handler branches to 0x08004120 (thumb)
Regions:     0x000000-0x07FFFF code+rodata (flash)
             0x200000-0x2001FFFF data (RAM, SP at top)
             0x40000000-0x4000FFFF MMIO, sparse word access  [basis: address
                 range and access width; specific peripheral not established]
Observations: vendor string "uClinux 3.0" at 0x0f21c; no filesystem magic
Open:        the 64 KiB region at 0x300000 has entropy 7.9 and no references
             from the vector table region
```

The `Open` line is what the next session reads first.

## See also

- `emulation.md` — running it, and what a model does not prove
- `elf.md`, `macho.md` — when the image *is* wrapped in a real container
- `tooling.md` — never assume a tool is installed
- `binary-diff.md` — comparing two firmware builds for the same device
- `investigation-state.md` — recording what is still open