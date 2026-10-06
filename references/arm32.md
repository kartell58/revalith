# ARM32 (AArch32)

32-bit ARM, still common in embedded systems, older Android devices and
firmware. The main complication is that code comes in two encodings.

## Thumb and ARM modes

- **ARM mode**: 4-byte instructions, conditional execution native to the ISA.
- **Thumb mode**: 16-bit (and extended 32-bit) instructions, denser code.

Both may appear in one binary, switching via `bx`/`blx`. Look for bit 0 of
the branch target: in Thumb, the interworking branch sets bit 0.

```
blx 0x1234      ; switch to Thumb at 0x1234 (bit 0 set)
bx   lr         ; return, restoring the caller's mode
```

Reading ARM32 disassembly without knowing the mode produces meaningless
output. Confirm the mode per function, ideally from the symbol address parity
or the tool's own decoding.

## Registers

`r0`–`r12` general purpose, `sp` stack pointer, `lr` link register, `pc`
program counter, `fp` frame pointer.

AAPCS:

| Purpose | Registers |
| --- | --- |
| Integer arguments 1–4 | `r0`–`r3` |
| Return value | `r0` |
| Callee-saved | `r4`–`r11` |
| Frame pointer | `r11` or `r7` |
| Link register | `r14` (`lr`) |
| Stack pointer | `r13` (`sp`) |
| Scratch / indirect result | `r12` (`ip`) |

Stack arguments begin at `[sp, #0]` after the return address. Arguments 5 and
up are memory operands, which is why a function taking six arguments shows
only four in registers.

## Instruction set that matters

| Insn | Effect |
| --- | --- |
| `bl <label>` | call, writes PC to `lr` |
| `blx <Rm>` / `blx <label>` | interworking call, sets mode bit |
| `bx lr` | return, restoring mode |
| `ldr r0, [pc, #8]` | literal-pool load (constant, or function address) |
| `ldr r0, =0x1234` | pseudo-instruction; assembles to a literal pool load |
| `add r0, pc, #...` | PC-relative address computation |
| `cmp`, `tst` | set flags |
| `b<cond>` | conditional branch (16 conditions in ARM mode) |
| `bls`, `bhi`, `ble` | unsigned/signed conditional branches |
| `mov`, `movw`, `movt` | move; `movw`+`movt` builds a 32-bit constant |
| `ldm`/`stm` | load/store multiple, used for prologues |

## Literal pools

ARM code reaches constants and addresses through a literal pool in `.text`:

```
ldr r3, [pc, #24]      ; load from the pool
...
.word 0xdeadbeef        ; the actual data, after the function
```

An address referenced only through a literal pool will not appear as an
operand of `ldr`/`add`. A single search for the target address in the file
finds the pool entry; finding the function that loads it requires scanning
backwards for the matching `ldr`.

`[pc, #imm]` is PC-relative, where PC is the instruction address plus 8 in
ARM mode. Tools usually resolve this, but verify when it matters.

## Building constants

```
movw r0, #0x1234
movt r0, #0xabcd      ; r0 = 0xabcd1234
```

`mov` with an 8-bit-rotated immediate covers many small constants; anything
larger needs `movw`/`movt`. A literal pool entry is another route.

## Stack frames

```
push {r4-r7, lr}      ; save registers and return address
sub  sp, sp, #16
...
add  sp, sp, #16
pop  {r4-r7, pc}      ; restore and return
```

`push {... lr}` plus `pop {... pc}` is the reliable frame signature. In Thumb
mode `push {r4, lr}` / `pop {r4, pc}` serve the same purpose. Frame size
(`sub sp, sp, #N`) indicates local storage.

## Conditional execution

In ARM mode almost any instruction can take a condition code, which makes
control flow denser than AArch64. The compiler often uses it instead of
branching:

```
moveq r0, #1     ; if equal, set r0 = 1
movne r0, #0     ; if not equal, set r0 = 0
```

This is an if/else expressed without a branch. Reading only explicit branches
will miss the structure, so look at the condition suffixes too.

In Thumb-2 there is `it` (`if-then`) blocks that scope conditions over
several instructions:

```
it   eq
moveq r0, #1
movne r0, #0
```

## Reading a function

1. Determine ARM or Thumb mode for that address.
2. Find the `push`/`stmfd` prologue and the frame size.
3. Identify `r0`–`r3` reads before writes — the register arguments. Check
   `[sp, #N]` operands for stack arguments.
4. Collect `bl`/`blx` targets.
5. Check `r0` before each return — `bx lr`, `pop {..., pc}`.
6. Find literal-pool loads to discover referenced constants and addresses.

## Platform notes

- Some ARM cores run Thumb-2 only (Cortex-M). No ARM mode, no literal pool in
  the classic sense, different `r13`/`r14` roles.
- Cortex-M uses `r13` as both stack pointer and process stack pointer, and
  `r14` as the exception return address.
- NEON and VFP introduce `q`/`d`/`s` registers; they carry floating-point and
  SIMD data, not ordinary arguments.
- `r12` (`ip`) is a scratch register, not an argument.
- Older ARM binaries may interwork `bx` freely; do not assume one mode for a
  whole image.