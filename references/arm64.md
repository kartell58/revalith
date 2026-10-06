# AArch64 / ARM64

Enough to reconstruct control flow, calls, arguments and data access. Not a
full ISA manual.

## Registers

- `x0`–`x30` — general purpose; `x` is 64-bit
- `w0`–`w30` — the low 32 bits of the same registers
- `sp` — stack pointer
- `pc` — program counter (not directly writable; branches write it)
- `xzr`/`wzr` — the zero register, reads as 0 and discards writes

Writing `w0` zeroes the top 32 bits of `x0`. In disassembly, `mov w0, #1`
makes the full register 1.

Under AAPCS64:

| Purpose | Registers |
| --- | --- |
| Integer arguments 1–8 | `x0`–`x7` |
| Return value | `x0` |
| Callee-saved | `x19`–`x28` |
| Frame pointer | `x29` (FP) |
| Link register | `x30` (LR) |
| Stack pointer | `sp` |
| Indirect result location | `x8` |

`x0` is both the first argument and the return register. That is the single
biggest source of signature mistakes: reading `x0` may be reading an argument,
returning a value, or both. Only the caller can disambiguate.

## Instruction set that matters

### Calls and returns

| Insn | Effect |
| --- | --- |
| `bl <label>` | branch with link: call, writes PC to `x30` |
| `blr <Xn>` | indirect call through a register |
| `br <Xn>` | indirect jump |
| `ret` | return to `x30` (`ret xN` returns to `xN`) |

`bl` is the workhorse. A function's callers are found by scanning for `bl`
targets.

### Addressing

| Insn | Effect |
| --- | --- |
| `adrp xd, page` | `xd` = page base of a 4 KiB-aligned address |
| `adr xd, label` | `xd` = full 21-bit-range address |
| `ldr xd, [xn, #imm]` | load 64-bit with unsigned offset |
| `str xd, [xn, #imm]` | store 64-bit |
| `ldur`/`stur` | same, signed offset |
| `ldp x1, x2, [sp, #16]` | load pair (also used to save registers) |

`adrp` always loads a *page* (4096-byte aligned) and is almost always paired
with `add` or `ldr`:

```
adrp x0, 0x20000      ; x0 = 0x20000
add  x0, x0, #0x8c0   ; x0 = 0x208c0  <- the real address
```

Disassemblers often fold the pair into `add x0, x0, #0x8c0` or print the
resolved symbol. When computing references manually, keep the pairing in mind;
matching on the `adrp` line alone finds pages, not addresses.

This is why `x8` appears in `ldr x17, [x16, #1288]` inside PLT stubs: it is
the GOT scratch register, not an argument.

### Comparison and branching

| Insn | Effect |
| --- | --- |
| `cmp xn, #imm` / `cmp xn, xm` | set flags |
| `tst xn, #imm` | test bits |
| `csel xd, xn, xm, cond` | conditional select (often an if/else) |
| `b.<cond>` | conditional branch |
| `cbz`/`cbnz` | compare and branch on zero |
| `tbz`/`tbnz` | test bit and branch |

Conditional branches are the source of most control-flow structure, so
reading them is how you recover if/else and loop boundaries. `cbz`/`cbnz` on
a function pointer almost always signals a null check before an indirect call.

### Loops

```
1:  ldrb w9, [x0], #1    ; load byte, post-increment
    cmp  w9, #0
    b.ne 1b              ; loop while non-zero
```

Post-indexed loads (`[x0], #1`) and backward branches define the loop. The
branch target is a label, printed as the containing symbol plus an offset.

## Stack frames

A standard prologue:

```
stp x29, x30, [sp, #-32]!   ; save FP and LR, pre-decrement SP
add x29, sp, #16            ; set frame pointer (or "mov x29, sp")
stp x19, x20, [sp, #16]     ; save callee-saved registers
...
sub sp, sp, #0x120          ; larger frame
...
ldp x29, x30, [sp], #32     ; restore
ret                        ; return to LR
```

`stp x29, x30, [sp, #-N]!` is the reliable prologue signature. A function that
never touches `sp` is a leaf and takes no frame. Frame size tells you about
local storage, which often reveals structure size.

`adrp x29, ...; mov x29, sp` (omit-frame-pointer) is common in release
builds. Then `x29` holds no frame pointer and cannot be used to walk the
stack.

## Calling convention notes

- The caller allocates the argument area, so callee code often does not push
  arguments.
- Stack arguments (beyond `x7`) are accessed via `sp` at fixed offsets.
- Structs larger than 16 bytes are passed by pointer, with `x8` holding the
  address of the result.
- `x16`/`x17` are intra-procedure-call temporaries — PLT stubs use them. Do
  not read them as arguments.
- `x18` is reserved by some platforms; treat it as reserved.
- Variadic functions need `al` to hold the count of vector registers used.
- AArch64 has no flags register; comparisons set NZCV and branches read it.

## Interprocedural calls

```
bl   0x2a4c0            ; direct call
ldr  x8, [x21, #16]
blr  x8                 ; indirect call through a table -> vtable or switch
```

An indirect call through a table loaded from a struct is the signature of
virtual dispatch, a callback, or a switch jump table. Follow the table to
find the candidates.

## Reading a function

1. Locate the prologue and frame size.
2. Note which of `x0`–`x7` are read before written — those are arguments.
3. Collect `bl` targets — callees.
4. Find `adrp`/`add` pairs — global data referenced.
5. Look for `csel`, `cbz` and conditional branches — the control-flow shape.
6. Check whether `x0` is written with a value unrelated to its incoming value
   before each `ret` — that is the return value.
7. If `x0` is only written immediately before a call, it is argument
   marshalling, not a return.

## Practical shortcuts

- A function whose body is `adrp/add` then `bl` is a thin wrapper or a getter.
- `mov w0, #0` followed by `ret` is a `return 0` / failure path.
- A `nop` cluster at the start often marks an alignment boundary, not code.
- `b` to the next instruction is unreachable filler.
- A long run of `nop` can be alignment padding before a data blob.