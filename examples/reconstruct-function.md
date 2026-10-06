# Example: reconstruct one function

From an address to a named, evidence-backed model. This is the smallest unit
of reconstruction, and it is the one that has to work before anything larger
does.

> All target data below is **synthetic**, invented for this example. The
> commands are real and runnable; substitute your own target.

## The starting point

> "What is 0x8120?" — with a stripped binary, a string reference, and no
> other context.

A question that looks small and is not: answering it means separating four
things that a decompiler silently merges.

## What is available

```sh
scripts/universal-dump.py ./game.bin -o dump/ -q
```

```
binaries
  game.bin
    ELF 6502 16-bit big, stripped
    entry 0xC010   interpreter none
```

No symbols, no interpreter — so it runs on an emulator or not at all. Check
that before planning dynamic analysis.

```sh
scripts/find-xrefs.py ./game.bin --addr 0x8120 --containing-funcs
scripts/elf-summary.py ./game.bin --sections
```

```
0x8120 referenced by 2 instruction(s)
  0xC3A1  jsr 0x8120        ; from the frame loop
  0xC412  jsr 0x8120        ; from the input handler
sections
  .text   0xC000  size 0x2A40
  .rodata 0xE440  size 0x0180
```

Two call sites, both in a plausible frame loop. That is the first real
observation.

## Observations

Collect these before forming any hypothesis:

```sh
objdump -d --start-address=0x8120 --stop-address=0x81A0 ./game.bin
```

```
8120: ldy  $10          ; load indirect Y
8122: lda  $4310,x      ; read one byte
8125: clc
8126: adc  $4312,x      ; add the next
8129: sta  $4314,x      ; write one byte
812c: lda  $4312,x
812f: cmp  #$40
8131: bcc  813d
8133: lda  #$00
8135: sta  $4312,x
8138: jmp  813d
813d: rts
```

Now list what is *in the code*, separate from what it might mean:

| Observed | Confidence |
| --- | --- |
| reads two bytes at 0x4310 and 0x4312 (offsets +0, +2 from X) | high |
| adds them: `byte0 + byte1` | high |
| writes the sum to 0x4314 (offset +4) | high |
| reads 0x4312 again and compares against 0x40 | high |
| if ≥ 0x40, zeroes 0x4312 | high |
| two call sites, both in the frame region | medium |
| X is a pointer to a 16-byte-ish block | low |

That table is the honest state. Nothing here mentions physics, health or
gravity, and no name should yet.

## The name, earned in steps

### Step 1 — describe it

```
0x8120
  "adds two bytes of a block, stores the sum, and clamps the second byte
   at 0x40"
  status: observed                    confidence: high
```

`sum_and_clamp` is defensible: every word is supported by an instruction.

### Step 2 — narrow it with the callers

What X is depends on the callers. Look at them.

```
0xC3A1: ldx  #$20       ; a fixed page
       jsr  0x8120
0xC412: ldx  #$24       ; a different fixed page
       jsr  0x8120
```

X is a fixed page index, not a pointer to a heap object. That changes the
model: the same routine maintains two fixed state blocks at 0x4310 and 0x4320.

```
0x8120
  "adds byte +0 to byte +2 of a fixed state page, stores to +4,
   clamps byte +2 at 64"
  status: observed                    confidence: high
```

### Step 3 — find the context

Two call sites, and one of them is in an input handler. Read around it:

```
0xC400: lda  #$01
0xC402: sta  $4312,x     ; writes the SAME byte this function clamps
0xC405: jsr  0x8120
0xC408: ldy  #$10
0xC40A: lda  $4310,x
```

`0x4312` is written by the caller before the call. So the clamp is on a value
the caller sets. That is a meaningful shape: the caller supplies an increment,
and 0x8120 accumulates it into a bounded total.

```
0x8120
  "accumulates byte +2 (set by the caller) into byte +0 as a byte,
   stores the low byte at +4, and resets +2 when it reaches 0x40"
  status: partially-reconstructed     confidence: medium
```

Now a defensible descriptive name:

```
accumulate_and_wrap
```

### Step 4 — dynamic evidence

If the target runs, this is where `medium` becomes `high` or the hypothesis
dies. Set a watchpoint and drive the input:

```sh
# on an emulator: break on 0x8120, read the three bytes each call
```

```
call   1: +0=0x00  +2=0x01  -> +4=0x01   +2=0x01
call   2: +0=0x01  +2=0x01  -> +4=0x02   +2=0x02
call  64: +0=0x3F  +2=0x01  -> +4=0x40   +2=0x40
call  65: +0=0x3F  +2=0x01  -> +4=0x00   +2=0x00
```

The trace settles two things the static read left open: the accumulator is
byte-wide (it wraps to 0x00, not to 0x40), and the clamp happens *after* the
store, so `+4` records 0x40 on the frame the counter saturates.

```
accumulate_and_wrap
  status: reconstructed               confidence: high
  observed_behaviour: adds +2 to +0 as a byte, stores the sum at +4,
                      then zeroes +2 when it reaches 0x40
```

### Step 5 — semantic name, or none

Is this a frame counter? A countdown? A resource meter? Two fixed pages, a
caller that increments one byte, a bound of 64, and a byte-wide accumulator.

```
hypothesis: a countdown that the input handler resets and that ticks once
            per frame
confidence: low
evidence:   2 fixed pages; the caller writes +2 before calling; saturates
            at 64 and wraps the accumulator to 0
next_test:  drive both pages and watch whether they wrap together or
            independently; a countdown shared by two players differs
```

`timed_resource` is now usable **because it is labelled low**. If the next
test shows the two pages wrap independently, the name is wrong and the ledger
says so.

What must not happen is `updateTimer` appearing anywhere in this process with
no record of how it was earned.

## Record it

```sh
scripts/recon-ledger.py add ./reconstruction functions 0x8120 \
    --address 0x8120 \
    --evidence "reads bytes at 0x4310 and 0x4312, adds them, stores at 0x4314" \
    --evidence "reads 0x4312, compares against 0x40, zeroes it if >= 0x40" \
    --evidence "both call sites pass X as a fixed page (0x20, 0x24)" \
    --evidence "the caller at 0xC402 writes 0x4312 immediately before the call" \
    --evidence "traced: the accumulator wraps to 0x00 at saturation" \
    --observed-behavior "adds +2 into +0 as a byte, stores the sum at +4, then resets +2 at 0x40" \
    --hypothesis "a countdown reset by the caller, ticking once per frame" \
    --next-test "drive both pages and see whether they wrap independently" \
    --status reconstructed --confidence high
```

```sh
scripts/recon-ledger.py show ./reconstruction 0x8120
```

The entry is honest about the split: the mechanism is reconstructed at `high`,
the purpose is a hypothesis at `low`, and the entry does not conflate them.

## From the model to code

The mechanism is enough to implement, and it does not require knowing the
purpose:

```c
/* Reconstructed from 0x8120. Semantics established; the "countdown"
   interpretation is a low-confidence hypothesis and is not encoded here. */
static void accumulate_and_wrap(uint8_t *page)
{
    page[0] = (uint8_t)(page[0] + page[2]);   /* wraps as a byte */
    page[4] = page[0];
    if (page[2] >= 0x40) {
        page[2] = 0;
    }
}
```

Note the comment says what is reconstructed and what is not. A reader can tell
that reimplementing the arithmetic does not depend on the hypothesis being
right.

## Verify

```sh
scripts/state-diff.py original-state.json reimpl-state.json
```

The original exposes this state through a save file or a debug register dump,
or it does not. If neither exists, the honest position is that the function's
behaviour is reconstructed from static evidence plus a trace, and the
reimplementation has not been differentially tested — record that rather than
implying the test happened.

## What this example shows

- the name arrived in four steps, each one supported
- the semantic name stayed a hypothesis, and was labelled
- the arithmetic was implemented from the model, not from the disassembly
- what is not verified is stated

The compact version of the discipline: **describe before naming, name only
what you can defend, and let the purpose stay a hypothesis until something
tests it.**