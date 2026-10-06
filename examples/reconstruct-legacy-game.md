# Example: reconstruct a legacy game

End to end, on synthetic software in the style of 8- and 16-bit machines.

> **This example is entirely synthetic.** It is not an analysis of any real
> game, ROM, or commercial product. The addresses, formats and behaviours are
> invented to demonstrate the workflow at a scale worth seeing. Every command
> is real and runnable; the target you would run them against is your own.

## The question

> "I have a ROM. I want to build my own game engine that plays it."

The temptation is to start writing an emulator. The right first move is to
establish what the ROM is doing, because an emulator that does not match the
original is a second project, not a reimplementation.

## The ladder, applied

```
ROM
 ↓  what is it?
identification and triage
 ↓  what can it run?
architecture, memory map
 ↓  what runs when?
entry point and frame loop
 ↓  what changes?
state blocks and writers
 ↓  what does that mean?
semantic model
 ↓  what does the player experience?
behavioural model
 ↓  can I write it?
subsystem by subsystem
 ↓  is it right?
differential test
 ↓  elsewhere?
port
```

## 1. Triage

```sh
scripts/universal-dump.py ./game.rom -o dump/
```

```
target : game.rom
type   : unknown

FILES
  by format : unknown=1
  unidentified : 1
  size : 32768

coverage
  files string-scanned : 0
  note: the file is not recognised by content, so nothing deeper was
        attempted
```

The dump says what it can and stops. That is correct behaviour: it identified
nothing, so it claims nothing.

Identify by content, not by the `.rom` extension:

```sh
xxd -l 64 ./game.rom
```

```
00000000: 4e45 53da 0000 0002 524f 4d00 0000 0040  ....RS..ROM..@+
```

Header vector at offset 0 is `da 52` little-endian → reset vector `0x52DA`.
Vector table at 0x40. This is a 6502-family ROM: 16-bit addresses, a reset and
IRQ vector table, banked or fixed memory at 0x8000.

`classify_blob` said `unknown-high-entropy`. Look at why, rather than trusting
the label:

```sh
python3 -c "
data = open('game.rom','rb').read()
print('total size', len(data))
print('entropy', __import__('math').log2(256) - 0)
import collections
c = collections.Counter(data)
import math
h = -sum(v/len(data) * math.log2(v/len(data)) for v in c.values())
print(f'entropy {h:.2f}')
for lo, hi, name in ((0x0000,0x4000,'vectors'), (0x4000,0x6000,'text'),
                     (0x6000,0x8000,'data'), (0x8000,0xC000,'chardata')):
    if hi <= len(data):
        seg = data[lo:hi]
        cc = collections.Counter(seg)
        hh = -sum(v/len(seg)*math.log2(v/len(seg)) for v in cc.values())
        print(f'  0x{lo:04x}-0x{hi:04x} {name:9} entropy {hh:.2f}')
"
```

```
total size 32768
entropy 5.61
  0x0000-0x4000 vectors     entropy 1.12
  0x4000-0x6000 text        entropy 6.34
  0x6000-0x8000 data        entropy 5.02
  0x8000-0xC000 chardata    entropy 7.21
```

Whole-file entropy of 5.61 is unremarkable. One region at 7.21 is high, and
the text region at 6.34 is normal for code. So: code and data are visible, and
`0x8000..0xC000` is compressed or encoded. That is a *hypothesis* about one
region, not a claim about the ROM.

## 2. Memory map

```
0x0000-0x00FF  zero page (256 bytes of RAM)
0x0100-0x01FF  stack
0x0200-0x7FFF  work RAM
0x8000-0xFFFF  ROM
```

Observed: the vectors point into `0x8000` and above. Everything below is RAM.

Find the frame loop — the single most valuable thing in a ROM:

```sh
# reset vector, then follow the call graph to the innermost loop
python3 -c "
import struct
d = open('game.rom','rb').read()
print('reset  0x%04X' % struct.unpack_from('<H', d, 0)[0])
print('irq    0x%04X' % struct.unpack_from('<H', d, 0x8000-0x8000+0xFFFE-0x8000)[0]
      if False else 'irq    (from the header table)')
"
```

```
reset  0x52DA
```

```sh
xxd -s $((0x52DA - 0x8000)) -l 64 ./game.rom
```

```
000052da: a9 01 8d 00 02 4c 8e 86 a9 ff 8d 00 02 60
```

`LDA #$01 / STA $0200` sets a flag, then `JMP $868E`. That is the reset
routine: set a state byte, jump into the dispatcher at 0x868E. So `$0200` is
likely the current state — one of the first semantic findings.

`0x868E` is the dispatcher. Read it:

```sh
xxd -s $((0x868E - 0x8000)) -l 96 ./game.rom
```

```
0000868e: ad 00 02 85 01 aa 8a 20 5a 87 a5 00 4c a9 86
0000869e: a9 ff 85 00 8d 00 02 a9 00 85 01 a0 12 bd 00 03
```

`LDA $0200 / STA $01 / TAX / TXA / JSR $875A` — dispatch on the state byte via
a computed jump. **That is a state machine, observed**, the same evidence a
`cmp`/`beq` chain would give but more compactly.

## 3. The state machine

Drive it. Since this is synthetic, the "drive it" step is a scripted trace,
but on a real ROM it is the same method: put it in each state, apply one
input, record the next state.

```
state  $0200   meaning (hypothesis)          evidence
0      0x00    title / idle                  resets to 0 on frame end
1      0x01    gameplay                      set by reset
2      0x02    (unreached)                   never observed in 400 frames
3      0x03    (unreached)                   never observed in 400 frames
```

Two of four states were never reached. That is a real limitation, and it
matters: a reimplementation that handles only states 0 and 1 will fail the
moment someone finds 2. Record it rather than treating the machine as closed.

```
hypothesis: a four-state machine, of which two states are unreached
status:     partially-reconstructed
confidence: medium
next_test:  find the writes to $0200 other than the dispatcher; state 2 and
            3 may be reachable from a path the traced input does not take
```

## 4. Player state

The interesting block is `0x0300` in zero page / RAM.

```sh
scripts/strings-map.py ./game.rom --xrefs --search "player"   # if any
xxd -s $((0x0300)) -l 64 ./game.rom
```

```
00000300: 50 01 00 00 a8 00 20 01 b0 00 80 00 00 00 00 00
```

```
offset  value  access evidence                          candidate
0x0300  0x01   written at reset, read by the dispatcher  player state
0x0301  0x50   read when rendering                      screen X (80 wide)
0x0304  0x01   read each frame                          frame counter
0x0306  0xa8   written each frame, mirrors 0x0308        previous X
```

`0x50 = 80` on an 80-column screen is a strong fit, and it is a *fit*: it is
consistent with a screen coordinate and with a palette index. Confirm it by
changing the value and observing the sprite:

```
set $0301 = 0x10 (16) -> the sprite moves left by 64 pixels
set $0301 = 0x50 (80) -> the sprite is at the right edge
```

Now it is established. That is the shape of the work: a candidate from the
data, a prediction, a test.

## 5. Physics

The player Y position and velocity, from the gameplay state handler:

```sh
xxd -s $((0x8700 - 0x8000)) -l 96 ./game.rom
```

```
00008700: a5 04 18 69 01 85 04 a5 06 18 65 01 85 06 a5 0a
00008710: 18 6a 01 85 0a 38 85 0a f0 06 a9 00 85 0a a5 06
```

`LDA $04 / CLC / ADC #$01 / STA $04` — add one to the low byte. `LDA $06 /
CMP #$01 / BCC` — compare against 1 and branch.

That is fixed-point arithmetic with a wrap at 1. Very likely a 8.8 fractional
accumulator with a sign bit, or a timer.

**Recover the scale by prediction, not by fitting.** That matters here more
than anywhere, because legacy code is full of fixed-point fields and the scale
is the first thing to get wrong.

```
candidate: $04/$05 is an 8.8 fixed-point X position
test: drive the player to a known screen column and read the raw value
      at column 0x28 (40):
        if scale 256: raw should be 40*256 = 10240 = 0x2800
        if scale 16:  raw should be 40*16  = 640  = 0x0280
observed at column 40: $05 = 0x28, $04 = 0x00
```

The high byte is the column and the low byte is 0. So the high byte is the
integer part and the low byte is the fraction: scale 256, 8.8 fixed-point.
Established by a prediction that would have been wrong under the other
reading.

Now the wrap at `$06`:

```
$CMP #$01 / BCC skip  ->  when $06 >= 1, reset it to 0
```

So `$06` is a counter bounded at 1, used as a "every other frame" flag, or a
one-shot latch. Test it:

```
set $06 = 0, run 1 frame -> $06 stays 0
set $06 = 1, run 1 frame -> $06 becomes 0
```

A latch that clears itself when set and is otherwise never modified. That is
a frame-parity or a one-shot. The model records the *behaviour* (self-clearing
latch) and both candidate purposes as hypotheses, because behaviour is what you
reimplement.

## 6. The compressed region

`0x8000..0xC000` at entropy 7.21. Reconstruct it as a format before
reimplementing whatever reads it.

```sh
python3 - <<'PY'
d = open("game.rom","rb").read()
seg = d[0x8000:0xC000]
print("magic:", seg[:4].hex(), repr(seg[:4]))
for name, magic in (("RLE", b"\x00"), ("LZSS", b"\x5a"), ("plain", None)):
    if magic and seg[:1] == magic:
        print("candidate:", name)
print("first 32 bytes:", seg[:32].hex())
# look for a repeating stride
for stride in (16, 24, 32, 64):
    same = sum(1 for i in range(0, len(seg)-stride, stride)
               if seg[i:i+4] == seg[i+stride:i+stride+4])
    if same > len(seg) // stride // 2:
        print(f"repeating 4-byte groups at stride {stride}")
PY
```

```
magic: 5a4c 0090
candidate: LZSS
first 32 bytes: 5a4c0090 00010203 04050607 08090a0b 0c0d0e0f
```

`5a 4c` — "ZL", the LZSS magic. And the following bytes are `00 01 02 03
04 05 06 07`, which is a compression failure: a well-compressed block does not
decompress to a run of consecutive integers. So the magic is present but the
payload is not plain LZSS.

That is worth stopping on. Either the magic is a coincidence, or the format is
LZSS-shaped but different, or the region is not data at all.

```
classification: magic present, structure does not match the named format
status:          unknown
confidence:      low
next_test:       try LZSS at other offsets; look for a header before the magic;
                 check whether this region is code rather than data
```

An unrecognised format that stays `unknown` is a better outcome than a decoder
that produces plausible garbage. The `scripts/universal-dump.py` run on the
extracted region keeps this visible:

```sh
scripts/universal-dump.py ./region.bin -o dump-region/
```

## 7. The model

What is established, and what is not:

```markdown
### Established (traced or predicted-and-confirmed)

- 6502-family, 16-bit addresses, ROM at 0x8000
- reset at 0x52DA sets $0200 = 1 and dispatches
- $0200 is a state byte, dispatched at 0x868E by computed jump
- 4 states exist in the dispatch table; 2 were reached in 400 frames
- $0301/$0302 are an 8.8 fixed-point X position; high byte is the screen
  column, confirmed by driving the sprite to columns 16 and 80
- $0306 is a self-clearing latch, cleared when set
- $04/$06 accumulate per frame with a self-clearing latch at 1

### Hypotheses

- $0200 = 0 is a title/idle state (medium)
- the two unreached states are reachable from an untested input path (medium)
- $06 is a frame-parity flag rather than a one-shot (low)

### Not established

- the purpose of the high-entropy region at 0x8000-0xC000
- whether $0301 is X and $0302 is Y, or a different arrangement
- the format of the dispatch table beyond the four entries
```

## 8. Implement a subsystem

Not an emulator. The player-physics subsystem, written from the model:

```c
/* Player physics, reconstructed from the 6502 routine at 0x8700.
 *
 * Established: an 8.8 fixed-point position; a self-clearing latch that is
 * cleared when set; a per-frame accumulate. Hypothesised: that the latch is
 * frame parity. That hypothesis is not encoded here, because the
 * reconstructed behaviour does not depend on it.
 *
 * Layout: position x at 0x01/0x02 (high/low), y at 0x03/0x04, latch at 0x06.
 */
#include <stdint.h>

typedef uint16_t fixed8_8;   /* 8.8 fixed point, scale 256 */

typedef struct {
    fixed8_8 x;
    fixed8_8 y;
    uint8_t  latch;
} player_state;

void player_step(player_state *p, int input_dx, int input_dy)
{
    /* The original adds the input each frame with no per-frame clamp;
     * clamping is applied elsewhere (not yet reconstructed). */
    p->x = (fixed8_8)(p->x + (fixed8_8)(input_dx << 8));
    p->y = (fixed8_8)(p->y + (fixed8_8)(input_dy << 8));

    /* The latch clears itself when set: observed, tested by setting it to 1
     * and observing it return to 0 on the next frame. Whether it is frame
     * parity is unestablished and deliberately not encoded. */
    if (p->latch >= 1) {
        p->latch = 0;
    }
}
```

Two comments carry the honesty of this file: the clamp is elsewhere and not
reconstructed, and the latch's purpose is unestablished.

## 9. Differentially test

The hard part of a legacy target is the harness. Build one that runs both and
captures comparable state:

```sh
# the original: an emulator harness you wrote, reading zero-page RAM
./emu-harness ./game.rom --watch 0x0300:2 0x0301:2 0x0306:1 \
    --input inputs/walk-right.bin --frames 600 --out frames/original.json

# the reimplementation, same input, same frame count
./reimpl-harness --input inputs/walk-right.bin --frames 600 \
    --out frames/reimpl.json

scripts/state-diff.py frames/original.json frames/reimpl.json --all-elements
```

```
first divergent element: 41   (1 field)
  0x0306
      original      : 0
      reimpl        : 1
```

A divergence in the latch at frame 41, not a position error. That is a
different subsystem from the one you thought you were testing, and the
element-wise comparison found it immediately.

The cause: the original's latch is cleared by a routine this subsystem does
not include, and the reimplementation clears it only when it is set. The
model recorded the latch's behaviour as "cleared when set" — which was true
of the observations and incomplete, because it did not describe the clear path.

```
model correction: the latch is cleared every frame, not only when set
status:  refuted and replaced
next_test: set the latch from the harness and observe the frame at which it
           clears, with the physics step not running
```

That is the loop working as intended. The divergence corrected a model claim,
and the correction is now testable independently.

## 10. What this example shows

- the high-entropy region stayed `unknown` instead of getting a decoder
- two of four states were never reached, and that is recorded as a risk
- the fixed-point scale was recovered by a prediction, not a fit
- one hypothesis is deliberately not encoded in the code
- the differential test found a divergence in a subsystem that was not the
  target, and corrected a model claim

The discipline, at the scale where it matters most: **a ROM is not understood
because you have written a disassembler for it. It is understood when every
claim you act on has a test behind it — and the claims you could not test are
written down as untested rather than quietly assumed.**