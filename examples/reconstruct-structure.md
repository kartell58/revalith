# Example: reconstruct a data structure

Recovering a layout and, separately, what the fields mean.

> Target data is **synthetic**. Commands are real and runnable.

## The starting point

> "Something is a 16-byte block at 0x4310 and 0x4320. Three functions touch
> it. What is it?"

No name, no type, no clues — just a page address and some traffic.

## Establish the size first

```sh
scripts/find-xrefs.py ./game.bin --addr 0x4310 --containing-funcs
```

```
0x4310 referenced by 11 instruction(s), 0x4320 by 9
  pages are indexed: ldx #$20, ldy #$30, ...
```

`LDX #$20` and `LDY #$30` suggest pages at 0x20-byte strides: 0x4310, 0x4320,
0x4330. Check what lies between 0x4310 and 0x4320.

```sh
xxd -s 0x4310 -l 0x40 ./game.bin
```

```
00004310: 2a00 4000 0100 1200 2a00 4100 0100 1300
00004320: 0500 3f00 0200 1400 0500 3e00 0200 1500
```

Sixteen bytes per page, two pages adjacent. The size is established by the
stride and by which offsets are touched — not by the name.

## Collect every access

This is the whole job, and it is mechanical. For each function, every load and
store, with the offset, the width and the direction:

```sh
objdump -d ./game.bin | grep -E '\$431[0-9a-f]|\$432[0-9a-f]'
```

```
0x8100: lda  $4310      ; read  byte  +0
0x8103: clc
0x8104: adc  $4312      ; read  byte  +2
0x8107: sta  $4314      ; write byte  +4
0x8120: ldy  $10
0x8122: lda  $4310,x    ; read  byte  +0
0x8140: sta  $4316,x    ; write byte  +6
0x8160: lda  $4311,x    ; read  byte  +1
0x8170: sta  $4318,x    ; write byte  +8
0x8190: lda  $4314,x    ; read  byte  +4
0x81A0: sta  $431A,x    ; write byte +10
0x81B0: lda  $4310,x    ; read  byte  +0
0x81B2: cmp  #$40       ; compared against 0x40
```

Tabulate by offset:

| offset | width | reads | writes | other evidence |
| --- | --- | --- | --- | --- |
| +0 | 1 | 3 | 0 | added to +2, result stored at +4 |
| +1 | 1 | 1 | 0 | stored at +8 |
| +2 | 1 | 2 | 0 | added to +0; written by a caller; compared against 0x40 |
| +4 | 1 | 1 | 1 | the sum of +0 and +2 |
| +6 | 1 | 0 | 1 | written by the caller at 0x8140 |
| +8 | 1 | 0 | 1 | mirrors +1 |
| +10 | 1 | 0 | 1 | mirrors +4 |

That table is observed fact. Everything below it is interpretation.

## Propose a layout, keeping meaning separate

```
offset  size  access evidence                            candidate
0x00    1     read; added to +2; sum stored at +4         accumulator
0x01    1     read; mirrored to +8                        counter
0x02    1     read; added to +0; clamped at 0x40          increment
0x04    1     written as the sum of +0 and +2             last_sum
0x06    1     written by the caller only                  caller_flag
0x08    1     mirror of +1                                counter_shadow
0x0A    1     mirror of +4                                last_sum_shadow
```

"candidate" is doing real work in that column. Each entry is a reading of the
access pattern, not a finding.

Note what the widths support and what they rule out. Every field is a byte, so
no 16- or 32-bit value is stored here — anything wider lives elsewhere. That
rules out a whole class of interpretation before any naming happens.

## Test the relationships

Two fields mirroring two others is a strong, testable claim.

```sh
# breakpoint after 0x8170 and after 0x81A0, compare the pairs
```

```
after 0x8170:  +1=0x07  +8=0x07
after 0x81A0:  +4=0x0A  +10=0x0A

drive +1 past 0xFF:
  +1=0x00  +8=0xFF   <-- mirror broken
```

The mirror is not a mirror. +8 and +10 are lags: they hold the *previous*
value. That is a different mechanism entirely, and it is only visible because
the wrap case was tested.

```
+8  = previous +1
+10 = previous +4
status: reconstructed    confidence: high
next_test: confirm the lag is exactly one frame and not one update call
```

## Name what the evidence supports

The accumulator relationship (+2 into +0, sum to +4, clamp at 0x40) is
established. What the page *is* is not.

```
entity_page
  +0   accumulator   byte   high    "added to +2; sum stored at +4"
  +1   counter       byte   medium  "read once; previous value at +8"
  +2   increment     byte   high    "added to +0; caller-supplied; clamps at 0x40"
  +4   last_sum      byte   high    "written as the sum of +0 and +2"
  +6   caller_flag   byte   low     "written by 0x8140; purpose unknown"
  +8   counter_prev  byte   high    "previous value of +1; confirmed across wrap"
  +0A  sum_prev      byte   high    "previous value of +4"
```

`entity_page` is a placeholder with a role, not a domain claim. That is
deliberate: the page could be a player, a timer, or a projectile, and the
layout is the same either way.

## What the offsets do not tell you

Three things worth writing down, because their absence is easy to mistake for
a settled answer:

- **The size is 16 bytes by inference.** Two pages are adjacent and no
  function touches beyond +0x0A. A 17th byte may exist and be unused. Write
  `"size": 16, "size_basis": "no access beyond +0x0A; not confirmed"`.
- **+6 has no interpretation.** One writer, no reader observed. `"meaning":
  null` is the right entry, and it is better than a guess.
- **Whether +8/+10 are frame lags or call lags is open.** Both fit the data so
  far.

## Record it

```sh
scripts/recon-ledger.py add ./reconstruction structures entity_page \
    --evidence "16-byte stride: pages at 0x4310, 0x4320, 0x4330" \
    --evidence "+0 added to +2, sum stored at +4 (0x8120)" \
    --evidence "+2 written by the caller at 0xC402, clamped at 0x40" \
    --evidence "+8 holds the previous +1; confirmed across a wrap at 0xFF" \
    --evidence "+10 holds the previous +4" \
    --evidence "no access beyond +0x0A in any of the 11 referencing functions" \
    --observed-behavior "a per-page accumulator with a caller-supplied increment and a bounded range" \
    --hypothesis "a fixed-size per-entity state page" \
    --next-test "confirm whether +8/+10 lag by one frame or one call" \
    --status partially-reconstructed --confidence medium \
    --related-functions 0x8120
```

`partially-reconstructed` at `medium` is the correct status: the layout is
reconstructed, two fields are not, and one relationship is untested.

## Implement from the layout

```c
/* Layout reconstructed from 11 referencing functions. Field meanings for
 * +0, +2, +4, +8, +0A are established; +6 is unknown and unused here. */
typedef struct {
    uint8_t accumulator;    /* +0  added to +2; sum stored at +4 */
    uint8_t counter;        /* +1  */
    uint8_t increment;      /* +2  caller-supplied, clamps at 0x40 */
    uint8_t last_sum;       /* +4  */
    uint8_t caller_flag;    /* +6  purpose unknown; not used */
    uint8_t counter_prev;   /* +8  previous value of +1 */
    uint8_t sum_prev;       /* +0A previous value of +4 */
    uint8_t pad[5];         /* +0B..+0F never observed; assumed, not known */
} entity_page;
```

The trailing `pad[5]` deserves comment, because it is the honest part: the
stride is 16 but nothing proved bytes `+0B..+0F` exist. A reimplementation that
allocates 16 bytes when the original allocated 12 is harmless here and fatal
where a layout is externally visible.

## Verify against the original

If the page is written to a save file, the layout is observable and the test
is direct:

```sh
scripts/state-diff.py original-page.json reimpl-page.json
```

If it is not externally visible, say so and do not imply the test ran. The
reconstructed layout is then evidence-based but unverified against a
specification, and `verified` would be a claim you cannot support.

## What this example shows

- the size came from a stride, not from a name
- field meanings were kept separate from the access evidence that produced them
- one relationship was wrong until the wrap case was tested
- one field is left as `null` rather than guessed
- padding is annotated as assumed

The discipline in one line: **recover the layout from access patterns, test
the relationships at their boundaries, and keep every interpretation labelled
as an interpretation.**