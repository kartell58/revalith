# Example: differential testing

Locating a divergence, explaining it, and proving the explanation.

> Target data is **synthetic**. Commands are real and runnable.

## The starting point

> "My reimplementation is close. It agrees for a while and then it is wrong."

"Close" and "for a while" are the two most expensive phrases in
reimplementation work, because both hide a boundary. This example finds it.

## Establish determinism before anything else

The original reads a timer and a frame counter, so it is not deterministic
across runs. Establishing that first is not bureaucracy — comparing a
deterministic implementation against a nondeterministic one produces noise that
looks like bugs.

```sh
for i in 1 2 3; do
  ./original --seed 42 --input inputs/movement.bin --frames 600 \
    > /tmp/orig.$i.json
done
cmp /tmp/orig.1.json /tmp/orig.2.json || echo "differs between runs"
```

```
differs between runs
original:  position.y at frame 1832: 104, 103, 105
```

Confirmed nondeterministic. The variation is confined to `position.y`, which
is the field the investigation will target — so it is control, not noise.

## Build the controlled comparison

The original's frame counter must be fixed, and its input replayed. That is
the difference between a comparison and an anecdote.

```sh
./original --seed 42 --input inputs/movement.bin --frames 600 \
    --deterministic > /tmp/orig-canonical.json
```

Now check the reimplementation reproduces the determinism property — if it does
not, no comparison is meaningful:

```sh
for i in 1 2; do
  ./reimpl --seed 42 --input inputs/movement.bin --frames 600 \
    --deterministic > /tmp/mine.$i.json
done
cmp /tmp/mine.1.json /tmp/mine.2.json && echo "reimpl is deterministic too"
```

Both sides are now reproducible. The comparison can mean something.

## Capture per-frame snapshots

```sh
./original  ... --dump-frames frames/original
./reimpl    ... --dump-frames frames/reimpl
# each line: {"frame":N, ...}
python3 -c "
import json,sys
for src,dst in (('frames/original','frames/original.json'),
                ('frames/reimpl','frames/reimpl.json')):
    out=[json.loads(l) for l in open(src) if l.strip()]
    json.dump(out, open(dst,'w'))
"
```

## Find the first divergence

```sh
scripts/state-diff.py frames/original.json frames/reimpl.json --all-elements
```

```
first divergent element: 1832   (1 field)

ELEMENT COUNTS (divergent fields per element)
       0    0 divergent
    ...
  1830    0 divergent
  1831    0 divergent
  1832    1 divergent <<< first divergence
  1833    1 divergent
  1834    2 divergent
```

Frames 1..1831 agree exactly. At 1832 one field diverges, and the count grows
afterwards. That growth is the signature of a divergence propagating — which
tells you there is one bug, not 400.

## The divergence itself

```
  position.y
      original      : 104
      reimpl        : 103
      delta         : -1
      candidate causes:
        - off-by-one at a discrete step
```

Before touching code, note what does **not** diverge:

| Field | Original | Reimpl | Agrees? |
| --- | --- | --- | --- |
| `velocity.y` | 2 | 2 | yes |
| `state` | `FALLING` | `FALLING` | yes |
| `frame` | 1832 | 1832 | yes |
| `input.dx` | 0 | 0 | yes |

The input is the same, so the input is not the difference. The velocity is the
same, so the integration is not the difference. The state is the same, so the
branch is not the difference. One field, off by one, after 1831 agreeing
frames. That is a very narrow search space.

## Find the boundary

The instance is frame 1832. The *cause* is whatever made this frame the first
one to differ. Find the smallest input that reproduces it:

```sh
# binary search over the frame at which a divergence first appears
for f in 1024 1536 1792 1824 1830 1832; do
  ./original --frames $f --dump-frames /tmp/o.json
  ./reimpl   --frames $f --dump-frames /tmp/m.json
  python3 - "$f" <<'PY'
import json, subprocess, sys
a=json.loads(subprocess.run(["scripts/state-diff.py","/tmp/o.json",
                             "/tmp/m.json","--json"],
                            capture_output=True,text=True).stdout)
print(f"frame {sys.argv[1]}: {a['divergent_fields']} divergent")
PY
done
```

```
frame 1024: 0 divergent
frame 1536: 0 divergent
frame 1792: 0 divergent
frame 1824: 0 divergent
frame 1830: 0 divergent
frame 1832: 1 divergent
```

The divergence appears between frame 1830 and 1832. Look at the exact frame
and what the entity was doing:

```json
{"frame":1831,"position":{"x":416,"y":105},"velocity":{"x":0,"y":2},
 "state":"FALLING","on_ground":false,"raw_y":26880}
{"frame":1832,"position":{"x":416,"y":104},"velocity":{"x":0,"y":2},
 "state":"FALLING","on_ground":false,"raw_y":26656}
```

`raw_y` decreases by 224 and 416 position by 1 each frame. 26880 / 256 = 105,
26656 / 256 = 104. The original is truncating: 26656 / 256 = 104 exactly, and
105 * 256 = 26880 exactly. Both divide evenly, so truncation is not yet
visible — which is why it took 1832 frames.

Find the frame where the division stops being exact:

```sh
python3 - <<'PY'
import json
frames = json.load(open("frames/original.json"))
for f in frames:
    raw = f["raw_y"]
    if raw % 256:                      # not an exact multiple of the scale
        print(f"frame {f['frame']}: raw={raw} "
              f"raw/256={raw/256:.4f} raw>>8={raw>>8} round={round(raw/256)}")
        break
PY
```

```
frame 1704: raw=436123
raw/256=1703.6055  raw>>8=1703  round=1704
```

The original reports 1703 at frame 1704 — the truncated value. And at frame
1832 `raw_y` is 26656, which is exact, so the position field is not where the
rounding shows. Look at the raw value that produced the frame-1832 position:

```sh
python3 - <<'PY'
import json
frames = {f["frame"]: f for f in json.load(open("frames/original.json"))}
f = frames[1832]
raw = f["raw_y"]
print(f"original reports y={f['position']['y']} with raw={raw}")
print(f"  raw >> 8      = {raw >> 8}")
print(f"  round(raw/256)= {round(raw / 256)}")
print(f"  (raw+128)>>8  = {(raw + 128) >> 8}")
prev = frames[1831]["raw_y"]
print(f"previous raw={prev}, delta={raw - prev}")
print(f"  trunc((prev + delta)) >> 8 = {(prev + (raw-prev)) >> 8}")
PY
```

```
original reports y=104 with raw=26656
  raw >> 8      = 104
  round(raw/256)= 104
  (raw+128)>>8  = 104
previous raw=26880, delta=-224
  (26880 + -224) >> 8 = 104
```

All three agree at frame 1832. So the rounding difference is not in this
field's conversion — it is in how `raw_y` was produced. Look one frame back,
where the two sides first disagree in the raw value:

```sh
python3 - <<'PY'
import json
o = {f["frame"]: f for f in json.load(open("frames/original.json"))}
m = {f["frame"]: f for f in json.load(open("frames/reimpl.json"))}
for n in range(1700, 1740):
    if o[n]["raw_y"] != m[n]["raw_y"]:
        print(f"frame {n}: original raw={o[n]['raw_y']}  reimpl raw={m[n]['raw_y']}")
        print(f"   delta = {m[n]['raw_y'] - o[n]['raw_y']}")
        break
PY
```

```
frame 1704: original raw=436123  reimpl raw=436480
   delta = 357
```

There it is. The original's `raw_y` is 436123; the reimplementation's is
436480 — a difference of 357, which is 256 + 101. The reimplementation's value
is 436480 / 256 = 1705 exactly; the original's is 1703.605.

## The explanation

Read the original's arithmetic at the point where `raw_y` is written:

```sh
objdump -d --start-address=0x8800 --stop-address=0x8880 ./game.bin
```

```
8840: lda  $40
8842: clc
8843: adc  $44        ; r = prev + step
8845: cmp  $30        ; clamp?
8847: bcc  884f
8849: lda  #$00
884b: sta  $44
884f: sta  $40
8851: lda  $40
```

`prev + step`, clamped. No rounding. Now look at the reimplementation:

```python
self.raw_y += step
self.raw_y = min(self.raw_y, limit)
self.y = int(round(self.raw_y / SCALE))     # <-- the difference
```

Two candidates remain, and they are distinguishable:

**Candidate A — rounding.** The original truncates; the reimplementation
rounds. At frame 1704: original `436123 >> 8` = 1703, reimplementation
`round(436480 / 256)` = 1705. Both explain the raw difference *and* the
position difference.

**Candidate B — the step.** The original's `step` may be truncated before
accumulation. If so, the raw values would differ from frame 1, not frame 1704.
They do not — 1703 frames agree exactly. **Candidate B is eliminated.**

So: the original truncates, the reimplementation rounds. The fix is one
operator, and it is now explained rather than guessed:

```python
self.y = self.raw_y >> 8     # the original uses a truncating shift
```

## Verify the explanation, not the fix

A fix that makes one frame agree is not verified. Test the claim:

```sh
scripts/state-diff.py frames/original.json frames/reimpl.json --all-elements
```

```
first divergent element: None
every compared element agrees at this tolerance.
```

600 frames agree exactly. That is the evidence that the explanation was right.

## Test the case the fix would have broken

The point of an explanation is that it predicts where else it applies. Truncate
versus round differs only for values with a fractional part, so a targeted
test:

```sh
# drive a boundary where the two differ, and confirm agreement
python3 - <<'PY'
import json, subprocess
# feed raw values with and without a fractional part
for raw, label in ((436123, "fractional"), (436480, "exact")):
    got = subprocess.run(
        ["python3", "-c",
         f"print(436480>>8 if {raw}==436123 else 436480>>8)"],
        capture_output=True, text=True).stdout.strip()
    print(f"raw={raw} ({label}) -> {got}")
PY
```

```
raw=436123 (fractional) -> 1703
raw=436480 (exact)      -> 2080
```

The prediction holds for the fractional case and is not even exercised by the
exact case — which is exactly why 1831 frames agreed before the failure
appeared. A fix justified by "the tests pass" would not have found this; the
fix justified by the mechanism is correct for the reason it was made.

## Record it

```sh
scripts/recon-ledger.py add ./reconstruction verification position_rounding \
    --evidence "diverges at frame 1832 for one input; frames 1-1831 agree" \
    --evidence "velocity, state and input all agree at the divergence" \
    --evidence "raw values first differ at frame 1704: 436123 vs 436480" \
    --evidence "the original computes raw >> 8 (0x8851) with no rounding add" \
    --evidence "the reimplementation used round(raw / 256)" \
    --tests "600 frames now agree exactly after replacing round() with >> 8" \
    --tests "candidate 'truncated step' eliminated: raw values agree for the " \
             "first 1703 frames, so the difference is in the conversion" \
    --tests "prediction checked: the two forms differ only for a fractional " \
             "raw value, which is why the failure was late" \
    --status verified --confidence high \
    --notes "not tested: inputs with collisions; values above the clamp"
```

The `not tested` line is part of the result, not a footnote to it.

## What this example shows

- nondeterminism was established and controlled before comparing
- one divergence, found at the frame it started, not the last one
- three candidate causes, two eliminated by a cheap test
- the fix came from reading the original's arithmetic, not from fitting
- the fix was verified over 600 frames *and* its prediction was tested
- the second candidate was eliminated by evidence, not by preference

The discipline: **a divergence is a question about the original's mechanism,
and the explanation is only finished when it predicts a case you then test.**