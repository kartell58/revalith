# Investigation state

Long-running investigations fail in a specific way: the same hypothesis gets
re-tested three weeks later because nobody recorded that it was already
refuted. This reference is about keeping state that prevents that.

## The problem

Without a record, an agent re-derives from scratch:

```
session 1: hypothesis "payload uses LZ4" -> tested -> refuted
session 2: hypothesis "payload uses LZ4" -> tested -> refuted   (again)
session 3: 30 minutes wasted on a settled question
```

The waste compounds across a large target: hundreds of small refutations,
each cheap individually, add up to a day of redundant work.

## The state directory

Copy the templates from `templates/project-state/` into the project being
investigated:

```sh
cp -r ~/.config/opencode/skills/revalith/templates/project-state/ \
   ./project-state/
```

| File | Holds |
| --- | --- |
| `dead-ends.md` | hypotheses already refuted, with what was tried |
| `known-formats.md` | container and file formats already decoded |
| `known-offsets.md` | structure offsets and their evidence |
| `known-protocols.md` | protocol fields, framing, state machines |
| `hypotheses.md` | live hypotheses, their status and next test |

These are working notes for the investigation, not deliverables. They exist to
be read by the next session, including one that is not you.

## dead-ends.md — the important one

Record a refuted hypothesis *as soon as it is refuted*, with enough detail that
the next reader can tell the test was adequate.

```markdown
## LZ4 compression for the asset payload

Status:     refuted (2026-03-14)
Confidence: high — multiple independent decompressors rejected the data.

Hypothesis: payload is LZ4-compressed.

Tests performed:
  - `lz4 -d` on the payload at offset 0x1a40        -> bad magic
  - Python `lz4.frame.decompress()`                -> LZ4Error
  - checked for the LZ4 frame magic 0x184D2204      -> absent
  - checked for a raw LZ4 block header              -> absent
  - compared byte distribution against LZ4 output entropy (~6.9 bits)
                                                        -> measured 7.8

Conclusion: not LZ4 in either framing. The high entropy remains unexplained;
see hypotheses.md entry "high-entropy asset region".
```

The last line is the point: a refutation is not a dead end if it redirects the
question. The next step was recorded rather than lost.

## hypotheses.md — live status

```markdown
## Asset region at 0x1a40 is encrypted

Status:     open
Confidence: low

Evidence:
  - 4 KiB region with entropy 7.8, no known magic
  - byte distribution is flat (no obvious key-length periodicity)
  - region is referenced by exactly one function (sub_4a2010)

Hypothesis: the region is encrypted, with the key derived at runtime.

Next test: trace sub_4a2010 during startup and look for a key-sized
           buffer being written before the region is read.
```

`Status` is one of: `open`, `testing`, `confirmed`, `refuted`, `blocked`.
`blocked` is for a test that cannot be run in this environment, with the
precondition stated — so it is not silently retried either.

## known-formats.md

Record what has been decoded, with the decoder and any version assumption.
This stops a format being re-derived from scratch and stops a *different*
format being assumed to match.

```markdown
| Container | Location | Decoder | Notes |
| --- | --- | --- | --- |
| Package header | 0x0000-0x001f | manual, `known-offsets.md` | magic 0x5051474D |
| Asset table | 0x2000+ | custom TLV | entries are (tag u16, len u32) |
| Texture blob | assets/tex/* | `binwalk` marked data | DCT/blocks, not raw PNG |
```

## known-offsets.md

Structures shift between versions. Record the version each offset was derived
from, or the note is worthless next month.

```markdown
## Player (derived from v1.4.2, 2026-03-11)

| Offset | Size | Evidence | Confidence |
| --- | --- | --- | --- |
| +0x00 | 8 | passed to memcpy as src in sub_4a1230 | high — pointer |
| +0x08 | 4 | compared against 0..1000 range in sub_4a1300 | medium — integer |
| +0x0c | 4 | written once at init, never in hot path | low — guess |

Not re-verified against v1.5.0. Field semantics beyond +0x08 unknown.
```

The "not re-verified" line is load-bearing. It tells the next reader the
offsets may not hold.

## known-protocols.md

```markdown
## Session control channel

Framing:   4-byte big-endian total length at +0x00, including the 4-byte
           header. Confirmed on 40 captures (big-endian equals observed
           length; little-endian did not).
Fields:    +0x00 u32 total_length    confirmed
           +0x04 u16 message_type    confirmed (type 31 gates the
                                     "unauthorised" response)
           +0x06 u16 unknown         varies; does not affect dispatch
           +0x08 ...                payload; offsets not established
Dispatch:  jump table at 0xb000, 0x40 entries, branches to sub_401a20
           for type 31.
Unknown:   purpose of +0x06; no malformed-input testing performed.
```

## Reading state before working

The habit that matters: **read `dead-ends.md` before forming a hypothesis**.
It costs seconds and saves the re-test.

```sh
cat project-state/dead-ends.md | head -50
```

When a new refutation lands, write it immediately. A dead end recorded late is
a dead end retried.

## Keeping the state honest

- Date every entry. A refutation from three versions ago may be stale.
- Record the version the evidence came from.
- Prefer "refuted" with detail over silence. Silence loses the information.
- When a dead end is *reopened*, say why — new evidence, or a better test.
  A hypothesis rejected for a weak reason deserves another attempt.
- Delete entries that no longer apply rather than leaving them to mislead.

The state files are working notes. When the investigation concludes, the
durable output is the report; the state directory is scaffolding and can be
discarded.