# Known offsets

Structures recovered from this target, with the evidence behind each field.

Structures shift between versions. **Always record which version an offset was
derived from.** An offset without a version is worse than no offset, because
it will be trusted where it no longer holds.

An unverified field is better than an invented one. Write `unknown` rather
than guessing a semantic name.

## Naming rule

Name a field only when a test supports the name. Otherwise use the offset:

```c
struct Player {          // derived from v1.4.2, 2026-03-11
    +0x00 void *unknown;     // memcpy src in sub_4a1230
    +0x08 int32_t  unknown;  // compared against 0..1000 in sub_4a1300
    +0x0c int32_t  unknown;  // written once at init only
};
```

## Structures

<!-- Add structures below this line. -->

### Player

Derived from: libfoo.so v1.4.2 (sha256:…)
Derived on:  YYYY-MM-DD

| Offset | Size | Proposed type | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| +0x00 | 8 | pointer | passed as `src` to memcpy in sub_4a1230 | high |
| +0x08 | 4 | int32 | compared against 0..1000 in sub_4a1300 | medium |
| +0x0c | 4 | unknown | written once during init, never in hot path | low |

Still unknown: the meaning of every field; whether the struct is larger than
0x10 bytes (no access past +0x0c was observed).
Not re-verified against: v1.5.0.

### *(structure name)*

Derived from: <file and version>
Derived on:  YYYY-MM-DD

| Offset | Size | Proposed type | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| | | | | |

Still unknown:
Not re-verified against:

## Version comparison

| Structure | v1.4.2 | v1.5.0 | Changed? |
| --- | --- | --- | --- |
| Player | derived above | not re-derived | unknown |

Record when an offset *moves* between versions — that is the single most
common cause of a misread structure, and it is cheap to check.

## Verification notes

How each field was established, and what would falsify it:

- **+0x00 pointer** — verified by tracing the argument at runtime and observing
  a valid mapped address in all 5 observed calls. Falsified by a call with a
  non-pointer value there.
- **+0x08 int32** — inferred from comparison bounds only. Falsified by a value
  outside 0..1000 being accepted, or by a fractional value appearing.