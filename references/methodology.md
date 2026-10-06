# Methodology

The reasoning discipline behind every finding. Tool choice and format details
live in other references; this file is about *how to conclude*.

## The evidence loop

```
Observe  ->  Hypothesis  ->  Test  ->  Confirm / Refute  ->  Document
   ^                                                      |
   +-------------------- new evidence --------------------+
```

Every claim moves through all four stages. The loop is cheap to enter and
should be entered constantly: a dynamic trace that shows an unexpected
argument sends you back to static analysis of the caller, not to a conclusion.

### 1. Observation

Something directly present in the file or observable at runtime.

> The function at `0x401230` references the string `"login_failed"` at
> `0x404a10`, and `sub_4012a0` is its only caller.

Write it so a reader could re-derive it. "Looks like authentication" is a
hypothesis wearing an observation's clothes.

### 2. Hypothesis

An interpretation, still unconfirmed, that predicts something observable.

> If this handles login failures, it should execute only on failure, and
> trace coverage should differ between a successful and a failed login.

A hypothesis that cannot be tested is not useful. If you cannot describe the
test, you do not yet have a hypothesis.

### 3. Test

An action that could come out either way. Design it to be capable of
refutation.

Good: run the same flow twice, differing only in the credential, and compare
call counts at `0x401230`.

Useless: "read the code and confirm it authenticates" — a test that cannot
fail proves nothing.

### 4. Conclusion

Result plus confidence plus the limits of what you established.

> The function executes only on authentication failure, and its return value
> selects the error response. Confidence: **high** — consistent dynamic
> evidence across two flows, plus a caller-side branch on the return value.
> Field semantics inside the packet struct remain unknown.

## Confidence levels

Assign deliberately and justify.

| Level | Meaning | Typical basis |
| --- | --- | --- |
| `very low` | Speculation from naming or a single weak hint | Symbol name matches; string similarity only |
| `low` | Plausible, one indirect piece of evidence | Called by one function that seems related |
| `medium` | Multiple consistent hints, no runtime check | Several strings, caller/callee shape, data flow fits |
| `high` | Runtime evidence confirms it | Traced execution plus a controlled negative case |
| `very high` | Behaviour proven from both sides | Traced and reproduced from an independent implementation |

Two common failures:

- **Confident underdetermination.** A stripped binary with one suggestive
  string can feel conclusive while being pure guesswork.
- **Conflating binary and semantic difference.** Bytes changed, therefore
  behaviour changed. Not valid. See `binary-diff.md`.

Raise confidence only with evidence. Never to make a report read better.

## Distinguishing facts from interpretation

Keep them separate in every note, every commit message, every summary.

```
Evidence (observed):
  - references authentication-related strings
  - called by sub_4012a0
  - receives pointer Y
  - its return value is checked by the caller
  - dynamic tracing confirms execution during authentication

Hypothesis:
  - likely participates in authentication validation

Confidence: high
```

A single string reference justifies *none* of "this authenticates". The
strength of the evidence is the number and independence of the items, not
their vividness.

## Provenance and reproducibility

Record enough that someone else can redo the work and get the same answers.

```markdown
file    : libfoo.so
hash    : sha256:9f2c...           # always record this
version : 2.4.1 (from .rodata)      # or "unknown"
arch    : aarch64, little-endian, position-independent
tool    : objdump 2.44 (GNU Binutils)
command : objdump -d --no-show-raw-insn --start-address 0x2a4c0 ...
subject : sub_2a4c0, 0x2a4c0..0x2a5f8
test    : replayed capture #7 (packet 0x1f…), same binary, no ASLR offset applied
result  : returns 16 on capture #7; returns 0 on malformed length field
```

Hashes matter most when comparing versions: without them you cannot prove the
two files are the same build.

## Reporting findings

Use this shape consistently:

```markdown
## Finding

Function:    sub_4012a0

Hypothesis:  Parses a binary message header.

Evidence:
  - reads a 16-bit value at offset 0
  - reads a 32-bit length at offset 2
  - caller passes a packet buffer
  - return value is used as payload offset

Tests:
  - traced against 6 captured packets; offsets matched every observed header
  - truncated packet returns 0 without reading past the buffer

Conclusion: High confidence in the field layout; exact semantic names of the
fields remain unknown.

Notes:      Offset 4..7 unexplained. Not confirmed whether it is a checksum.
```

Sections that have no evidence say so. "Not investigated" is information;
a silently omitted section reads as "checked, nothing found".

## Choosing a name

The name is a claim. Make it no stronger than the evidence.

| Evidence | Defensible name |
| --- | --- |
| none | `sub_4012a0` |
| references `login_failed`, in the auth module | `handle_login_failure` |
| called with a packet buffer, reads a 4-byte header | `parse_header` |
| traced doing exactly that, on both valid and invalid input | `parse_header` + confirmed |
| also validates a signature token | `parse_header_and_validate_signature` |

Avoid stacking every plausible verb into a name. Long compound names hide how
much of each part is actually known.

## Choosing what to investigate

Start where evidence is cheapest and most discriminating:

1. **Entry points and exports** — someone decided these matter.
2. **Strings** — error messages are unusually informative; log format strings
   reveal data flow; protocol names localise a subsystem.
3. **Interesting imports** — `SSL_read`, `sendto`, `dlopen` locate subsystems.
4. **Cross-references** — one string shared by few functions localises fast.
5. **Callers of interesting callees** — the caller usually reveals intent.

Strings are **entry points, not evidence of purpose**. `"encrypt"` appears in
a function that logs an error about encryption; another function does the work.
Always walk string → referencing function → its callers and callees.

## Reasoning under limited evidence

When a technique cannot answer the question, say what is unknown and why.

Bad: "This appears to be a lock-free queue based on the atomic instructions."
Good: "Uses `ldxr`/`stxr` loops around the push. That is consistent with a
lock-free queue, but no contention test was run, so the intent is unconfirmed."

Legitimate answers: `unknown`, `insufficient evidence`, `not testable in this
environment`, `precondition not met (no symbols)`. These are conclusions.

A note that a technique was inapplicable saves the next person hours:

```
Technique attempted: Frida hook on sub_4012a0
Result:    unavailable — no frida-server, and ptrace_scope is restricted
Fallback:  static analysis only; return value semantics unconfirmed
```

## Cross-checking against an oracle

Ground truth, when available, ends the debate:

- **Source code** for the exact build.
- **A second implementation** of the same protocol (server, prior client).
- **Debug symbols or a `.debug` section** in a companion file.
- **Vendor documentation**, an SDK header, an IDL definition.
- **The runtime**, when it can be observed.

Prefer the oracle over inference every time. When no oracle exists, say so —
that is what makes the remaining uncertainty honest.

## Common failure modes

- **Anchoring.** Committing to the first plausible story. Actively look for the
  disconfirming case.
- **Recency.** Assuming the newest build's behaviour applies to the old one.
- **String worship.** Treating a nearby string as the function's purpose.
- **Assuming layout continuity.** Fields shift between versions; re-derive.
- **Trusting tool output blindly.** Symbol addresses, sizes and section
  boundaries are worth spot-checking against raw bytes.
- **Reporting inference as observation.** The most damaging error, because it
  is invisible later.
- **Silent scope reduction.** Analysing 400 of 3000 functions and reporting
  the whole binary as understood. Say what fraction was covered.