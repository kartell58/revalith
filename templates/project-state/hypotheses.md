# Hypotheses

Live hypotheses with their status and next test. A hypothesis that has been
refuted moves to `dead-ends.md`; it does not stay here in a stale state.

`Status` is one of: `open`, `testing`, `confirmed`, `refuted`, `blocked`.

`blocked` is for a test that cannot be run in this environment. Record the
precondition so the same blocked test is not retried under identical
conditions.

## How to write an entry

```markdown
## <the claim, stated so it could be false>

Status:     open | testing | confirmed | refuted | blocked
Confidence: very low | low | medium | high | very high — why this level
Target:     what this is about, precisely enough to find again
Evidence:   observations only — what was seen, not what it means
Hypothesis: the interpretation
Next test:  the specific action that could confirm or refute it
```

The `Next test` line is required. A hypothesis with no testable next step is
not yet a hypothesis.

## Open hypotheses

<!-- Add entries below this line. -->

### *(example)* The asset payload is encrypted

Status:     open
Confidence: low — entropy and the absence of a magic are suggestive but not
            diagnostic.

Target:     libfoo.so v1.4.2, region at offset 0x1a40 (4 KiB)

Evidence:
  - region entropy 7.8 bits/byte
  - no known magic at the start of the region
  - byte distribution is flat (no periodicity that would suggest a key length)
  - referenced by exactly one function, sub_4a2010

Hypothesis: the region is encrypted, with a key derived at runtime.

Next test: trace sub_4a2010 during startup and look for a key-sized buffer
           written before the region is read.

If it is encrypted: record the key derivation and the algorithm here, and move
the region to known-formats.md.
If it is not: say which compression or encoding was found, and move it to
dead-ends.md so it is not retried.

## Blocked

Tests that cannot be run in this environment, with the reason.

### *(example)* Confirming the return value semantics of sub_4012a0

Status:     blocked
Confidence: n/a — no test was run.

Target:     sub_4012a0 at 0x4012a0

Hypothesis: the return value is the payload offset.

Blocker:    no frida-server available and ptrace_scope is 3 on this host; the
            target also self-attaches via ptrace(PTRACE_TRACEME).

What would unblock it: a host with ptrace_scope <= 1, or a patched target that
            skips the self-attach call.

## Confirmed

Hypotheses with the test that settled them. Keep these: they are the load
bearing part of the investigation.

### *(example)* The endpoint requires Accept: application/json

Status:     confirmed (YYYY-MM-DD)
Confidence: high — isolated to one variable and reproduced 5 times.

Evidence:
  - the app client sends `Accept: application/json`; the browser sends
    `text/html`
  - with `text/html` the endpoint returns 403 and an HTML body
  - restoring `application/json` returns 200

Hypothesis: the endpoint routes on `Accept` and rejects non-JSON requests.

Test:      replayed the app request varying only `Accept`:
             `application/json` -> 200, `text/html` -> 403, `*/*` -> 403.
           Repeated 5 times with identical results.

Ruled out at the same time: `Origin` and `User-Agent` were varied
           independently and neither changed the outcome.

## Retired

Hypotheses superseded by a better explanation. Keep a short note so the
original line of reasoning is not repeated.

| Hypothesis | Superseded by | Date |
| --- | --- | --- |
| *(example)* "the header is a length prefix" | it is a flags byte; the length follows at +0x04 | YYYY-MM-DD |