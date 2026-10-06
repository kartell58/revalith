# Dead ends

Hypotheses that were tested and did not survive. Write the entry **as soon as
the hypothesis is refuted**, with enough detail that the next session can tell
the test was adequate rather than merely abandoned.

Why this file exists: a refuted hypothesis that is not recorded here will be
re-tested in a later session, and the time spent will be invisible to anyone
reviewing the work.

## How to write an entry

```markdown
## <the hypothesis in one line>

Status:     refuted (YYYY-MM-DD)
Confidence: high | medium | low — why this level
Target:     what was tested, with enough identity to find it again
            (version, hash, offset)

Hypothesis: <the claim>

Tests performed:
  - <the actual command or trace, and its outcome>
  - <the alternative that was also ruled out>

Conclusion: <what the evidence actually supports, which may be a different
            hypothesis or simply "still unknown">

Redirects to: <link to a hypotheses.md entry, if the question moved>
```

## Entries

<!-- Add new entries below this line. -->

## Template: compression format

Status:     refuted (YYYY-MM-DD)
Confidence: high — two independent decoders and the magic bytes all disagree.

Target:     `libfoo.so`, payload region at offset 0x0000a1a40, v1.4.2
            (sha256:…)

Hypothesis: payload is LZ4-compressed.

Tests performed:
  - checked for the LZ4 frame magic 0x184D2204   -> absent
  - `lz4 -d` on the region                       -> bad magic
  - Python `lz4.frame.decompress()`             -> LZ4Error
  - checked for a raw LZ4 block header           -> absent
  - measured region entropy 7.8 bits/byte         -> higher than typical
    LZ4 output, but entropy alone does not decide this

Conclusion: not LZ4 in either framing. The region remains unexplained; the
high entropy is a separate open question.

Redirects to: hypotheses.md — "high-entropy region in libfoo.so"

## Template: encryption algorithm

Status:     refuted (YYYY-MM-DD)
Confidence: medium — consistent results, but only tested against known vectors.

Target:     <file and offset>

Hypothesis: payload is encrypted with <algorithm>.

Tests performed:
  - decrypted the captured sample with <algorithm>  -> no valid padding
  - re-encrypted a known plaintext and compared      -> no match
  - checked for an IV/nonce at <offset>              -> <found/not found>

Conclusion: <algorithm> does not produce this output. Other algorithms in the
same family are not ruled out.

## Template: dynamic analysis unavailable

Status:     blocked (YYYY-MM-DD)
Confidence: n/a — no test was run.

Target:     <function or address>

Hypothesis: needs runtime observation.

Blocker:    <precondition, e.g. "no frida-server, ptrace_scope is 3, target
             needs Android 15 and the device is Android 11">

What would unblock it: <the specific change that would make the test
possible>.

Note: record blockers too. A blocked test retried under identical conditions
is as wasteful as a refuted hypothesis retried.