# Example: compare two builds

Turning an artefact diff into tested hypotheses about behaviour — and being
explicit when it cannot go further.

> Target data is **synthetic**. Commands are real and runnable.

## The two questions

> What changed between v1.9.0 and v1.10.0 of the client? And did the release
> note's claim — "improved session validation" — correspond to a real change?

Two different questions. The first is an artefact question. The second needs
running software. Keeping them apart is the whole discipline.

## 1. Establish the baseline first

If both source and a reproducible build are available, build the same commit
twice. Without that, you cannot separate a real change from build
nondeterminism, and every finding below is suspect.

```sh
scripts/compare-symbols.py build1/libfoo.so build2/libfoo.so
cmp -l build1/libfoo.so build2/libfoo.so | wc -l
```

*(Illustrative: a same-commit rebuild differing in 41 bytes of build-id and
timestamps. That is the noise floor.)*

If you cannot establish a noise floor, say so in the report. "Compared two
builds; no noise floor established" is honest. "No functional changes" is not
supportable.

## 2. Dump both, then diff the dumps

```sh
scripts/universal-dump.py v1/game.apk -o dump-v1 -q
scripts/universal-dump.py v2/game.apk -o dump-v2 -q
scripts/dump-diff.py dump-v1/report.json dump-v2/report.json
```

```
DUMP DIFF  (artefact comparison, not behaviour comparison)
!! This is a comparison of artefacts. A byte, symbol or string difference is
   a binary difference. It is not evidence that behaviour changed.

  files added     : 3
  files removed   : 1
  files changed   : 412
  files unchanged : 1098
  urls added/removed : 4/1
  domains added/removed : 2/0

FILES WITH A DIFFERENT HASH
  ~ lib/arm64-v8a/libmain.so
      size 28473984 -> 29160448  (delta +686464)
  ~ assets/bin/Data/global-metadata.dat
      size 14725184 -> 15212544  (delta +487360)
  ~ classes.dex
      size 4218368 -> 4404016  (delta +185648)

NETWORK INDICATORS
  urls:
    + https://api.example.com/v2/token/refresh
    + https://telemetry.example.net/v2/collect
  domains:
    + auth.example.com

ANDROID MANIFEST
  permissions added   : com.example.app.permission.BIOMETRIC
  version_code: 190 -> 1100

UNITY / IL2CPP
  il2cpp     : True -> True
  metadata status : standard_header_present -> standard_header_present
  metadata magic  : yes -> yes
  metadata size   : 14725184 -> 15212544
```

`libmain.so` grew by 686 KB and `global-metadata.dat` by 487 KB. The
`token/refresh` URL is new.

## 3. What each difference licenses

| Difference | What it supports | What it does not support |
| --- | --- | --- |
| `libmain.so` +686 KB | more code, or different data layout | *what* the code does |
| new `/token/refresh` URL | an endpoint string exists in v2 | that it is used, live, or new in intent |
| `BIOMETRIC` permission added | the app requested it | that biometrics are used |
| metadata grew | more managed types, or re-layout | which types |
| `version_code` 190 → 1100 | a version bump | anything about behaviour |

The pattern to notice: **every row is about presence, not function.** The
release note claimed "improved session validation". The diff is consistent
with that, and consistency is not confirmation. It is equally consistent with
an unrelated feature landing in the same release.

## 4. Hypotheses with tests

```markdown
1. v2 introduced a token refresh endpoint.
   basis: /token/refresh string present in v2, absent in v1
   test: run both builds through an expired-session flow and observe whether
         v2 makes a request to that path

2. v2 added biometric authentication.
   basis: BIOMETRIC permission declared in v2 only
   test: exercise the login flow on both; observe whether the biometric
         prompt appears in v2 and not in v1

3. The release note's "improved session validation" refers to a change in
   libmain.so.
   basis: libmain.so grew 686 KB
   test: NOT SUPPORTED by this diff. A size change does not identify which
         function changed, and the native library is stripped so functions
         cannot be matched by name. Needs a function-level diff (Diaphora)
         or a runtime test.
```

The third entry is the important one. It names a hypothesis, then states
plainly that this method cannot test it — and says what would.

## 5. Test them

### Hypothesis 1: the token refresh endpoint

```sh
# v1 and v2 against a test backend, same expired token
for v in v1 v2; do
  echo "--- $v ---"
  ./$v/game --profile /tmp/$v-profile   # log outgoing requests
  # expire the session, trigger any authenticated action
done
diff <(grep -o '/api/[^ ]*' /tmp/v1.log | sort -u) \
     <(grep -o '/api/[^ ]*' /tmp/v2.log | sort -u)
```

```
--- paths only in v2 ---
/api/v2/token/refresh
```

The string in v2's binary is now backed by an observed request. That is
`confirmed`.

### Hypothesis 2: biometrics

```markdown
Test: login flow on both builds, same account, fresh install.
  v1.9.0: no biometric prompt; PIN/password path
  v1.10.0: biometric prompt appears on second factor
  repeated 3 times, identical each run

Conclusion: v1.10.0 requests biometric authentication. High confidence —
tested directly, and the permission and the observed behaviour agree.
```

Permission declared **and** behaviour observed. Two independent lines of
evidence.

### Hypothesis 3: the release-note claim

```sh
scripts/compare-symbols.py \
    v1/lib/arm64-v8a/libmain.so v2/lib/arm64-v8a/libmain.so \
    --kind exports --fuzzy
```

```
exports: 8 -> 11
added:
  + libmain.so: _ZN6Session6ValidateERKNS_6TokenE
```

*(Illustrative; on a fully stripped library the symbol count is zero and
this method yields nothing — which is itself the finding.)*

If the library is stripped, this returns nothing useful and you say so:

```markdown
The libmain.so comparison cannot be done at symbol level: both builds are
stripped, so compare-symbols.py reports zero exports for both. The IL2CPP
dumper can recover names from global-metadata.dat for both versions, which
would give a comparable method list. Not done yet.
```

That is more useful than a guess, because it names the next action.

## 6. The distinction, stated plainly

```markdown
## Comparison: 1.9.0 -> 1.10.0

### Binary differences (established)
- libmain.so: +686,464 bytes, hash changed
- global-metadata.dat: +487,360 bytes, hash changed
- classes.dex: +185,648 bytes, hash changed
- 3 files added, 1 removed (see report)
- new strings: /api/v2/token/refresh, auth.example.com
- BIOMETRIC permission added
- version_code 190 -> 1100

### Semantic differences (established by testing)
- v1.10.0 requests biometric authentication; v1.9.0 does not.
  Tested on 3 fresh installs, identical result each time. High confidence.
- v1.10.0 calls /api/v2/token/refresh on an expired session; v1.9.0 does not.
  Observed in request logs. High confidence.

### Not established
- Whether "improved session validation" refers to any specific change. The
  binary diff cannot answer this: the relevant library is stripped, and a
  size increase identifies no function.
- Whether the 3 added files are used. Presence in the archive is not use.
- Whether the metadata growth is new functionality or re-layout.
```

The third section is not a failure. It is the accurate state of knowledge,
and it prevents someone else claiming the release-note claim was verified.

## 7. When only one version runs

If the old version cannot be executed — an expired entitlement, an
unsupported OS, a server that no longer accepts it — limit everything to
static comparison and say so at the top of the report:

```markdown
**Testing constraint:** v1.9.0 could not be run (requires API v1, which was
retired). Everything below is artefact comparison only. No behavioural claim
is made or implied.
```

A static-only diff is still worth producing. It just answers a different
question, and it must not answer the one it was not asked.

## Next investigation step

- Recover IL2CPP method names for both versions (the dumper already ran on
  both) and diff the method lists. That substitutes for the symbol comparison
  the stripped library cannot support, and it is what would let hypothesis 3
  be tested at all.
- If the old build still runs anywhere, execute hypotheses 1 and 2 against it
  under the same conditions, to turn the strongest artefact differences into
  semantic ones.