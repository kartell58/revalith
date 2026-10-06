# Known protocols

Protocol and message formats recovered from this target: framing, fields,
state machines, checksums.

> If you intend to **implement** a client or server for one of these
> protocols, the reconstruction ledger is the better tool: it records the state
> machine, the message model and the verification tests as testable entries.
> See `templates/reconstruction/` and `references/reconstruction.md`.

Field states are load-bearing. Use exactly one:

| State | Meaning |
| --- | --- |
| `observed` | seen in the bytes, no interpretation attached |
| `inferred` | a hypothesis consistent with the observations |
| `confirmed` | verified by a test, ideally across varied inputs |
| `unknown` | no evidence; recorded as unknown |

Overstating a field is the standard failure here. "Offset +0x06 is the
checksum" without testing it will mislead every later piece of work.

## Protocols

<!-- Add protocols below this line. -->

### *(protocol name)*

Captured from: <source of the captures, e.g. "40 messages, pcap file, sha256:…">

**Framing**
- *(e.g. 4-byte big-endian total length at +0x00, including the 4-byte header)*
- How established: *(e.g. "big-endian reading equals observed length on all
  40 captures; the little-endian reading did not")*

**Fields**

| Offset | Size | Name | State | Evidence | Confidence |
| --- | --- | --- | --- | --- | --- |
| +0x00 | 4 | total_length | confirmed | equals message size in all captures | high |
| +0x04 | 2 | message_type | confirmed | type 31 gates the "unauthorised" response | high |
| +0x06 | 2 | — | unknown | varies; does not affect dispatch | — |
| +0x08 | … | payload | inferred | offset not established | low |

**Dispatch**
- *(e.g. jump table at 0xb000, 0x40 entries, type 31 branches to sub_401a20)*

**State machine** (if any)

```
CONNECTED -> AUTHENTICATED -> JOINED -> PLAYING
```

- Transitions observed: *(which were seen)*
- Transitions inferred: *(which follow from the code but were not exercised)*

**Tests performed**
- *(e.g. "truncating the length field by 1 byte yields 'bad length' at the
  server — confirmed against the live server")*

**Still unknown**
- *(what was not established)*

## Capture inventory

| Capture | Source | Count | File | Notes |
| --- | --- | --- | --- | --- |
| *(example)* session-control | live server | 40 | `captures/ctl-2026-03-11.pcap` | includes 4 malformed |

## Checksums

| Algorithm | Location | Evidence | Confidence |
| --- | --- | --- | --- |
| *(example)* CRC32 | trailing 4 bytes | matches on 12 of 12 samples | medium |

State the algorithm only when it was actually tested against several samples.
A checksum that happens to match on one input is a coincidence, not a
finding.

## Unidentified

Regions of traffic not yet framed or parsed.

| Offset / pattern | Bytes | Ruled out | Status |
| --- | --- | --- | --- |
| *(example)* bytes 32..63 | 32 | length prefix, magic, timestamp | open |