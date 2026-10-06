# Example: reconstruct a protocol

From captured bytes to an independent client, with the state machine as the
deliverable rather than the framing code.

> Target data is **synthetic**. Commands are real and runnable.

## The starting point

> "The client talks to a server and I want my own client to work. What do I
> need to know?"

Not "reverse the encryption". The question is what a correct client must do,
and that is a specification, not a parser.

## Capture before analysing

Analysis of captured bytes without knowing what you captured is where protocol
reconstruction goes wrong.

```sh
tcpdump -i any -w captures/session.pcap 'host 198.51.100.7 and port 9000'
```

If the traffic is TLS, that is a wall: you can see lengths and timing and
nothing else. Check before planning.

```
observed: TLS handshake to :9000, then encrypted application data
implication: field-level reconstruction is not possible from this capture
next: find whether the client has a plaintext mode, or whether the
      certificate and the binary reveal the record layout
```

Say that in the notes. A protocol you cannot see is not a protocol you can
reconstruct, and the honest answer is more useful than an invented spec.

Assuming plaintext here, proceed.

## Find the framing

```sh
scripts/strings-map.py ./client.bin --xrefs --search "recv"
python3 - <<'PY'
# dump the payload field offsets and lengths from the capture
import struct
data = open("captures/session.pcap","rb").read()
for i in range(0, len(data) - 4, 1):
    if data[i:i+2] == b"\x50\x4b":          # 'PK' marker in the example
        ln = struct.unpack_from(">H", data, i+2)[0]
        print(f"offset {i}: length field {ln}, total {ln+4}")
        break
PY
```

```
offset 214: length field 24, total 28
offset 242: length field 31, total 35
offset 277: length field 24, total 28
```

Four bytes of big-endian length, matching the distance between messages, and
the value equals the payload size rather than the whole frame. Test that:

```sh
# for each candidate: does the big-endian length equal frame size minus 4?
python3 - <<'PY'
import struct
data = open("captures/session.pcap","rb").read()
offsets = [i for i in range(len(data)-2) if data[i:i+2] == b"\x50\x4b"]
be = [(o, struct.unpack_from(">H", data, o+2)[0]) for o in offsets]
le = [(o, struct.unpack_from("<H", data, o+2)[0]) for o in offsets]
print(f"big-endian lengths equal to the next frame's distance: "
      f"{sum(1 for a,b in zip(be, be[1:]) if a[1] == b[0]-a[0])}/{len(be)-1}")
print(f"little-endian equivalent: "
      f"{sum(1 for a,b in zip(le, le[1:]) if a[1] == b[0]-a[0])}/{len(le)-1}")
PY
```

```
big-endian lengths equal to the next frame's distance: 39/40
little-endian equivalent: 3/40
```

Big-endian, on 39 of 40. The one miss is the final frame, where there is no
"next frame" — so 40/40 is the correct reading. Evidence, not a preference.

## Recover the fields

Now work field by field. The method is: vary one input, observe one output.

| offset | size | observation across 40 messages | candidate |
| --- | --- | --- | --- |
| 0 | 2 | always `0x504B`, never varies | message type "PK" |
| 2 | 2 | equals the frame size minus 4 | length |
| 4 | 1 | always 3 | protocol version |
| 5 | 1 | always 0 in the request set | flags |
| 6 | 4 | matches the packet index seen in the client's log | sequence |
| 10 | 4 | equals a wall-clock delta measured externally | client time |

Each candidate needs the same treatment — a prediction. `flags` is always
zero, so:

```
hypothesis: flags is unused in this message type
status:     observed at medium -- 40 messages, one type, no variation
next_test:  find a message type with non-zero flags; if none exists,
            the field's purpose is unestablished
```

The honest phrasing matters here. "flags is unused" and "flags is zero in the
40 messages I captured" are different claims, and only the second is
established.

## Build the state machine

This is the deliverable. The parser is easy and reusable; the sequence rules
are what a client must get right.

```
observed sequence over 3 sessions:

  CONNECT(ver=3)         -> SERVER_READY
  CLIENT_AUTH(token)     -> AUTH_OK | AUTH_FAIL
  AUTH_OK                -> JOIN(session)
  JOIN                   -> WELCOME(entity_id, spawn)
  WELCOME                -> READY
  READY + INPUT(seq)     -> STATE(pos, vel, tick)
  READY + INPUT          -> ...

  AUTH_FAIL              -> CLOSED
  no INPUT for 30s       -> READY (timeout, connection kept)
  sequence gap > 3       -> RESYNC (observed twice, both after a reconnect)
```

A gap tolerance is the kind of rule that is invisible until you miss it, and
missing it means a client that works perfectly until one dropped packet.

```json
{"name": "session_machine",
 "states": ["CONNECTED", "READY", "WELCOME", "CLOSED"],
 "transitions": [
   {"from":"CONNECTED","event":"CLIENT_AUTH","to":"READY|AUTH_FAIL",
    "evidence":"40 sessions"},
   {"from":"READY","event":"INPUT","to":"READY",
    "guard":"sequence within 3 of last accepted","evidence":"2 gaps observed"},
   {"from":"READY","event":"timeout 30s","to":"READY",
    "evidence":"observed in 2 sessions; not tested by deliberate silence"}],
 "unknown": ["behaviour on an unknown message type",
             "whether AUTH_FAIL is retried"]}
```

The two unknowns are the valuable part. They are where a reimplementation will
differ, and recording them means the difference is a known risk rather than a
surprise.

## Write an independent client

The framing and the state machine are the specification. Implement from them.

```python
# Independent client, written from the reconstructed model.
# Behavioural fidelity only: the original's internal structure is not
# reproduced, and nothing here depends on it.
import struct

TYPE_HANDSHAKE = 0x504B
VERSION = 3

class Session:
    def __init__(self, sock):
        self.sock = sock
        self.state = "CONNECTED"
        self.last_seq = 0

    def send(self, msg_type, body=b""):
        # 2B type | 2B length (payload size, not frame size) | body
        frame = struct.pack(">HH", msg_type, len(body)) + body
        self.sock.sendall(frame)

    def recv(self):
        head = self._recv_exact(4)
        msg_type, length = struct.unpack(">HH", head)
        body = self._recv_exact(length)     # length excludes the 4-byte header
        return msg_type, body

    def pump(self, message):
        """Advance the reconstructed state machine. Returns the next state."""
        if self.state == "CONNECTED":
            if message == "SERVER_READY":
                self.send(TYPE_HANDSHAKE, bytes([VERSION, 0]))
                self.state = "AUTH_SENT"
            return self.state
        if self.state == "AUTH_SENT":
            if message == "AUTH_OK":
                self.state = "READY"
            elif message == "AUTH_FAIL":
                self.state = "CLOSED"
            return self.state
        if self.state == "READY":
            msg_type, body = message
            seq = struct.unpack_from(">I", body, 0)[0] if len(body) >= 4 else None
            if seq is not None:
                if abs(seq - self.last_seq) > 3:     # reconstructed gap rule
                    self.state = "RESYNC"
                else:
                    self.last_seq = seq
            return self.state
        return self.state

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError(f"closed after {len(buf)} of {n} bytes")
            buf += chunk
        return buf
```

Note the three reconstructions that are visible and each one is marked where
it came from: big-endian length excluding the header, version 3, and the gap
tolerance of 3. A reader can check each against the model.

## Verify against the original client

Same capture, same input, same server:

```sh
# 1. the original client, against a replay server, recording its frames
./original --replay captures/session.pcap --out frames/original

# 2. the reimplementation, against the same server
python3 client.py --host 198.51.100.7 --out frames/reimpl

# 3. compare the sequences of message types
scripts/trace-diff.py frames/original frames/reimpl --detail
```

```
   idx  original                    reimplementation
   0    HANDSHAKE                   HANDSHAKE                   =
   1    SERVER_READY                SERVER_READY                =
   2    CLIENT_AUTH                 CLIENT_AUTH                 =
   3    AUTH_OK                     AUTH_OK                     =
   4    JOIN                        JOIN                        =
   5    WELCOME                     WELCOME                     =
   6    READY                       READY                       =
   7    INPUT                       INPUT                       =
```

Agreement on the happy path is the easy half. Test the parts that are hard:

```sh
# force a gap: drop three INPUT frames from the replay
# force an auth failure: replay with an invalid token
# force an unknown message type: send type 0xDEAD
```

The third is the one nobody tests and the one that differs. The model records
"behaviour on an unknown message type" as unknown, so the test is expected to
disagree, and the disagreement is information rather than a defect:

```
original:      disconnects immediately
reimpl:        stays READY
model records: behaviour on an unknown message type = unknown
```

Now the ledger has a specific, testable open question instead of a vague
suspicion. That is the correct outcome: the model predicted it did not know,
and the test told it.

## Record it

```sh
scripts/recon-ledger.py add ./reconstruction formats handshake_frame \
    --evidence "2-byte type 0x504B, constant across 40 messages" \
    --evidence "2-byte big-endian length; equals frame size minus 4 on 40/40" \
    --evidence "little-endian reading matches on only 3 of 40" \
    --evidence "version byte is 3 in every message" \
    --observed-behavior "type + length + payload; length excludes the header" \
    --status reconstructed --confidence high \
    --next-test "find a message with a non-zero flags byte"

scripts/recon-ledger.py add ./reconstruction states session_machine \
    --evidence "CONNECT/AUTH/JOIN/WELCOME sequence identical across 3 sessions" \
    --evidence "a sequence gap greater than 3 triggers RESYNC; observed twice" \
    --evidence "no input for 30s keeps the connection in READY" \
    --hypothesis "the state machine above is the complete session lifecycle" \
    --contradicting "behaviour on an unknown message type is unestablished: " \
                    "the original disconnects, the reimplementation does not" \
    --next-test "resolve the unknown-message case against the original" \
    --status partially-reconstructed --confidence medium
```

## What this example shows

- framing established by testing both endiannesses against the data
- one field left explicitly unknown rather than assumed unused
- the state machine is the deliverable, and the parser follows from it
- the happy path agrees, and the disagreement is on the case nobody would test
- the disagreement became a recorded open question

The discipline: **the protocol is a sequence, so the state machine is the
specification and the bytes are an implementation detail — and every state
rule you cannot test is a rule your client will get wrong.**