# Protocols and proprietary formats

The same evidence discipline applies, applied to bytes rather than functions.
The goal is a specification backed by evidence, not a plausible guess.

## The loop

```
Observe traffic  ->  Capture bytes  ->  Find framing  ->  Locate parser
      ^                                                      |
      |                                                      v
  Document  <-  Confirm with runtime  <-  Map fields  <-  Find serialiser
```

Two directions, both useful:

- **From the code**: find the parser, then learn the format from what it reads.
- **From the traffic**: capture bytes, then find the code that handles them.

Code-first is usually faster; traffic-first is necessary when the format is
generated, obfuscated, or entirely server-defined.

## Step 1: get bytes

The most valuable artefact. Capture with whatever the target provides:
a proxy, a tap, a file, a debugger breakpoint on a send/receive function.

```sh
tcpdump -i any -w capture.pcap 'port 443'
tshark -r capture.pcap -Y 'tcp' -T fields -e tcp.payload
```

Frida hooking `send`/`recv`/`write` gives exact bytes per call — often better
than a pcap, because it preserves message boundaries the stack may coalesce.

```javascript
Interceptor.attach(Module.getExportByName(null, "send"), {
  onEnter(args) {
    console.log(hexdump(args[1], { length: args[2].toInt32() }));
  }
});
```

Record the length too. Message boundaries are protocol evidence.

## Step 2: find framing

How do you know where a message begins and ends? In order of reliability:

1. **Length field** — a value that matches the remaining size
2. **Delimiter** — a sentinel byte sequence
3. **Fixed size** — everything the same length
4. **Structure magic** — a recognisable header
5. **Timing or behaviour** — weaker, often wrong

Look for a 16- or 32-bit field near the start whose value equals
`total_length - header_length`. That single observation usually cracks the
format. Also consider byte order: read the same field both ways and see which
produces a consistent total.

Network byte order (big-endian) is the norm for protocol headers; several
formats use little-endian, and a few are inconsistent.

## Step 3: locate the parser

From the string or magic:

```sh
scripts/find-xrefs.py ./server --string "NOTICE_AUTH" --containing-funcs
strings -a -t x ./server | grep -i notice
```

From behaviour: hook `recv`/`read` in the runtime and record the return
address. That address is the caller's code — the parser's entry.

From the disassembly: look for a function that loads a small integer from a
buffer and switches on it. That is a dispatch loop over message types.

## Step 4: map the fields

For each byte range, record what you actually know:

| Field | Status |
| --- | --- |
| offset 0, 2 bytes | observed: always `0x0001` in 40 captures |
| offset 2, 4 bytes | confirmed: equals total message length in all captures |
| offset 6, 4 bytes | inferred: increases with payload size; likely a length |
| offset 10, 16 bytes | unknown: varies, no hypothesis |

Distinguish these states rigorously:

- **observed** — seen in the bytes, no interpretation
- **inferred** — a hypothesis consistent with observations
- **confirmed** — verified by a test, ideally across varied inputs
- **unknown** — no evidence, recorded as unknown

Overstating a field is the standard failure. "offset 6 is the checksum"
without testing it is a guess that will mislead later work.

## Step 5: confirm with runtime behaviour

Correlate parsing with execution. Which opcode value causes which handler?
Which field changes which code path?

```javascript
// Dispatch switch: log the type before it is handled
Interceptor.attach(dispatch, {
  onEnter(args) { console.log("msg type", args[1].toInt32()); }
});
```

Change one field in a captured message and observe what breaks. A field that
changes the handler identifies itself in one experiment.

## Field types

Inferred from behaviour, not position:

| Evidence | Likely type |
| --- | --- |
| Value equals total length | length, 32-bit |
| Small, matches error text | opcode / message type |
| Changes over successive messages, +1 each time | sequence number |
| Fixed value across all captures | constant, magic or version |
| Matches a name in the symbol table | id / reference |
| Varies with payload, always at the end | trailing checksum |
| Little-endian reading produces sane values | little-endian integer |

Checksum identification: try the common algorithms (CRC32, Adler-32, sum of
bytes, XOR) against captured data. A match across several samples confirms it.

## Framing above the transport

TCP is a stream: it may split or coalesce messages. Expect a length field or
delimiter precisely because TCP provides neither. Over UDP or QUIC, framing
is usually per-datagram and simpler.

TLS hides the payload. Either capture keys, hook after decryption, or analyse
the parsing code statically — this is a hard precondition, and a static-only
investigation of a TLS payload is not possible from the capture.

## State machines

Many protocols are state machines, and the state explains the ordering
constraints you will otherwise find baffling:

```
CONNECTED -> AUTHENTICATED -> JOINED -> PLAYING
```

Evidence: which states accept which messages; what errors occur out of order.
Representing the machine explicitly makes later behaviour predictable — and
predicting an unobserved transition is a hypothesis you can then test.

## Documenting

```markdown
## Protocol hypothesis

Framing:    2-byte big-endian total length, including the 4-byte header.
Header:    offset 0: u8 version (always 1)
           offset 1: u8 type
           offset 2: u16 payload length
Observed:  40 messages captured (file capture-2024-03-11.pcap, sha256:…)
Confidence: framing high; field 2 length medium; field 6 checksum unknown.

Tested:    truncating payload length by 1 byte yields "bad length" at the
           server (confirmed against the running server).

Unknown:   bytes 6..9 vary per message; purpose not established.
```

Explicitly listing unknowns is what makes the document useful to the next
person — and stops them repeating the work.

## Common mistakes

- Assuming the format mirrors the code. Optimisation and inlining frequently
  eliminate any correspondence to the source-level structure.
- Concluding a field's meaning from one sample. Confirm across varied input.
- Assuming field order is contiguous. Padding and alignment are common.
- Ignoring endianness. Test both; do not pick the plausible one.
- Treating a checksum as part of the payload. Identify it explicitly.
- Claiming the protocol is understood from captures alone when the server
  behaviour was never observed.