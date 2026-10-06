# Example: find the protocol handler

From a string, an opcode or a packet field to the code that parses and handles
it. Two routes; both are shown.

## Route A: from a string

### 1. Find the string

```sh
strings -a -t x ./server | grep -i "unauthorised\|invalid session"
scripts/strings-map.py ./server --search "unauthorised" --limit 20
```

Record the address. Everything after this is relative to it.

### 2. Find what references it

```sh
scripts/find-xrefs.py ./server --string "unauthorised" --containing-funcs
```

Output something like:

```
target 0x4a2f1c  (string 'unauthorised')
  section   : .rodata
  references: 2
    instruction 0x5a3b4  adrp x0, a000
    instruction 0x5a3c8  add  x0, x0, #0x2f1c
  containing functions: sub_401a20
```

One containing function is a strong localisation. Note what this does **not**
prove: that the function handles the whole message, only that it references
this string.

With a disassembly tool:

```sh
r2 -q -c 'aaa; axt @ 0x4a2f1c' ./server
objdump -d --start-address 0x401a20 --stop-address 0x401c00 \
        --no-show-raw-insn ./server
```

### 3. Read around the reference

```sh
objdump -d --start-address 0x5a380 --stop-address 0x5a420 \
        --no-show-raw-insn ./server
```

Look for the comparison that guards the string reference. The value compared
against is the **message type** the string reports on. That single line often
cracks the whole dispatch.

```asm
401a94:  ldr  w1, [x0, #4]        ; load a field from the message
401a98:  cmp  w1, #0x1f           ; compare against 31
401a9c:  b.ne 401b40              ; not this type
401aa0:  adrp x0, a000
401aa4:  add  x0, x0, #0x2f1c     ; -> "unauthorised"
401aa8:  bl   0x4d2210            ; send an error
```

Observations, in order: field at offset 4, compared with 31, gates the error
message. Hypothesis: **message type 31 is an authentication failure**.

### 4. Find the dispatch

Now that a type value exists, find where it is compared:

```sh
objdump -d --no-show-raw-insn ./server | grep -B12 "unauthorised"
r2 -q -c 'aaa; axt @ 0x401a20' ./server     # who calls the handler
```

The dispatch is the caller that loads a type field and branches over many
handlers — a switch, or a jump table:

```asm
401700:  ldr  w1, [x19, #4]
401704:  cmp  w1, #0x40
401708:  b.hi 401900
40170c:  adrp x2, b000
401710:  add  x2, x2, lsr       ; jump table
401714:  lsl  x1, x1, #3
401718:  ldr  x3, [x2, x1]
40171c:  br   x3                 ; indirect dispatch
```

A `br` through a scaled table lookup is a jump table over message types.
Dump it:

```sh
r2 -q -c 'aaa; pxw 0x100 @ 0xb000' ./server
```

Each 8-byte entry is a handler address. This recovers the **entire dispatch
table**, not just the one handler — usually more valuable than the single
function you started from.

## Route B: from captured bytes

### 1. Get the bytes

```sh
tcpdump -i any -w capture.pcap 'port 8080'
tshark -r capture.pcap -T fields -e tcp.payload | head
```

Better: hook the send/receive call so message boundaries survive:

```javascript
Interceptor.attach(Module.findExportByName(null, "recv"), {
  onEnter(args) { this.fd = args[0]; this.buf = args[1]; this.len = args[2]; },
  onLeave(retval) {
    const n = retval.toInt32();
    if (n > 0) console.log(hexdump(this.buf, { length: n }));
  }
});
```

Record lengths. Boundaries are protocol evidence, and TCP will not preserve
them for you.

### 2. Find framing

Test the hypothesis that a field near the start is a total length. Read it
both ways:

```python
import struct, binascii
pkt = binascii.unhexlify("0000001e01f40a00000010...")
be = struct.unpack_from(">I", pkt, 0)[0]
le = struct.unpack_from("<I", pkt, 0)[0]
print("big-endian:", be, " little-endian:", le, " actual:", len(pkt))
```

One reading equals the message length; the other is nonsense. That is
conclusive evidence about endianness *and* about the length field, from one
sample — and it is a test that could have failed.

### 3. Identify the type field

The field that varies most across captures, with values that are small
integers, is a candidate message type:

```python
import collections, struct
types = collections.Counter()
for pkt in packets:
    types[struct.unpack_from(">H", pkt, 4)[0]] += 1
print(types.most_common(10))
```

Small, repeated values suggest an enumerated field; large unique values
suggest a length, id or random nonce. Distinguishing them is inference and
should be labelled so.

### 4. Correlate with the code

Take the value that corresponds to the error string and search the
disassembly for it:

```sh
objdump -d --no-show-raw-insn ./server | grep -n "0x1f\b"
```

Find the constant from step 3, locate it in the code, and you have both
halves: bytes in one hand, handler in the other.

### 5. Confirm

Feed a modified packet and observe what changes:

```markdown
Test: replayed capture with the type field changed from 0x1f to 0x20
Result: server took a different branch; error message no longer sent
Conclusion: the field at offset 4 selects the message handler. High confidence.
```

## Route C: from the receiving function

When there is no string to start from, hook the receive call and read the
caller:

```javascript
Interceptor.attach(Module.findExportByName(null, "recv"), {
  onEnter(args) {
    console.log("recv called from: " +
      Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).join("\n  "));
  }
});
```

The return address is the code that consumes the data. Work backwards from
there.

## Handling a protocol that is not text-based

Encrypted or compressed payloads resist all of this. Establish which:

- high entropy with no repeating structure: encrypted
- a recognisable compression header (`78 9c` zlib, `1f 8b` gzip): compressed
- neither, but the bytes look structured: proprietary encoding, possibly a
  lookup table

Then either find the key, dump after decryption, or analyse the decryption
routine statically. Analysing an encrypted payload's structure is not
possible — say that rather than inferring a format from noise.

## Documenting

```markdown
## Protocol: session control messages

Framing:  4-byte big-endian total length at offset 0, including the header.
          Confirmed on 40 captures (big-endian reading equals observed
          length; little-endian did not).
Header:   +0x00 u32 total_length   confirmed
          +0x04 u16 message_type   confirmed (type 31 gates the
                                    "unauthorised" response)
          +0x06 u16 unknown        varies; does not affect dispatch
          +0x08 ...   payload, offsets not established

Dispatch: jump table at 0xb000 indexed by message_type, 0x40 entries,
          branches to sub_401a20 (type 31).

Confidence: framing high; type field high; remaining fields unknown.

Not established: types of fields beyond offset 6; no malformed-input
testing was performed against a live server.
```

The unknowns are as much of the result as the findings. A reader who knows
offset 6 is unexplained will not waste a day re-deriving that.