# Known formats

Container, asset and data formats already identified in this target. Record
the decoder used and any version assumption, so the format is not re-derived
and a *similar-looking* format is not assumed to match.

Keep one row per format. If two formats are suspected of being the same, keep
separate rows until proven otherwise.

## Table

<!-- Add rows below this line. -->

| Format | Location | Decoder | Version | Confidence | Notes |
| --- | --- | --- | --- | --- | --- |
| *(example)* Package header | `0x0000-0x001f` | manual, see known-offsets.md | v1.4.2 | high | magic `0x5051474D` |
| *(example)* Asset table | `0x2000+` | custom TLV | v1.4.2 | medium | entries are (tag u16, len u32) |
| *(example)* Texture blob | `assets/tex/*` | `binwalk` | v1.4.2 | medium | DCT/blocks, not raw PNG |

## Per-format notes

### *(format name)*

- **Magic:** `xx xx xx xx` at offset 0
- **Layout:** describe the header and the body
- **Established by:** how this was determined (observed bytes, a tool, a
  specification, or a working decode)
- **Version assumption:** <what this depends on>
- **Still unknown:** what was not determined
- **Not re-verified against:** <version, if applicable>

## Unidentified

Files and regions whose format is not established. This is a working list, not
a conclusion — an entry here means "open", not "unknown forever".

| Path / offset | Size | Entropy | What was ruled out | Status |
| --- | --- | --- | --- | --- |
| `assets/blob.dat` | 40960 | 7.9 | gzip, zlib, LZ4, SQLite, protobuf | open — see hypotheses.md |
| `0x1a40` in libfoo.so | 4096 | 7.8 | LZ4 (both framings) | open — see dead-ends.md |

## Superseded

Formats whose identification was later revised. Keeping the old row prevents
someone re-adopting a discredited conclusion.

| Former claim | Superseded by | Date | Why |
| --- | --- | --- | --- |
| *(example)* "protobuf" | custom TLV | YYYY-MM-DD | field 1 is a length, not a varint tag |