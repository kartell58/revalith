# Contributing

Thanks for helping improve this skill.

## What belongs here

The skill teaches a **methodology** and supplies **analysis tooling**. Changes
that fit:

- New formats, architectures or environments, when practical to analyse
- New tools, described by *when to use them*, not just by listing commands
- Corrections to existing technical claims
- Scripts that reduce repeated manual work
- Worked examples showing a real investigation end to end

Changes that do not fit:

- Project-specific workflows with no generalisable lesson
- Commands presented as "best practice" without evidence or caveats
- Anything that weakens the evidence-before-conclusion discipline
- Scripts that need network access or non-standard dependencies

## Ground rules

**Evidence or it does not go in.** Every technical claim needs a basis. If you
cannot run the command, say that it is unverified. If a tool's behaviour
differs by version or platform, document the difference.

**Do not soften the method.** The evidence loop, confidence levels and the
`unknown` answer are the point of this skill. Proposing to remove them for
brevity will be declined.

**Keep `SKILL.md` short.** Specialised knowledge goes in `references/`. The
entry point is an index and an operating procedure, not a manual.

**Scripts must work with nothing installed.** Standard library only. If a
script needs an external tool, it must detect it and degrade with a clear
message.

## Working on the scripts

```sh
python3 scripts/selftest.py     # required before and after any parser change
python3 scripts/elf-summary.py --help
```

`selftest.py` builds fixtures whose exact contents it knows, so a parser change
that silently returns wrong data fails immediately. Please add assertions for
whatever you change.

Style: readable over clever, comments explaining *why* rather than *what*, and
no silent fallbacks — if something cannot be determined, report that.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[body]

[footer]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `build`, `ci`.

Scopes: `methodology`, `references`, `scripts`, `examples`, `docs`.

```
feat(scripts): add Mach-O universal binary slice extraction
fix(references/arm64): correct the B.cond bit-field mask
docs(references): document .eh_frame as a stripped-binary boundary source
test(scripts): cover 32-bit and big-endian ELF in selftest
```

## Pull requests

1. Branch from `main`: `feat/…`, `fix/…`, `docs/…`
2. Run `selftest.py` and paste the result
3. Update `CHANGELOG.md` under an *Unreleased* heading
4. Keep the diff focused; unrelated changes belong in their own PR
5. Describe what you verified and what you did not

If you are correcting a technical claim, say what was wrong and how you
confirmed the correction. That makes the change reviewable.

## Adding a reference file

- Name it after the thing it describes (`elf.md`, not `formats.md`)
- Cross-link from `SKILL.md` so it is discoverable
- Cross-link from related references
- State limitations: what the technique cannot do, what it needs
- Prefer specifics over generalities; "this fails when packing is present" is
  useful, "be careful" is not

## Code of conduct

Be accurate, be direct, and assume good faith. Disagreeing with evidence is
welcome; disagreeing about people is not.