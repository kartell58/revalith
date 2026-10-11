# project-state — the readable view

Five Markdown files. None of them are the source of truth.

The ledger is: `templates/reconstruction/*.json`, maintained by
`recon-ledger.py`. These files are what it renders to.

```sh
scripts/recon-ledger.py render ./reconstruction -o ./project-state/
```

writes `investigation-state.md`, `dead-ends.md`, `hypotheses.md`,
`known-formats.md`, `known-offsets.md` and `known-protocols.md`, each with a
generated banner.

## Why generate them at all

Because two stores of the same facts do not stay in agreement. A session reads
`dead-ends.md`, decides LZ4 was refuted, and writes that in the ledger. A
later session reads the Markdown, which was never updated, and spends an hour
on a settled question. Both files were correct when written; nothing notices
they stopped agreeing.

Rendering removes the second copy rather than trying to synchronise it.

## What each file is for

| File | Read it when |
| --- | --- |
| `investigation-state.md` | picking the work back up; it counts what exists and lists what is still open |
| `dead-ends.md` | before proposing an idea; it is the list of questions already settled |
| `hypotheses.md` | deciding what to test next; every entry carries a next test |
| `known-formats.md` | before decoding a blob that might already be decoded |
| `known-offsets.md` | before trusting a field, and which version it was derived from |
| `known-protocols.md` | before writing a parser for a wire format |

## One command replaces reading all five

```sh
scripts/recon-ledger.py gaps ./reconstruction
```

answers the same question — what is still unknown — from the ledger itself,
with every category accounted for, including the ones nobody has asked about
yet. The Markdown is for a human reading the work; `gaps` is for deciding what
to do next.

## The files here

The five Markdown files in this directory are **examples of the rendered
format**, kept because a readable file has to stay readable and the renderer
cannot explain itself. The live copies come from `render`, not from here.