# Domain Docs

This repository has no domain docs of its own. The specification it implements owns them, vendored
at the pinned commit:

- **`spec/CONTEXT.md`** — the glossary. Name domain concepts (in a ticket title, a test name, a
  type) by its terms, and never by a word it lists under _Avoid_.
- **`spec/docs/adr/`** — the decisions. Read the ADRs that touch the area you are about to work in.

Do not create a `CONTEXT.md` or `docs/adr/` here. A new term, a gap in the glossary, or a decision
the specification does not make goes back to the specification repository through
`/grill-with-docs`, never into this one.

## Flag ADR conflicts

If your output contradicts an ADR, say so explicitly rather than silently overriding it:

> _Contradicts spec ADR-0029 (the machine speaks Nostr), but worth reopening because…_
