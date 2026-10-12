# Issue tracker: beads (`br`)

Issues, specs and tickets for this repo live in beads: `.beads/issues.jsonl`, committed, with
`.beads/beads.db` as the local working copy. Issue prefix `twr`.

## Conventions

- A spec is one issue of type `epic`; its tickets are issues created with `--parent <epic>`.
- Blocking is native: `br dep add <ticket> <blocker>`. `br ready --sort oldest` lists open,
  unblocked, undeferred work in creation order, which is the order a plan was published in; it is
  the frontier, and its first entry is the next ticket. (`br ready` alone sorts by its hybrid
  policy, not by creation.)
- Triage state is a label (see `triage-labels.md`): `br label add <id> --label <label>`.
- Never hand-edit `issues.jsonl`: `updated_at` goes stale and the next `br update` or `br close`
  silently reverts the edit. Every change goes through `br`.
- Before committing, `br sync --flush-only` so the JSONL matches the database; commit
  `.beads/issues.jsonl` with the change it tracks. `beads.db` is not committed.

## When a skill says "publish to the issue tracker"

A spec: `br create --type epic --title "<spec title>" --description-file <spec.md>
--labels ready-for-agent`. A ticket: `br create --parent <epic> --deps <blocker,...> --title ...
--description-file <ticket.md>`. Then `br sync --flush-only`.

## When a skill says "fetch the relevant ticket"

`br show <id>`. The user will normally pass the id.

## Wayfinding operations

Used by `/wayfinder`. The **map** is an `epic`; each **child** is an issue under it.

- **Child ticket**: `br create --parent <map> --labels type:<research|prototype|grilling|task>`
  with the question as the description.
- **Blocking**: `br dep add <child> <blocker>`; a child is unblocked when every blocker is closed.
- **Frontier**: `br ready --sort oldest`, filtered to the map's children; the first entry wins.
- **Claim**: `br update <id> --status in_progress` before any work.
- **Resolve**: `br comments add <id> "<answer>"`, `br close <id>`, then append a one-line pointer
  (gist plus the child's id) to the map's description. `--description-file` replaces the whole
  description, so write the current one plus the new line and pass that:
  `{ br show <map> --json | jq -r '.[0].description'; echo "- <gist> (<id>)"; } > map.md` then
  `br update <map> --description-file map.md`.
