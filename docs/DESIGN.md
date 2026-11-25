# Design

netwatch runs package tools locally or over SSH and stores observations in SQLite.

| Module | Responsibility |
| --- | --- |
| `adapters.py` | Collect installed packages, discover available updates and define update commands. |
| `sources.py` | Fetch/cache advisory data and match installed packages; separately fetch optional cve.now context, pwn.watch incident leads and Zero Wire briefings. |
| `store.py` | Store registrations, scans, findings, events and update attempts; own the schema migration, the lifecycle columns and lazy expiry. |
| `workflow.py` | Check environments, save previews, apply approved updates and record results. |
| `scan.py` | Walk a root, classify lanes, decide ownership, persist runs and register targets from them. |
| `tickets.py` | Repo-lane findings and the `.netwatch` ticket: collect, render, publish by rename. |
| `userlane.py` | Read what a manager recorded inside a venv (receipt, metadata, exposed launchers, index options) and inventory it. |
| `pins.py` | Derive the pinned upgrade set under the environment's own bounds, read PEP 610 origins, verify launchers, build the install argv. |
| `probe.py` | The per-venv provenance token: read, publish by `os.link`, clean stale temps, compare witnesses. |
| `lifecycle.py` | Pure state functions: one pairing rule, the transition table, recovery and publication authority. |
| `venvflow.py` | The `uvtool`/`pipx` sequences: `check` `(c0)`–`(c5)`, `preview` `(p-1)`–`(p11)`, `apply` `(0)`–`(5)`, claim and classifier. |
| `cli.py` | Parse commands and present text or JSON results. |

## Behavior to preserve

- Collect only registered environments. Commands come from adapter definitions; advisory text cannot supply commands or repositories.
- Express Homebrew coverage per formula: a scan that ran but skipped packages clears findings only for the formulae it checked, and a `complete: false` whose gap is named by an installed, loadable formula — with the checked count still accounting for the remaining formulae — is reported as coverage rather than as a failed check; an incomplete scan whose gap the installed set cannot explain, or whose count does not balance, credits nothing and fails the advisory check. A formula the scan skipped keeps the finding for the version it was reported for, while still installed; uninstalling it or changing that version retires the finding. `outdated_without_sbom` names count as uncovered, because Homebrew reports those against the current formula version. No scanner and a scan skipped in offline mode are incomplete advisory checks, not clean ones. Homebrew's own scanner is the source; netwatch does not re-derive OSV matches for formulae.
- Match Ubuntu notices using Noble source versions and binary membership. Use OSV for installed PyPI/npm packages. Keep uncertain Arch/CachyOS matches and missing conda-native coverage visible.
- Retain earlier findings when collection or advisory requests fail. Record changes separately from routine checks.
- Advisory screening is batched and strictly sequential: the screen asks `querybatch` in pages of up to 1000 packages, halves and re-asks a refused batch, follows continuation tokens, identifies itself as `netwatch/<version>`, and caches per `(ecosystem, name, version)` for the hour; a failed screen is an incomplete check, never a clean one.
- `check --context` enriches existing CVE references through cve.now and locally matches pwn.watch live patch/supply-chain incidents by advisory IDs or exact package/source tags with fixed aliases, and matches Cloudflare Zero Wire briefings by exact CVE tags only. Keep all three sources outside applicability, fix-version and command selection. No inventory is sent to either source.
- Cache and record context independently of findings. Failed context sources retain prior records with their observation times; checks that omit context, including `apply` recollection, mark it skipped. Context changes have separate history events, and incomplete requested context makes `check` exit 1 without changing `advisory_check_ok`.
- Bound context requests and validate identities before caching. Allow only the cve.now-to-storage redirect for the same CVE path; never follow advisory links. Reject XML document type/entity declarations and drop Zero Wire prose before caching.
- A preview binds the target, inventory and environment-wide command list. Changed inventory or an expired preview requires a new preview. Repository candidates can change before execution.
- Record approval and start before running updates. Recollect afterward and report remaining findings separately from command completion.
- Block another attempt while an update is running or needs attention. Recovery records the operator's note and invalidates outstanding previews.
- Operator filesystem and SSH permissions control access. Keep agent accounts read-only.

## Scan, tickets and the venv kinds

- **Two lanes, one walk.** A user-lane venv is a `pyvenv.cfg` beside a manager receipt; a repo-lane checkout is a `.git` entry. The walk stops at each repo root, does not follow symlinked directories, and keeps the operator's path spelling so a launcher naming an alias is still recognised as inside its venv.
- **`scan --list` touches nothing.** No git, no `gh`, no package tool, and no database: it must not create or migrate a state file, because it is the step that lets an operator choose exclusions before a real scan runs a repository's configured programs.
- **A scan narrates itself and cannot hang.** Progress lines go to stderr (stdout stays the summary), every git read is bounded and prompt-free, and one unreadable checkout is recorded as incomplete rather than aborting the walk. A silent scan and a stalled scan must not look the same.
- **A repo is never a target.** It gets one `.netwatch` file with findings, actions and a fenced JSON block; staleness is a lead, never a finding. Writes are confined to repos whose github origin is the authenticated account or an explicit `--handle`; `report` is the explicit override. Tickets publish by temp file plus rename after a pre-rename header re-check, refuse anything that is not a regular file or was written by another tool, and are never staged.
- **Registration indexes into a stored run.** Never a fresh walk: a tree that changed since the scan cannot redirect a registration. Batches are all-or-nothing, and each item is re-verified on disk (realpath, device and inode, manager metadata, distribution) before anything is written.
- **The manager names the tool; the operator names the target.** Everything that looks up a distribution uses the recorded tool (`tool_of`), never the label, and a target's extras come from the venv's receipt or pipx metadata.
- **An approval is bound to an installation.** The probe token is created once, only after identity passes, and never rewritten; apply refuses if it moved. The constraints file carries the retained bounds *and* the pins, because selecting under a bound without passing it lets the installer resolve past it. Markers are evaluated against the venv's own interpreter, not the host's.
- **Origins gate planning.** An undetermined PEP 610 origin makes a target unplannable; direct, VCS and local installs are held at their version. A held distribution that disappears during an install fails the gate.
- **The result says what happened.** `applied` needs an unchanged probe, the approved pins installed, no new consistency entry, preserved origins and no held distribution removed. A failure that changed nothing (same token, digest, consistency report, and no file disagreeing with its own `RECORD`) returns the plan to `proposed`; anything else is `needs_attention`.
- **Lifecycle is one machine.** Ambiguous evidence needs two paired observations, unambiguous evidence one; a superseded or unfinished observation writes nothing. The lifecycle flags live in columns, never in the body, and every write is guarded by generation and `state_seq` so a stale run cannot overwrite a newer decision.
- **uv runs from the state directory** with the operator's environment, `--no-config` deliberately not used: ignoring their configuration would resolve a private-index tool against the public index.

## Development checks

Use injected command runners, synthetic responses and temporary databases for tests. Test each adapter's collection, update discovery and apply paths. Live operations require explicit target authorization.
