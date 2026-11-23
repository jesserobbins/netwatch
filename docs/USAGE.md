# Usage guide

## Install and try

Requires Python 3.12+ and Git. Install into a virtual environment:

```bash
git clone https://github.com/lhl/netwatch.git
cd netwatch
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --require-hashes -r requirements.lock
python3 -m pip install .
netwatch demo
```

The demo uses synthetic data and a simulated package manager. From a checkout, `python3 -m netwatch` runs the same CLI as `netwatch`.

From a checkout you can also let the bundled script do the environment work:

```bash
./netwatch-run.sh                 # prepare .venv, then print the overview
./netwatch-run.sh status          # any netwatch command, arguments passed through
```

It creates `.venv` with Python 3.12+ and installs the pinned requirements plus netwatch itself in editable mode, then runs the command. The install happens once: later runs only compare `pyproject.toml` and `requirements.lock` against a stamp inside the environment and start immediately. Progress notes go to stderr, so `--json` output stays clean. `NETWATCH_VENV`, `NETWATCH_PYTHON`, `NETWATCH_SETUP=always` and `NETWATCH_QUIET=0` change where it builds, which interpreter it uses, whether it reinstalls, and whether you see the installer work.

Running `netwatch` with no command prints an overview of the daily loop, the commands, the supported kinds and where state lives.

## Daily workflow

Replace the example SSH alias with your target. Registration saves a name; `check` collects installed versions, advisory evidence and available updates.

```bash
netwatch add server ubuntu --host my-server
netwatch check server
netwatch status server
netwatch list
```

Use `--path /absolute/project/path` for a project or conda prefix. Omit `--host` for local use. `check` without a name checks all registrations; `status` without a name shows their cached reports.

If you do not want to name each environment by hand, a scan finds them: `netwatch scan ~/GitHub --list` classifies what a root contains without touching it, a real `netwatch scan ~/GitHub` also writes tickets into the repos you own, and `netwatch scan ~/GitHub --register 1 3` turns chosen rows into targets. See [find what is on a machine](#find-what-is-on-a-machine).

For an update, review the commands and environment-wide scope returned by `preview`, then substitute its ID for `PLAN_ID`:

```bash
netwatch preview server
netwatch apply PLAN_ID --yes
netwatch status server
```

OS updates on Linux require `sudo -n` access. Application updates, including Homebrew on macOS, use the invoking account; Homebrew is never run as root. `apply` updates the whole selected environment, including dependencies. Tool-venv upgrades have been exercised end to end in throwaway tool homes; OS package-manager updates have not been exercised live, so start on a disposable target. See [update behavior and recovery](#updates).

## Agent and script queries

```bash
netwatch --json list
netwatch --json status server
netwatch --json history --since 0
```

Global flags (`--json`, `--db`) go before the command. Status returns the saved report, last collection attempt and pending update plans. History returns events and `next_cursor`; pass that value as `--since` on the next request. These queries do not contact targets. Keep agent permissions read-only and use an operator account to apply updates.

## Find what is on a machine

`scan` walks a filesystem root and classifies what it finds, instead of you naming each environment. It never registers anything by itself.

```bash
netwatch scan ~/GitHub --list                 # classification only: no git, no gh, no store
netwatch scan ~/GitHub                        # also writes tickets into repos you own
netwatch scan ~/GitHub --register 1 3 --run 7 # register those rows as targets
```

Two lanes come out of one walk:

| Lane | What it is | What netwatch does with it |
| --- | --- | --- |
| user-lane | a venv a manager owns: `pyvenv.cfg` plus `uv-receipt.toml` or `pipx_metadata.json` | can be registered as a `uvtool` or `pipx` target |
| repo-lane | a checkout: a `.git` entry | never a target; gets a `.netwatch` ticket |
| unclassified | a `pyvenv.cfg` with no manager receipt beside it | listed, never offered for upgrade |

The walk stops at each repo root and does not descend into it, skips `.git`, `node_modules`, `.venv` and `__pycache__`, does not follow symlinked directories, and bounds itself with `--depth` (default 4). `--exclude PATTERN` is repeatable and matches entry names.

`--list` is the safe first step: it reads directory structure and nothing else — no `git`, no `gh`, no package-tool enumeration, and it does not open the database, so it cannot create or migrate one. Point it at any root to see what a real scan would touch, then choose `--exclude` entries before running one. A real scan runs `git` inside the checkouts it classifies, and git honours repository configuration: a configured clean filter (for example `git-lfs filter-process`) can execute while `git status` hashes stat-dirty files. netwatch disables the filesystem monitor, the untracked cache and commit-signature verification, but a clean filter is the checkout owner's own program and runs under their configuration.

A real scan works through the tree in order and says so: one line per classified item on **stderr**, plus a line when it starts reading a checkout and one when it writes that checkout's ticket. Stdout carries only the summary and results, so `--quiet` gives you a scriptable run and `--json` output is never mixed with progress. The slow part is the checkout reads. For advisories, netwatch screens every locked package against OSV in batched requests of up to 1000 packages and asks for per-package detail only where the screen finds an advisory; a failed screen makes the affected packages an incomplete advisory check, never a clean one. Both layers are cached per `(ecosystem, name, version)` for an hour, so a repeat scan inside the hour makes no advisory requests. On a tree of roughly 1,700 locked packages the screen and the detail queries took 27.2 s on a first scan and 2.0 s on a repeat, down from about 1,200 single-package requests over two and a half minutes. OSV publishes no rate limit; netwatch stays sequential and sends every request as `netwatch/<version>`.

No single checkout can stall the scan: every git read is bounded at 60 seconds and gets no terminal prompt, and a checkout whose reads fail is reported as `incomplete: <path> (<reason>)` while the rest of the walk continues. `--list` runs none of this.

Scan output starts with a summary line carrying the run id:

```
scan run 7: 3 repos, 3 user-lane, 1 unclassified
```

That run is stored, so registration can refer to it later. Runs are keyed by the normalized root, and `scan --register` needs `--run` only when a root has more than one run.

## Repo tickets

A repo-lane checkout gets one file, `.netwatch`, holding what netwatch found and what to do about it: a human-readable list and a fenced JSON block with the same content.

Findings are `unpinned` (a manifest with no lockfile), `not_revertible` (a lockfile that is uncommitted), `drifted` (a lockfile that differs from the committed state) and `advisory` (a known-vulnerable resolved version, with the OSV id, the source lockfile and any fixed versions). Staleness — a lockfile untouched for 90 days — is a **lead**, not a finding: netwatch does not claim an old lockfile is vulnerable.

Automatic writes stay inside repos netwatch can claim: a `github.com` remote whose owner is the authenticated `gh` account or a name passed with `--handle`. Anything else is listed and skipped, never written. To write a ticket into a repository you do not own, ask for it:

```bash
netwatch report ~/src/someone-elses-project
```

The file is safe to commit or delete, and it says so. netwatch never stages or commits it. It refuses to touch a `.netwatch` that is a symlink, a directory, or was written by something else, and it publishes by writing `.netwatch.tmp-<32 hex characters>` and renaming it into place after re-checking the destination. Leftover temps older than an hour are cleaned on the next run that writes into that repo.

A scan that collected nothing at all writes no ticket and leaves a previous one untouched; a partial collection writes a ticket that says it is incomplete.

## Register environments from a scan

```bash
netwatch scan ~/GitHub --register 2 4 --run 7
```

Registration indexes into the **stored** run, not the live tree, so a repo deleted or a row reordered since the scan cannot redirect it to a different tool. Indices count user-lane rows only, 1..N in printed order; a repo row cannot be registered, and an index past the end is an error rather than a wrap.

A batch is all-or-nothing: every item's identity is checked before any target is written, so a transient failure on item three of five commits nothing and re-running the same command is safe. At most five indices per invocation. Registration re-verifies the environment on disk first — the recorded realpath, the venv directory's device and inode, the manager metadata naming the same tool, and the distribution listed inside — and refuses with a suggestion to rescan if any of that moved. It also refuses a venv that another live target already tracks. If the tool's own name is already taken by a *different* live target, the new one is registered as `name-2`, `name-3` and so on, and the output says which name it used — it never rebinds the existing target.

## Environments

| Kind | Package tools | Advisory coverage |
| --- | --- | --- |
| `ubuntu` | dpkg, APT; Ubuntu 24.04 noble amd64 | Canonical notices for published standard-security fixes; excludes Pro/ESM and pre-patch vulnerabilities. |
| `arch` | pacman, `vercmp`, `checkupdates` from pacman-contrib | Exact affected-version matches with a `Vulnerable` or `Fixed` tracker status are flagged. Other matches need investigation; the tracker may lag releases. |
| `cachyos` | pacman, `vercmp`, `checkupdates` | Arch advisory names provide leads; applicability to rebuilt packages is unknown. |
| `conda`, `mamba` | The named tool and an existing prefix | OSV for pip/PyPI-origin entries only. Conda-native coverage is unknown. |
| `uv` | uv and an installed project `.venv` | OSV for installed PyPI packages. |
| `npm` | npm and installed dependencies | OSV for installed npm packages, including transitive dependencies. |
| `brew` | Homebrew 7+ with the `vulns` command, on a macOS host (arm64 or Intel) | Homebrew's own OSV scan: formulae only, and only those it can map to an upstream repository and tag. |
| `uvtool` | one uv-managed tool venv, by path | OSV for the venv's installed PyPI packages, dependencies included. |
| `pipx` | one pipx-managed venv, by path | OSV for the venv's installed PyPI packages, dependencies included. |

For repository packages on Arch/CachyOS, `vercmp` filters out notices whose fixed version is at or below the installed version. This removes historical matches; it does not verify CachyOS patch contents. Foreign packages and notices without usable fix versions remain for review. A missing or failed `vercmp` makes the advisory check incomplete.

Additional registration examples:

```bash
netwatch add desktop arch --host my-desktop
netwatch add workstation cachyos --host my-workstation
netwatch add analysis conda --path /opt/conda/envs/analysis
netwatch add laptop brew
```

Homebrew coverage is reported per formula. A scan that ran but skipped packages clears findings only for the formulae it checked; skipped formulae and refused taps keep their earlier findings marked `unknown`, and `check` says how many formulae were not scanned. A finding is retained only while the version it was reported for is still installed: uninstalling a formula, or upgrading one Homebrew keeps skipping, retires its earlier finding. A keg whose formula can no longer be loaded (its tap was untapped, or the formula left core) is still installed: netwatch keeps it in the inventory, never counts it as scanned or clean, and its earlier finding stays marked `unknown` until the keg is removed or its formula is available again. Homebrew's `outdated_without_sbom` formulae count as uncovered too, because its results for those describe the current formula version rather than the installed one, and a finding that names a version the host does not have is not published. If installed versions change while the scan runs, the check re-collects inventory, keeps the earlier findings and asks for a re-run rather than clearing anything on evidence it cannot tie to this host. `check --offline` skips Homebrew's scan, which needs the target, and reports the advisory check as incomplete with earlier findings retained. Unlike the other advisory sources, Homebrew's scan runs on the target on every online check regardless of `--refresh`; the one-hour cache applies to the other feeds only. Casks are never scanned by Homebrew, produce no pwn.watch leads, and are tracked as inventory and updates only. A Homebrew older than 7.0 has no `vulns` command: the report says so, marks the advisory check incomplete and exits 1 rather than claiming a clean scan. Homebrew is never run as root, and a target whose `id -u` is 0 is refused during collection.

### uv tool and pipx environments

These two kinds manage a single tool venv each. Register one from a scan (preferred, because the scan records what it inspected), or add it directly:

```bash
netwatch add mylabel uvtool --path ~/.local/share/uv/tools/ruff
netwatch add pyflakes pipx --path ~/.local/pipx/venvs/pyflakes
```

The name is your label. netwatch reads the manager's own receipt inside the venv (`uv-receipt.toml`, `pipx_metadata.json`), so a label that differs from the tool name is fine and `check` still knows what it is tracking.

`check` inventories the venv through its own interpreter, asks `uv pip list --outdated` for candidates, queries OSV for every installed distribution, compares dependency consistency, and verifies the launchers the manager says it exposed. A launcher that is missing, invokes another entry point, or points outside the venv is a finding; a native binary (ruff, uv themselves) cannot be entry-point verified, and the report says so rather than implying it was checked.

**Probe token.** The first check or preview writes `<venv>/.netwatch-probe` containing one line, `netwatch-probe: <uuid>`. It is created once, never rewritten, and only after the identity read has passed. Its purpose is to bind an approval to an installation: apply refuses if the token on disk is not the one the preview recorded, which is how a rebuilt or replaced venv is caught. The token is safe to delete; the next check or preview writes a fresh one, and any saved preview for that target stops being appliable.

**Approval is constrained twice.** Preview derives the upgrade set under the environment's own bounds — the `Requires-Dist` metadata of the distributions it is *not* replacing, with PEP 508 markers evaluated against the venv's interpreter — and writes both the pins and those retained bounds into a constraints file beside the database at `constraints/preview-<nonce>.txt`. Apply runs exactly:

```
uv pip install --python <venv>/bin/python -c <plan constraints file> <recorded index options> <pins>
```

That is one command for both kinds, with no `--upgrade` flag, so uv keeps installed versions except where a pin requires a change. A recorded per-tool index (a private index passed to `uv tool install`, or pipx's `pip_args`/pip configuration) is replayed, because without it the install would resolve a private-index tool against the public default index. Credentials in that index URL are used at the moment of use and never stored; the plan records a redacted form and its digest.

**What apply verifies, in order.** Plan state and expiry; the recorded path still resolving to the recorded realpath; runtime identity (the manager metadata still naming this tool); the probe token; the inventory digest, which covers each distribution's metadata and origin bytes, not just versions; the interpreter's own marker values; the requested extras; the index-option digest; the constraints digest; and a verified copy of those bytes, which is what the command actually runs. The approval is also bound to uv's configuration environment — the `UV_*`/`PIP_*` variables, the configuration files discovery would read, and the uv executable's content — and uv runs from netwatch's state directory so a repository-local `[uv]` configuration cannot shape the resolution.

A successful install is only `applied` if the probe is unchanged, the approved pins are what is installed, dependency consistency did not get worse, no distribution's origin changed, and no distribution the plan held has disappeared. Otherwise the result is `needs_attention` with the problems named. A failure that changed nothing — same token, same inventory digest, same consistency report, and no file disagreeing with its own `RECORD` hashes — returns the plan to `proposed` so you can retry; anything else locks the target until you inspect it.

**Lifecycle states.** `status` prints the state whenever it is not `live`, with the action that clears it:

| State | Meaning | Recovery |
| --- | --- | --- |
| `live` | the venv is present and in service | — |
| `not_bindable` | no usable probe token, so an approval cannot be bound | delete `<venv>/.netwatch-probe` and re-run `check`; netwatch writes a fresh one, or reports the permission problem again |
| `identity_mismatch` | the venv no longer names this tool | inspect it, then re-register or retire the target; only a clean `check` clears it |
| `unresolved_path` | the recorded path has been missing for two consecutive checks | restore the venv; a later check that finds it again returns the target to service |
| removed | retired with `targets remove` | re-register or `add` the same name to revive it |

A lifecycle change never invalidates a saved preview by itself; a changed probe token or inventory does. Previews expire after one hour, and a write-capable command that meets an expired proposal marks it stale and deletes its constraints file.

Probe corrections are additive: a target removed and revived is a new registration with a bumped generation, so plans approved before the removal are refused as stale rather than applied to a target that was retired in between.

### Retiring a target

```bash
netwatch targets remove server
```

Retirement marks the row removed, keeps its history and frees its name; proposed plans for the target, and for any other target on the same venv, are marked stale in the same transaction. It refuses while an update for that target or venv is `running` or locked `needs_attention`, because the venv is still being inspected.

A scan only sees what lies under the root you give it; it does not consult uv's or pipx's own registry of other locations. Uninstalled lockfile dependencies, containers, Snap and Flatpak are not assessed. Source forks need separate assessment. Held packages and project constraints can prevent an update from reaching an advisory's fixed version.

## Cache and network

| Command | Behavior |
| --- | --- |
| `check NAME` | Collect inventory and discover updates; use advisory cache up to one hour old. |
| `check NAME --refresh` | Also fetch fresh advisories. |
| `check NAME --offline` | Still collect inventory, including over SSH. Use fresh cached advisories and skip update discovery. |
| `check NAME --context` | Also fetch/cache cve.now context and locally match pwn.watch incidents and Cloudflare Zero Wire briefings. |
| `status NAME` | Read stored results without connecting. |
| `scan ROOT --list` | Classify what a root contains. No `git`, no `gh`, no package tools, and it does not open the database. |
| `scan ROOT` | Also run `git` reads in each classified checkout, query OSV for lockfile-resolved versions, and write tickets into owned repos. |
| `report PATH` | The same reads and one ticket write for a single checkout, whatever its owner. |

Ubuntu and Arch checks download public feeds. Python/npm checks query `api.osv.dev` with package names and versions. Package managers may contact their repositories during update discovery.

The Ubuntu feed was about 354 MB at the 2026-10-23 check. netwatch caches about 7 MB of Noble data, but download and decoding need more memory than the cache size.

`check` exits 1 when collection, advisory checking or update discovery is incomplete, including when `--offline` skips update discovery. Requested context that fails or reaches its lookup limit also causes exit 1, independently of `advisory_check_ok`. Earlier findings and update observations are retained with their timestamps; the report identifies the failed or skipped step.

## Optional security context

Add `--context` to a check to use all three supplementary sources. It is opt-in for each invocation; it does not register another target or change package matching.

```bash
netwatch check server --context
netwatch check server --context --refresh
netwatch status server --all
netwatch --json status server
```

| Source | What netwatch uses | What leaves your machine |
| --- | --- | --- |
| [cve.now](https://cve.now/) | Source-reported CVSS, CISA Known Exploited Vulnerabilities (KEV) listing, Exploit Prediction Scoring System (EPSS) threshold-reached dates, public-exploit indicators, upstream attribution and labeled model summaries. | CVE IDs referenced by existing findings; no inventory or lockfile upload. |
| [pwn.watch](https://pwn.watch/) | Live patch and supply-chain incidents overlapping finding/advisory IDs or package/source names and product tags. | A request for the public incident catalog; relevance is matched locally. |
| [Cloudflare Zero Wire](https://radar.cloudflare.com/security/zero-wire) | Curated briefings on critical Internet-facing vulnerabilities whose CVE tags match CVE IDs referenced by existing findings: title, link, Cloudflare priority label, dates and topic tags. | A request for the public RSS feed; relevance is matched locally. |

cve.now is queried once per distinct CVE, in sorted-ID order, up to 20 IDs per environment per check. No new CVE lookup starts once 60 seconds have elapsed; an in-flight request can finish afterward. Omitted IDs and failed lookups leave context marked `incomplete`. EPSS threshold dates are not current probability scores. An absent exploitation signal does not establish safety. Model summaries are explanatory text, attributed to the named model and cve.now under CC-BY-4.0; upstream records retain their listed licenses.

pwn.watch leads always have `state: review`. Matching uses lowercased exact package/source names, with PyPI punctuation normalization, and fixed aliases: `nodejs` → `node`, `bind9` → `bind`, and `linux-lts`/`linux-zen`/`linux-hardened` → `linux`. A `linux` tag match additionally requires a product name beginning with `Linux kernel`. Broad tags can still produce unrelated leads; missing tags, other aliases and uncollected software can hide relevant incidents. Breach-only, closed and example incidents are excluded. Its `cveIds` field can contain non-CVE advisory IDs; these are preserved without inventing CVE identities.

Zero Wire briefings also have `state: review`. They match only when an exact CVE `<category>` tag equals a CVE ID on an existing finding or its notice references; topic tags such as `Node.js`, `PHP` or `Kernel` are kept for reading but never matched to packages. Briefings without CVE tags, and briefings about software netwatch does not collect (appliances, CMS sites, certificates, Alpine/musl), therefore never appear. The feed is small and curated: absence is not evidence of low risk. netwatch keeps only identities, dates, the `Needs attention`/`Reference` label and tags; the briefing prose, including its upgrade versions and mitigation steps, is not stored or shown. Read the linked briefing yourself. Cloudflare publishes Radar API data under CC BY-NC 4.0 and does not state separate feed terms; netwatch keeps a local cache only and does not redistribute it.

No context source can mark a package affected or fixed, clear an advisory finding, supply an update command, or establish conda/CachyOS patch applicability. A notice-level CVE reference is not a per-package CVE determination. A source's `patched` incident label is not evidence that your installation is patched. netwatch links to incident details but does not import their remediation commands or follow their links.

Context uses the one-hour cache and honors `--refresh` and `--offline`. Failed source checks retain earlier context with its original observation times and `retained: true`; a successful source check replaces that source's context. A later check without `--context`, including the post-update check from `apply`, marks saved context `skipped` and retains it for reference. It does not claim that retained incidents still apply. `status` and `history` remain network-free.

JSON reports store this data separately under `report.context.cve_now`, `report.context.pwn_watch` and `report.context.zero_wire`, each with `status`, `items`, `errors` and fetch `evidence`. Items include `fetched_at`; pwn.watch and Zero Wire also record catalog/feed build time (`generated_at`, `built_at`) and overlap reasons. Changes produce `context_changed` history events, not package-finding events. Default text output shows five records per source; `--all` and JSON expose all saved records.

Context requests accept only the fixed public endpoints. cve.now entry lookups may make one HTTPS redirect to a `*.public.blob.vercel-storage.com` host at the exact same CVE's `/public/entries/ID.json` path, without credentials, ports, queries or fragments. Other redirects are refused. The Zero Wire feed is parsed as XML only after rejecting document type and entity declarations. Responses are bounded to 2 MiB per cve.now entry, 5 MiB for the Zero Wire feed and 20 MiB for the pwn.watch catalog, with a 10-second socket timeout and a 20-second elapsed-read check. These limits do not make the feeds authoritative or guarantee availability.

## Report output

`check` and `status` group findings by package, separate affected packages from notices needing review, and show installed-to-candidate update versions. The default view shows five package groups per category and ten updates. Optional context appears in separate, labeled sections.

```bash
netwatch status server --all   # expand every row
netwatch --json status server  # complete records, including evidence and inventory
```

Color terminals at least 90 columns wide show a summary panel and aligned finding/update tables. Narrower terminals use a stacked layout. The reported-severity column is separate from finding status; empty finding sections remain visible as counts in the summary.

Color terminals show affected findings in red, review findings in yellow and ordinary updates in cyan. Updates marked `[affected]` or `[review]` have an associated finding; the marker does not establish that the candidate fixes it. Source-reported severity is shown separately where available. Pipes and redirected files use plain text. Set `NO_COLOR=1` to disable styling; `--json` always emits plain JSON.

The summary includes observation times, failed checks and the count of historical notices filtered out. Packages with available updates appear first in finding groups; updates for affected packages appear first, followed by review matches and other updates.

## History

```bash
netwatch --json history --since 0
netwatch history --name server
```

Each page contains up to 1,000 events and a `next_cursor`. Save that cursor after processing the page. Reads do not consume events.

Findings have first/last-seen times. History records new or changed findings, failed checks and update attempts. Findings absent from a successful check produce `finding_no_longer_detected` events. When a matching-rule change removes findings, one `findings_reassessed` event records the count and links to the previous scan; it does not report package updates.

## Updates

`preview` saves the update commands, observed candidates and inventory. It expires after one hour; inventory changes require another preview. Approval covers the environment-wide operation, so repository changes can change the versions installed.

| Kind | Apply commands |
| --- | --- |
| Ubuntu | `sudo -n apt-get update`, then `sudo -n apt-get upgrade -y` |
| Arch/CachyOS | `sudo -n pacman -Syu --noconfirm` |
| conda/mamba | `conda update --all --yes --prefix PATH` or its `mamba` equivalent |
| uv | `uv lock --upgrade`, then `uv sync --locked` |
| npm | `npm update --ignore-scripts` |
| brew | `brew update`, then `brew upgrade --formula`, then `brew upgrade --cask`, as the invoking user; never under `sudo` |
| uvtool, pipx | `uv pip install --python <venv>/bin/python -c <constraints file> <recorded index options> <pins>` |

- Arch/CachyOS always perform a full system upgrade.
- Conda/mamba leave pip-installed packages unchanged.
- uv updates within project constraints and syncs default groups.
- npm skips scripts; packages needing build scripts may require follow-up.
- Cask upgrades can need privileges, quit running applications or run installers, and they run as a separate command from formulae so a failure names the right half.
- `brew update` runs first because netwatch suppresses Homebrew's implicit refresh; without it an upgrade can stop at a version the local metadata knows.
- The upgrade steps re-enable Homebrew's normal cleanup, which usually removes the superseded keg so a later check can confirm the new version clean. A formula listed in `HOMEBREW_NO_CLEANUP_FORMULAE` keeps its old keg. If you want to keep the old keg for rollback, upgrade by hand instead.
- The update list marks a pinned formula `[held]` and a cask outside `brew outdated`'s default list `[not in default upgrade as observed]`. The marker compares two queries, so a cask that becomes outdated between them can carry the marker and still be taken by the approved cask upgrade.
- Package scripts and builds can run code and affect services.
- `uvtool`/`pipx` installs run against the venv's own interpreter with the plan's constraints file, and are checked afterwards for the probe token, the installed pins, dependency consistency and origin preservation. A failure that changed nothing returns the plan to `proposed`; visible or partial damage locks it as `needs_attention`. See [uv tool and pipx environments](#uv-tool-and-pipx-environments).

Use the package manager directly if you need to approve an exact list of versions.

### After an update

The result includes `package_state_changed`, `remaining_findings` and `advisory_check_ok`. Ubuntu also reports its reboot-required marker. Check service health and restart requirements yourself; netwatch does not restart services or roll back changes.

### After a failure

A failed or interrupted update leaves `needs_attention` or `running`, blocking another update to that registration.

Inspect the target and confirm the update process has stopped—an SSH disconnect alone does not establish that. Repair package state if needed, then record your action:

```bash
netwatch resolve PLAN_ID --note 'Confirmed update stopped; repaired package state'
```

Replace `PLAN_ID` and the note with the attempt you inspected. `resolve` clears the block; it does not undo changes. Create a fresh preview before retrying.

## Storage

Default: `~/.local/state/netwatch/state.db`, created with mode 600.

```bash
netwatch --db /path/to/state.db status
```

Back up this file to preserve inventories and update history. Records are not automatically pruned. Schema 10 databases upgrade in place to schema 11 (target lifecycle columns, plus `scan_runs` and `scan_records` for stored scans); schema 11 is accepted as-is; anything else is refused rather than migrated. A newer schema is never opened and stamped back down.

Approval artifacts live beside the database, in `constraints/` next to the database file, so a `--db /tmp/state.db` run writes there rather than into the default state directory. Unreferenced artifacts older than an hour are cleaned by the next write-capable command.
