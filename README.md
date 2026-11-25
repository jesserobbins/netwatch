# netwatch

netwatch tracks vulnerabilities and available updates across your machines and development environments, then lets you review and apply updates.

- Checks Ubuntu, Arch/CachyOS, conda/mamba, uv, npm and Homebrew environments locally or over SSH, plus uv-tool and pipx tool venvs by path.
- Gets Homebrew advisories for formulae from Homebrew's own scan, and tracks casks for updates only.
- Matches installed packages against Canonical, Arch and OSV advisories.
- Scans a filesystem root to find those environments, including the uv-tool and pipx venvs a Mac already has, and writes a `.netwatch` ticket into the git checkouts it owns.
- Binds each tool-venv approval to a probe token and installs the pinned set under the environment's own declared bounds.
- Optionally adds cve.now context, pwn.watch incident leads and Cloudflare Zero Wire briefings for review with `check --context`.
- Stores findings and history in SQLite, with text and JSON output for you or your agent.

![netwatch status showing package findings, reported severity and available updates](docs/status-screenshot.png)

## Quick start

Requires Python 3.12+ and Git.

```bash
git clone https://github.com/lhl/netwatch.git
cd netwatch
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install .
netwatch demo
```

The demo checks and updates a synthetic package in temporary state without making network requests or changing your installed software.

To skip the environment steps, run the bundled script — it builds `.venv`, installs the pinned dependencies and netwatch, and starts it:

```bash
./netwatch-run.sh          # prints the overview: the daily loop, commands and kinds
./netwatch-run.sh status   # any command, with its arguments passed through
```

It reinstalls only when `pyproject.toml` or `requirements.lock` change, writes progress to stderr so `--json` stays clean, and takes `NETWATCH_VENV` / `NETWATCH_PYTHON` to build somewhere else or with another interpreter.

## Usage

### Check a Mac

```bash
netwatch add laptop brew
netwatch check laptop
```

Homebrew formulae get advisories from Homebrew's own scan. Casks are collected and updated, and Homebrew never scans them for vulnerabilities. To find the tool venvs a Mac already has:

```bash
netwatch scan ~/.local/share/uv/tools --list
netwatch scan ~/.local/share/uv/tools --register 1 3
netwatch add ruff-tool uvtool --path ~/.local/share/uv/tools/ruff
```

Homebrew needs a `vulns` command, netwatch never runs it as root, and a remote Mac needs Remote Login enabled. See the [macOS guide](docs/MACOS.md) for host setup, Homebrew coverage, updating and troubleshooting.

### Check a Linux host

For an Ubuntu **24.04 LTS, amd64** machine, replace `my-server` with your SSH alias:

```bash
netwatch add server ubuntu --host my-server
netwatch check server
```

OS updates need `sudo -n` access. Ubuntu matching covers published Noble fixes and excludes Pro/ESM. CachyOS findings need investigation. See [environment support](docs/USAGE.md#environments).

### Check a project or environment

These work on any host:

```bash
netwatch add api uv --path /srv/api
netwatch add frontend npm --path /srv/frontend
netwatch add training mamba --path /opt/conda/envs/training
netwatch check
```

uv checks the project's `.venv`; npm checks installed dependencies. Remote targets need their package tools available over SSH.

Reports show affected packages, advisory links, fix versions, available updates and failed checks.

Python/npm checks send package names and versions to OSV. Add optional incident and exploitation context with:

```bash
netwatch check server --context
```

This sends referenced CVE IDs to cve.now and downloads pwn.watch's public incident catalog and Cloudflare's Zero Wire RSS feed for local matching. Context does not change package applicability or update commands. Tag-based incident leads require investigation; they are not confirmed vulnerabilities. See [optional security context](docs/USAGE.md#optional-security-context).

### Find what is on a machine

Point a scan at a directory instead of naming every environment by hand:

```bash
netwatch scan ~/GitHub --list   # classify only: no git, no gh, no package tools, no database
netwatch scan ~/GitHub          # also write tickets into the repos you own
netwatch scan ~/GitHub --register 1 3
netwatch report ~/src/some-checkout   # one ticket, any owner, on request
```

A scan separates **tool venvs** (uv tool, pipx — upgradeable, registerable as targets) from **git checkouts** (never targets: they get a `.netwatch` file listing drift, unpinned manifests and vulnerable locked versions, with the action to take). Nothing is registered without `--register`, and `--list` is safe to point anywhere because it reads directory structure and stops there. See [find what is on a machine](docs/USAGE.md#find-what-is-on-a-machine) and [repo tickets](docs/USAGE.md#repo-tickets).

### Check a tool venv

```bash
netwatch add ruff-tool uvtool --path ~/.local/share/uv/tools/ruff
netwatch check ruff-tool
netwatch preview ruff-tool
```

A tool venv is bound to an installation by a probe token and upgraded with one constrained `uv pip install`, with the environment's own declared bounds and PEP 508 markers applied. `apply` reports `applied`, `needs_attention` or, when nothing changed, returns the plan for another try. See [uv tool and pipx environments](docs/USAGE.md#uv-tool-and-pipx-environments).

### Read status and history

```bash
netwatch list                   # registered environments
netwatch status                 # cached reports; no connections
netwatch history --name server  # changes and update attempts
netwatch check server --refresh # fetch fresh advisories
```

Advisories are cached for one hour, except Homebrew's scanner, which runs on the target on every online check. Failed checks preserve earlier findings and appear in the report. The default report groups findings by package and shows a short update list; add `--all` to `status` or `check` to expand it. Color terminals highlight affected findings in red, review findings in yellow and other updates in cyan. Use `NO_COLOR=1` for plain output.

### Apply updates

`apply` updates the **whole selected environment**, including dependencies, so review its scope and back up before running it. Tool-venv upgrades (`uvtool`, `pipx`) have been exercised end to end on the machine they were developed on, in throwaway tool homes; OS package-manager updates have not. Start with a disposable environment.

```bash
netwatch preview server
```

Review the commands and scope. Replace `PLAN_ID` with the returned ID:

```bash
netwatch apply PLAN_ID --yes
netwatch status server
```

OS updates need `sudo -n` access. After applying, netwatch checks installed versions again. Check services and restart/reboot requirements afterward. [Update commands and recovery](docs/USAGE.md#updates).

### Query from an agent or script

```bash
netwatch --json status
netwatch --json history --since 0
```

Pass the returned `next_cursor` as `--since` to read later events. Give agents read-only access; run `apply` yourself with an account that can update the target.

## Reference

- [macOS guide](docs/MACOS.md): Homebrew coverage, host setup, updating and troubleshooting on a Mac.
- [Usage guide](docs/USAGE.md): supported environments, scanning and tickets, probing and constrained approvals, caching, update commands and recovery.
- [Design contract](docs/DESIGN.md): modules and the behavior to preserve.
- `netwatch --help` or `netwatch COMMAND --help`: command arguments.

Data lives in `~/.local/state/netwatch/state.db`. To use another database, put `--db /path/to/state.db` before the command.

## Development

```bash
python3 -B -m unittest discover -s tests -v
python3 -B scripts/check_package.py
```

For development, install the pinned dependencies with `python3 -m pip install --require-hashes -r requirements.lock`. The packaging check downloads those wheels, then installs and tests from the local copies.

Add package-manager support in [`netwatch/adapters.py`](netwatch/adapters.py), advisory matching in [`netwatch/sources.py`](netwatch/sources.py), and tool-venv behavior in [`netwatch/venvflow.py`](netwatch/venvflow.py) with its pure state machine in [`netwatch/lifecycle.py`](netwatch/lifecycle.py). See the [design contract](docs/DESIGN.md).

## License

[Apache License 2.0](LICENSE).
