# netwatch on macOS

netwatch tracks vulnerabilities and available updates on a Mac. It covers
Homebrew formulae and casks, the tool venvs that uv and pipx create, and the
Python and npm projects you point it at. This page runs from setup to an applied
upgrade. The [usage guide](USAGE.md) holds the reference for everything else.

## What netwatch covers on a Mac

| What is on the Mac | Collected | Advisories |
| --- | --- | --- |
| Homebrew formulae | yes | Homebrew's own OSV scan, reported per formula |
| Homebrew casks | yes | none. Homebrew never scans casks |
| uv tool venvs | yes, by path | OSV for the venv's installed packages, dependencies included |
| pipx venvs | yes, by path | the same |
| uv projects | yes, by path | OSV for installed PyPI packages |
| npm projects | yes, by path | OSV for installed npm packages, transitive dependencies included |
| conda prefixes | yes, by path | OSV for pip and PyPI-origin entries only |

Four things are outside this release:

- MacPorts. There is no `macports` kind and no advisory path for it.
- The App Store. Software installed through `mas` is not in the inventory.
- Xcode and the command-line developer tools. Their SDK content is not read.
- Homebrew on Linux. A `brew` target must be a macOS host, and netwatch refuses
  one anywhere else.

## Before the first run

netwatch itself needs Python 3.12 or newer and Git. [Install and try](USAGE.md#install-and-try)
in the usage guide has the two commands. A `brew` target needs
Homebrew with a `vulns` command, which netwatch tests by reading `brew commands`
and looking for `vulns` in the output. It never reads a version number. A
Homebrew without that command produces an incomplete advisory check, not a clean
one. [Reading a Homebrew report](#reading-a-homebrew-report) covers the result.

Homebrew lives at `/opt/homebrew` on Apple silicon and at `/usr/local` on Intel.
A non-interactive command has no login shell, so neither prefix is on its
`PATH`. netwatch passes a fixed `PATH` covering both, along with
`HOMEBREW_NO_AUTO_UPDATE=1` and `NONINTERACTIVE=1`, to every brew command it
runs. You do not set any of that yourself.

netwatch refuses to run Homebrew as root. It reads `id -u` during collection and
stops when the answer is 0. Run it as the account that owns the Homebrew
installation.

To check a Mac over SSH, enable Remote Login on that Mac first, under System
Settings, General, Sharing. Then register the target with `--host` and an SSH
alias that works for the account netwatch runs as.

## First run

Do not start with a scan of your home directory. `scan` walks to depth four by
default, and a Mac home holds Library and Documents, which cost time and hold no
tool venvs. Point the scan at the manager roots instead.

A uv tool venv sits under `~/.local/share/uv/tools`, and a pipx venv under
`~/.local/pipx/venvs`. Look before you scan:

```bash
netwatch scan ~/.local/share/uv/tools --list
```

`--list` reads directory structure and nothing else. It runs no git, no gh and
no package tool, and it does not open the database. When the rows look right,
run the scan for real and register the ones you want:

```bash
netwatch scan ~/.local/share/uv/tools
netwatch scan ~/.local/share/uv/tools --register 1 3
```

Registration indexes into the stored run, so a tree that changed since the scan
cannot redirect it to a different tool. A batch is all or nothing, at most five
indices, and every item is re-verified on disk before anything is written.

The Homebrew side of the Mac is one target for the whole host:

```bash
netwatch add laptop brew
netwatch check laptop
```

Then read what you have:

```bash
netwatch status laptop
netwatch status --all
```

netwatch also finds checkouts without being asked: any git repository you point
it at gets a `.netwatch` ticket when a GitHub remote names an account it can
claim. See [repo tickets](USAGE.md#repo-tickets).

## Reading a Homebrew report

Homebrew's scanner is the source, and netwatch reports its result per formula.
A scan that ran but skipped packages clears findings only for the formulae it
checked. A skipped formula keeps the finding it had, marked `unknown`, and
`check` says how many formulae it did not scan.

A formula the scan could not map to an upstream repository and tag arrives in
one of two shapes. An unscanned formula has a reason attached. A keg whose
formula can no longer be loaded, because the tap was untapped or the formula
left core, is still installed and still in the inventory. netwatch never counts
an unloadable keg as scanned or as clean, and its earlier finding stays
`unknown` until the keg is gone or the formula comes back.

Homebrew also reports `outdated_without_sbom` formulae. Its result for one of
those describes the current formula version, not the installed one, so netwatch
counts it as uncovered. For the same reason netwatch drops a finding that names
a version this host does not have.

If installed versions change while the scan runs, no result is used. The check
re-reads the inventory, keeps the earlier findings, asks for a rerun, and reports
the advisory check as incomplete.

Casks are inventoried and updated, and they are never scanned: Homebrew does not
scan them, and netwatch does not derive matches for them. A cask has no advisory,
whatever its version.

`check --offline` skips Homebrew's scan, because the scan needs the target. The
advisory check is incomplete and earlier findings are retained. Unlike the other
advisory sources, the one-hour cache does not cover Homebrew's scanner: every
online check runs it, with or without `--refresh`.

Warnings from a check look like this. The values are synthetic:

```text
Coverage: Homebrew's scan needs the target and was skipped in offline mode; prior findings retained
Coverage: this Homebrew has no vulnerability scanner; no formula was assessed
Coverage: 2 formulae were scanned against the current formula version, not the installed one
```

An incomplete advisory check makes `check` exit 1. A finding you had before is
still there, and it is not evidence of a clean host.

## Updating on a Mac

`preview` saves the plan, and `apply` runs exactly that plan as the invoking user,
never under `sudo`:

```bash
netwatch preview laptop
netwatch apply PLAN_ID --yes
netwatch status laptop
```

For Homebrew the plan is three commands in order: `brew update`, then
`brew upgrade --formula`, then `brew upgrade --cask`. The refresh runs first
because netwatch suppresses Homebrew's own, and an upgrade without it can stop at
a version the local metadata knows.

The two upgrade steps re-enable Homebrew's cleanup, so the superseded keg is
usually removed and a later check can confirm the new version clean. That also
means an upgrade is not a rollback path. If you want the old keg kept, add the
formula to `HOMEBREW_NO_CLEANUP_FORMULAE` or upgrade it by hand.

Formula and cask upgrades are separate commands, so a failure names the right
half. A cask upgrade can ask for privileges, need a running application to quit,
or run an installer. Treat an approved cask upgrade as a change to the running
system, not just to files in the Homebrew prefix.

A tool venv upgrades through one constrained command:

```bash
netwatch preview ruff-tool
netwatch apply PLAN_ID --yes
```

The install runs against the venv's own interpreter with the plan's constraints
file, which carries both the pins and the bounds the venv declares. `apply`
reports `applied` only when the probe token is unchanged, the approved pins are
installed, dependency consistency did not get worse, no package origin changed
and no held package disappeared. Anything else is `needs_attention` with the
problems named, and a failure that changed nothing returns the plan to
`proposed` so you can retry.

Check services and restart requirements yourself. netwatch does not restart
services and does not roll back.

## When something looks wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `check` exits 1 and says the advisory check is incomplete | Homebrew's scan was skipped, refused a formula, or ran against an inventory that changed | Read the coverage line, then run `check` again. An incomplete check is not a clean one |
| A formula is listed as unloadable | The keg is installed, and its formula cannot be loaded because the tap is gone or the formula left core | Reinstall or remove the keg, or add the tap back |
| A cask has no advisory | Casks are never scanned | Read its upstream changelog. netwatch cannot help here |
| A target reports `not_bindable` | There is no usable probe token, so an approval cannot be bound to the installation | Delete `<venv>/.netwatch-probe` and run `check` again |
| A target reports `identity_mismatch` | The venv no longer names this tool | Inspect it, then re-register or retire the target. Only a clean `check` clears it |
| A target reports `unresolved_path` | The recorded path has been missing for two checks | Restore the venv. A later check returns the target to service |
| A scan finds nothing | The root holds no manager receipt beside a `pyvenv.cfg` | Scan `~/.local/share/uv/tools` or `~/.local/pipx/venvs`, not your home directory |
| `brew: command not found` over SSH | The remote command has no login shell | netwatch supplies the prefix `PATH` itself. Check that the target is the Mac, not a Linux host |
| Registration is refused because the account is root | Homebrew must not run as root | Re-run as the user who owns the Homebrew installation |

## Limits on macOS

Homebrew's scanner covers only formulae it can map to an upstream repository and
tag. Some formulae stay uncovered on every check, and no setting changes that.

Casks carry no advisories. MacPorts, the App Store and Xcode content are outside
the inventory.

A held formula or a pinned cask can block an upgrade from reaching a fixed
version. The update list marks a held formula `[held]`.

A lifecycle change does not invalidate a saved preview by itself. A changed
probe token or a changed inventory does.
