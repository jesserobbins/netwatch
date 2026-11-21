"""Environment adapters: ordinary functions and fixed package-manager commands."""
import json
import os
import re
import shlex
import signal
import subprocess
from pathlib import PurePosixPath

from .core import Error, name, text


KINDS = ("ubuntu", "arch", "cachyos", "conda", "mamba", "uv", "npm", "brew")

# Homebrew and MacPorts are not on the PATH of a BatchMode SSH command. The
# prefix travels inside the argv rather than being resolved at registration,
# because `add` must not connect and `commands(t)` is compared against the
# approved plan body.
MAC_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


def brew_env(*args, cleanup=True):
    """Fixed PATH and Homebrew's non-interactive settings, carried in argv.

    `cleanup=False` unsets HOMEBREW_NO_INSTALL_CLEANUP so an approved upgrade may
    remove the superseded keg; read-only commands keep it set. `env -u` is needed
    because a locally exported variable would otherwise be inherited.
    """
    pairs = {"PATH": MAC_PATH, "HOMEBREW_NO_AUTO_UPDATE": "1", "NONINTERACTIVE": "1"}
    if cleanup:
        pairs["HOMEBREW_NO_INSTALL_CLEANUP"] = "1"
    head = ["env"] + [f"{key}={value}" for key, value in pairs.items()]
    if not cleanup:
        # Unset an inherited value; `env` applies -u before any assignments, and none
        # of the assignments may re-set the variable.
        head = ["env", "-u", "HOMEBREW_NO_INSTALL_CLEANUP"] + head[1:]
    return [*head, *args]


def target(name_, kind, host="local", path=None):
    name(name_)
    if kind not in KINDS:
        raise Error("Unsupported environment kind")
    text(host, "SSH alias")
    if host.startswith("-") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@" for c in host):
        raise Error("Host must be local or an explicit SSH alias/user@host")
    if kind in ("conda", "mamba", "uv", "npm"):
        text(path, "absolute environment/project path")
        if not PurePosixPath(path).is_absolute():
            raise Error("Environment/project path must be absolute")
    elif path is not None:
        raise Error("OS environments do not take a project path")
    return {"name": name_, "kind": kind, "host": host, "path": path}


def step_label(argv):
    """The tool and its subcommand, ignoring an `env K=V` prefix or SSH wrapper."""
    args = list(argv)
    if args and args[0] == "ssh":
        try:
            args = shlex.split(args[-1])
        except ValueError:
            return args[0]
        # A project target is wrapped as `cd -- PATH && <command>`.
        if args[:2] == ["cd", "--"] and "&&" in args:
            args = args[args.index("&&") + 1:]
    if args and args[0] == "env":
        args = args[1:]
        while args and ("=" in args[0] or (args[0] == "-u" and len(args) > 1)):
            args = args[2:] if args[0] == "-u" else args[1:]
    if args and args[0] == "sudo":
        args = args[1:]
        while args and args[0].startswith("-"):
            args = args[1:]
    return " ".join(args[:3]) if args else str(argv[0])


def run(t, argv, *, ok=(0,), timeout=120):
    """SSH needs one quoted remote command; no advisory text enters it."""
    cwd = t.get("path") if t["kind"] in ("uv", "npm") else None
    if t["host"] != "local":
        command = shlex.join(argv)
        if cwd:
            command = "cd -- " + shlex.quote(cwd) + " && " + command
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", t["host"], command]
        cwd = None
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            out, err = process.communicate(timeout=timeout)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"Command unavailable or timed out: {step_label(argv)}") from exc
    if len(out) + len(err) > 20 * 1024 * 1024:
        raise Error("Command output exceeds 20 MiB")
    if process.returncode not in ok:
        # Avoid storing tool output that can include credentials or private URLs.
        raise Error(f"Command failed: {step_label(argv)} (exit {process.returncode})")
    return out.decode("utf-8")


def package(n, v, ecosystem, **extra):
    return {"name": text(n, "package name"), "version": text(v, "version"), "ecosystem": ecosystem, **extra}


def os_info(t, runner):
    if t["kind"] == "brew":
        if runner(t, ["uname", "-s"]).strip() != "Darwin":
            raise Error("Homebrew adapter requires a macOS host")
        return {"ID": "macos", "PLATFORM": runner(t, ["uname", "-m"]).strip(),
                "VERSION": runner(t, ["sw_vers", "-productVersion"]).strip(),
                "UID": runner(t, ["id", "-u"]).strip()}
    data = {}
    for line in runner(t, ["cat", "/etc/os-release"]).splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            data[key] = value.strip('"\'')
    if t["kind"] == "ubuntu" and (data.get("ID"), data.get("VERSION_CODENAME")) != ("ubuntu", "noble"):
        raise Error("Ubuntu adapter currently matches only Ubuntu 24.04 noble")
    if t["kind"] in ("arch", "cachyos") and data.get("ID") != t["kind"]:
        raise Error("Configured OS differs from collected OS")
    return data


def ubuntu_inventory(t, runner):
    os_info(t, runner)
    if runner(t, ["dpkg", "--print-architecture"]).strip() != "amd64":
        raise Error("Ubuntu advisory support currently requires amd64")
    fmt = "${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\t${db:Status-Status}\\n"
    result = []
    for line in runner(t, ["dpkg-query", "-W", "-f=" + fmt]).splitlines():
        n, v, source, sv, arch, status = line.split("\t")
        if status == "installed":
            result.append(package(n.split(":")[0], v, "Ubuntu", source=source, source_version=sv, architecture=arch))
        elif status not in ("not-installed", "config-files"):
            raise Error("Package database has unfinished operations; repair it before checking")
    return result


def arch_inventory(t, runner):
    os_info(t, runner)
    foreign = {line.split()[0] for line in runner(t, ["pacman", "-Qm"], ok=(0, 1)).splitlines()}
    return [package(*line.split(), "Arch", foreign=line.split()[0] in foreign)
            for line in runner(t, ["pacman", "-Q"]).splitlines()]


def valid_arch_version(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_:~\-]{0,255}", value) is not None


def arch_compare(t, pairs, runner=run):
    """Use the target's vercmp in bounded batches, including over SSH."""
    if any(not valid_arch_version(v) for pair in pairs for v in pair):
        raise Error("Unsupported Arch version syntax")
    result = {}
    script = 'while [ "$#" -ge 2 ]; do vercmp "$1" "$2" || exit; shift 2; done'
    for start in range(0, len(pairs), 64):
        batch = pairs[start:start + 64]
        try:
            output = runner(t, ["sh", "-c", script, "netwatch-vercmp", *[v for pair in batch for v in pair]])
            values = [int(line) for line in output.splitlines()]
            if len(values) != len(batch):
                raise ValueError()
        except (Error, ValueError) as exc:
            raise Error("Arch version comparison failed; check vercmp is available on the target") from exc
        result.update((pair, (value > 0) - (value < 0)) for pair, value in zip(batch, values))
    return result


def conda_inventory(t, runner):
    rows = json.loads(runner(t, [t["kind"], "list", "--json", "--prefix", t["path"]]))
    return [package(r["name"], r["version"], "PyPI" if r.get("channel") == "pypi" else "Conda",
                    build=r.get("build_string", r.get("build", ""))) for r in rows]


def uv_inventory(t, runner):
    python = t["path"].rstrip("/") + "/.venv/bin/python"
    rows = json.loads(runner(t, ["uv", "pip", "list", "--format", "json", "--python", python]))
    return [package(r["name"], r["version"], "PyPI") for r in rows]


def npm_inventory(t, runner):
    # Fail incomplete/broken dependency trees, rather than resolving old findings.
    tree = json.loads(runner(t, ["npm", "ls", "--all", "--json"]))
    result = {}
    def visit(node):
        for n, row in node.get("dependencies", {}).items():
            if row.get("missing") or row.get("invalid") or not row.get("version"):
                raise Error("npm dependency tree is incomplete")
            p = package(n, row["version"], "npm")
            result[(n, row["version"])] = p
            visit(row)
    visit(tree)
    return list(result.values())


# Homebrew writes a revision into the keg name (`ffmpeg 9.0.2_1`), so `_` is legal;
# 21 formulae on the reference host carry one.
BREW_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~,-]{0,127}")


def brew_base(version):
    """`9.0.2_1` -> `9.0.2`: `brew vulns` reports the upstream version.

    Only a trailing `_<digits>` is a revision, matching Homebrew's own parse; an
    underscore inside the version itself is part of the version.
    """
    return re.sub(r"_\d+$", "", version)


def brew_considered(t, runner):
    """The formulae `brew vulns` actually considers.

    `brew list --versions` lists more than this: on the reference host 269 names
    against `brew info --installed`'s 236, so coverage claimed from the wider list
    would include formulae Homebrew never looked at.

    Returns (names, aliases): the considered set and the full_name -> name map.
    """
    data = json.loads(runner(t, brew_env("brew", "info", "--installed", "--json=v2"), timeout=300))
    try:
        names = {text(entry["name"], "formula name") for entry in data["formulae"]}
        # `brew vulns` reports `full_name`, which is tap-qualified for third-party taps
        # (scouzi1966/afm/afm-next on this host) and plain for core.
        aliases = {text(entry["full_name"], "formula full name"): text(entry["name"], "formula name")
                   for entry in data["formulae"] if entry.get("full_name")}
    except (KeyError, TypeError) as exc:
        raise Error("Unrecognized Homebrew installed formulae output") from exc
    return names, aliases


def brew_formula_inventory(t, runner):
    """Formulae only. Advisory reconciliation must not pay for a cask listing."""
    os_info(t, runner)
    result = []
    for line in runner(t, brew_env("brew", "list", "--versions")).splitlines():
        parts = line.split()
        if len(parts) < 2 or any(BREW_VERSION.fullmatch(value) is None for value in parts[1:]):
            raise Error("Unrecognized Homebrew inventory line")
        result.extend(package(parts[0], version, "Homebrew") for version in parts[1:])
    return result


def brew_inventory(t, runner):
    """One row per installed keg version, formulae then casks."""
    if os_info(t, runner)["UID"] == "0":
        # Homebrew must not run as root, and every check or apply path collects
        # inventory first, so refusing here covers all of them without adding an
        # unapproved command to the apply sequence.
        raise Error("Homebrew must not run as root; re-run as the invoking user")
    result = []
    for ecosystem, argv in (("Homebrew", ["brew", "list", "--formula", "--versions"]),
                            ("Homebrew-cask", ["brew", "list", "--cask", "--versions"])):
        for line in runner(t, brew_env(*argv)).splitlines():
            parts = line.split()
            if len(parts) < 2 or any(BREW_VERSION.fullmatch(value) is None for value in parts[1:]):
                raise Error("Unrecognized Homebrew inventory line")
            result.extend(package(parts[0], version, ecosystem) for version in parts[1:])
    return result


INVENTORIES = {"ubuntu": ubuntu_inventory, "arch": arch_inventory, "cachyos": arch_inventory,
               "conda": conda_inventory, "mamba": conda_inventory, "uv": uv_inventory, "npm": npm_inventory,
               "brew": brew_inventory}


def inventory(t, runner=run):
    rows = INVENTORIES[t["kind"]](t, runner)
    if len(rows) > 50000:
        raise Error("Inventory exceeds 50,000 packages")
    return sorted(rows, key=lambda p: (p["name"], p["version"], p.get("architecture", "")))


def updates(t, runner=run):
    kind = t["kind"]
    if kind == "ubuntu":
        output = runner(t, ["apt", "list", "--upgradable"])
        return [{"package": line.split("/")[0], "candidate": line.split()[1]}
                for line in output.splitlines() if "/" in line and len(line.split()) >= 2]
    if kind in ("arch", "cachyos"):
        # checkupdates refreshes an isolated sync database, not the live one.
        output = runner(t, ["checkupdates"], ok=(0, 2))
        return [{"package": line.split()[0], "candidate": line.split()[-1]} for line in output.splitlines()]
    if kind in ("conda", "mamba"):
        data = json.loads(runner(t, [kind, "update", "--all", "--dry-run", "--json", "--prefix", t["path"]], timeout=300))
        if data.get("success") is False or data.get("error"):
            raise Error("Environment solver could not determine updates")
        return [{"package": r["name"], "candidate": r["version"]} for r in data.get("actions", {}).get("LINK", [])]
    if kind == "brew":
        return brew_outdated(t, runner)
    if kind == "uv":
        data = json.loads(runner(t, ["uv", "pip", "list", "--outdated", "--format", "json", "--python",
                                    t["path"].rstrip("/") + "/.venv/bin/python"]))
        return [{"package": r["name"], "candidate": r["latest_version"]} for r in data]
    data = json.loads(runner(t, ["npm", "outdated", "--json"], ok=(0, 1)) or "{}")
    return [{"package": n, "candidate": r.get("wanted"), "latest": r.get("latest")} for n, r in sorted(data.items())]



def brew_outdated(t, runner):
    """Pending updates, with held and greedy-only entries marked honestly."""
    def rows(*extra):
        data = json.loads(runner(t, brew_env("brew", "outdated", "--json=v2", *extra), timeout=300))
        # A formula and a cask can share a name, so the identity is the pair. An empty
        # object where an array belongs is malformed, not an empty update list.
        for field in ("formulae", "casks"):
            value = data.get(field)
            if not isinstance(value, list):
                raise Error("Unrecognized Homebrew update output")
        found = {("Homebrew", r["name"]): r for r in data.get("formulae", [])}
        found.update({("Homebrew-cask", r["name"]): r for r in data.get("casks", [])})
        for row in found.values():
            if not isinstance(row.get("name"), str) or not row["name"]:
                raise Error("Unrecognized Homebrew update name")
            for field in ("current_version", "pinned_version"):
                value = row.get(field)
                if value is not None and not isinstance(value, str):
                    raise Error("Unrecognized Homebrew update version")
        return found
    plain, greedy = rows(), rows("--greedy")
    result = []
    for (ecosystem, name), row in sorted(greedy.items(), key=lambda item: (item[0][1], item[0][0])):
        entry = {"package": name, "candidate": row.get("current_version"), "ecosystem": ecosystem}
        if row.get("pinned"):
            entry.update(held=True, held_version=row.get("pinned_version"))
        if (ecosystem, name) not in plain:
            entry.update(greedy_only=True, reason="Excluded from the default outdated list")
        result.append(entry)
    return result

def commands(t):
    """Operator-approved environment-wide updates, not arbitrary feed commands."""
    return {
        "ubuntu": [["sudo", "-n", "apt-get", "update"], ["sudo", "-n", "apt-get", "upgrade", "-y"]],
        "arch": [["sudo", "-n", "pacman", "-Syu", "--noconfirm"]],
        "cachyos": [["sudo", "-n", "pacman", "-Syu", "--noconfirm"]],
        "conda": [["conda", "update", "--all", "--yes", "--prefix", t.get("path")]],
        "mamba": [["mamba", "update", "--all", "--yes", "--prefix", t.get("path")]],
        "uv": [["uv", "lock", "--upgrade"], ["uv", "sync", "--locked"]],
        "npm": [["npm", "update", "--ignore-scripts"]],
        # HOMEBREW_NO_AUTO_UPDATE=1 suppresses Homebrew's implicit refresh, so the
        # plan refreshes first, the way apt-get update and pacman -Syu do. The upgrades
        # run without HOMEBREW_NO_INSTALL_CLEANUP so the superseded keg is removed and a
        # later scan can cover the formula; cleanup stays on for read-only commands.
        "brew": [brew_env("brew", "update"),
                 brew_env("brew", "upgrade", "--formula", cleanup=False),
                 brew_env("brew", "upgrade", "--cask", cleanup=False)],
    }[t["kind"]]
