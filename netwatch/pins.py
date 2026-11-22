"""What to install, from where, and whether the launcher still points at this venv.

Three separate questions, three separate answers:

- `derive` chooses the pinned set from the environment's own declared bounds.
- `origin` says what a distribution's provenance is, per PEP 610.
- `launchers` checks that the console scripts still resolve inside the registered venv.

Nothing here runs an installer or writes a file.
"""
import json
import os
import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from . import sources
from .core import Error, digest

SHEBANG = re.compile(r"^#!\s*(\S+)(?:\s+(.*))?$")
TRAMPOLINE = re.compile(r"""^'''exec'\s+"?([^"\s]+)"?""", re.M)
SCRIPT_SIG = "import re, sys;"


def _dist_info(venv, name):
    wanted = name.lower().replace("_", "-").replace(".", "-")
    root = Path(venv) / "lib"
    for candidate in sorted(root.glob("python*/site-packages")):
        for entry in candidate.glob("*.dist-info"):
            if entry.name.lower().replace("_", "-").split("-")[0] == wanted:
                return entry
    return None


def _requires(venv, name):
    dist = _dist_info(venv, name)
    if dist is None or not (dist / "METADATA").is_file():
        return []
    out, in_requires = [], False
    for line in (dist / "METADATA").read_text(errors="replace").splitlines():
        if not line.strip():
            in_requires = False
        elif line.lower().startswith("requires-dist:"):
            out.append(line.split(":", 1)[1].strip())
        elif in_requires and line[:1] in (" ", "\t"):
            out.append(line.strip())
        else:
            in_requires = False
    return out


def marker_environment(t, runner=None):
    """The PEP 508 environment of the venv's own interpreter.

    Markers like `python_version >= "3.12"` decide whether a bound applies at all; guessing
    from the host's Python would apply another interpreter's bounds to this venv.
    """
    argv = [str(Path(t["path"]) / "bin" / "python"), "-I", "-S", "-c",
            "import json,platform,sys;"
            "print(json.dumps({'os_name':__import__('os').name,"
            "'sys_platform':sys.platform,"
            "'platform_machine':platform.machine(),"
            "'platform_python_implementation':platform.python_implementation(),"
            "'python_version':'.'.join(platform.python_version_tuple()[:2]),"
            "'python_full_version':platform.python_version(),"
            "'implementation_name':sys.implementation.name,"
            "'implementation_version':str(getattr(sys.implementation,'version',None) or ''),"
            "'platform_release':platform.release(),"
            "'platform_system':platform.system()}))"]
    runner = runner or _local_run
    try:
        data = json.loads(runner(argv))
    except Error as exc:
        raise Error("Cannot evaluate environment markers: the venv's interpreter could "
                    "not be run (%s)" % exc) from exc
    data.setdefault("extra", "")
    return data


def _local_run(argv):
    from . import adapters
    return adapters.run({"name": "local", "kind": "uv", "host": "local"}, argv, timeout=60)


def _marker_true(requirement, extras, environment=None):
    """PEP 508: does this marker hold for this venv, under any of its extras?"""
    if requirement.marker is None:
        return True
    environment = dict(environment or {})
    for extra in [""] + list(extras or ()):
        try:
            if requirement.marker.evaluate({**environment, "extra": extra}):
                return True
        except (KeyError, ValueError):
            continue
    return False


def _unknown_extra(requirement, extras):
    """A marker guarded by an extra nobody has told us about."""
    text = str(requirement.marker or "")
    if "extra ==" not in text:
        return False
    names = re.findall(r"""extra\s*==\s*['"]([^'"]+)['"]""", text)
    return any(name not in extras for name in names)


def _satisfies(version, requirement):
    try:
        return Version(version) in requirement.specifier
    except InvalidVersion:
        return False


def derive(venv, packages, candidates, *, extras=(), tool=None, limit=None, environment=None):
    """Choose the pinned set: every eligible upgrade, under the environment's own bounds.

    Two passes, then a fixed point. Pass 1 derives bounds from the full inventory and
    selects upgrades under them; pass 2 re-derives excluding the pass-1 selections and
    re-runs selection, because a distribution being replaced cannot keep its old bound in
    force. The selection only grows, so the loop is bounded by the number of installed
    distributions plus one.
    """
    installed = {p["name"]: p["version"] for p in packages}
    supplied = list(candidates or [])
    supplied_names = [c["name"] for c in supplied]
    if limit is not None:
        supplied = supplied[:limit]
    # The marker environment costs one subprocess, so it is read only when a requirement
    # actually carries a marker.
    def environment_for():
        nonlocal environment
        if environment is None:
            environment = marker_environment({"path": venv})
        return environment

    budget = len(installed) + 1
    retired, selected, blocked = set(), {}, set()
    in_force = {}
    for _ in range(budget):
        constraints = {}
        for name in installed:
            if name in retired:
                # A distribution that is itself being replaced cannot keep its old bound
                # in force: that bound describes the version being left behind.
                continue
            for raw in _requires(venv, name):
                try:
                    requirement = Requirement(raw)
                except InvalidRequirement:
                    continue
                if requirement.url or not _marker_true(
                        requirement, extras,
                        environment_for() if requirement.marker is not None else None):
                    continue
                constraints.setdefault(requirement.name.lower(), []).append(requirement)
                # Keep who imposed the bound: a bound from a distribution that is itself
                # being replaced describes the version being left behind, so it must not
                # reach the installer.
                in_force[_constraint_line(requirement)] = {"requirer": name,
                                                           "package": requirement.name.lower()}
        chosen, blocked = {}, set()
        for candidate in supplied:
            name = candidate["name"]
            if any(not _satisfies(candidate["version"], req)
                   for req in constraints.get(name.lower(), [])):
                blocked.add(name)
                continue
            chosen[name] = candidate["version"]
        grown = set(chosen) - set(selected)
        selected = chosen
        if not grown:
            break
        retired |= set(chosen)
    pins, leads = [], []
    for name, version in sorted(selected.items()):
        pin_extras = set()
        if name == tool:
            pin_extras |= set(extras)
        for other in installed:
            if other in selected or other == name:
                continue
            for raw in _requires(venv, other):
                try:
                    requirement = Requirement(raw)
                except InvalidRequirement:
                    continue
                if requirement.name.lower() != name.lower():
                    continue
                if _unknown_extra(requirement, extras):
                    leads.append({"type": "extras", "package": name, "by": other,
                                  "detail": "referenced with extras %s by %s; pinned without them"
                                            % (sorted(requirement.extras), other)})
                elif _marker_true(requirement, extras,
                                  environment_for() if requirement.marker is not None else None):
                    pin_extras |= set(requirement.extras)
        pins.append({"name": name, "version": version, "extras": sorted(pin_extras)})
    return {"pins": pins, "leads": leads, "excluded": sorted(set(supplied_names) - set(selected)),
            "blocked": sorted(blocked),
            # The same bounds the selection used: an install that is only *selected* under
            # them is not constrained by them, and uv would resolve past them.
            "constraints": sorted(line for line, source in in_force.items()
                                  if source["requirer"].lower()
                                  not in {pin["name"].lower() for pin in pins})}


def _constraint_line(requirement):
    """A constraint line without its marker: the marker already decided it applies."""
    line = requirement.name
    if requirement.extras:
        line += "[%s]" % ",".join(sorted(requirement.extras))
    if requirement.specifier:
        line += str(requirement.specifier)
    return line


def pin_text(pin):
    extras = "[%s]" % ",".join(pin["extras"]) if pin["extras"] else ""
    return "%s%s==%s" % (pin["name"], extras, pin["version"])


def origin(dist_info):
    """PEP 610: what this distribution's provenance actually says.

    Missing means index origin — the normal state of an index install. Readable but
    malformed, or valid JSON that describes no provenance, is **undetermined**: netwatch
    cannot say what its byte-identity means, so the target is not plannable. A readable
    file that fails to read at all is an incomplete observation.
    """
    path = Path(dist_info) / "direct_url.json"
    if not path.exists():
        return ("index", {})
    try:
        raw = path.read_text()
    except OSError as exc:
        return ("unreadable", {"error": str(exc)})
    try:
        data = json.loads(raw)
    except ValueError:
        return ("undetermined", {"error": "direct_url.json is not JSON"})
    if not isinstance(data, dict) or not ({"url", "vcs_info", "dir_info"} & set(data)):
        return ("undetermined", {"error": "direct_url.json describes no provenance"})
    kind = "vcs" if "vcs_info" in data else ("local" if "dir_info" in data else "direct")
    return (kind, data)


def entry_points(venv, name):
    """The console scripts the registered distribution itself declares."""
    dist = _dist_info(venv, name)
    if dist is None:
        return {}
    path = dist / "entry_points.txt"
    if not path.is_file():
        return {}
    current, found = None, {}
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
        elif current == "console_scripts" and "=" in line:
            script, target = line.split("=", 1)
            found[script.strip()] = target.strip()
    return found


def _inside(path, roots):
    """Normalize lexically, then require containment at a path separator."""
    normalized = os.path.normpath(path)
    for root in roots:
        if not root:
            continue
        root = os.path.normpath(root)
        if normalized == root or normalized.startswith(root + os.sep):
            return True
    return False


def launchers(venv, bin_dir, name):
    """Check the console scripts: still there, still ours, still inside this venv.

    A wrapper written by uv or pip may be a plain script or a `#!/bin/sh` trampoline; the
    trampoline's interpreter is the path in its `exec` line, never `/bin/sh`.
    """
    # Containment is checked against both spellings registration records: the realpath
    # targets and locks use, and the path as the operator wrote it.
    roots = [os.path.realpath(venv), str(venv)]
    reported = []
    for script, target in sorted(entry_points(venv, name).items()):
        path = Path(bin_dir) / script
        if not path.exists():
            reported.append({"script": script, "status": "broken", "detail": "missing"})
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError as exc:
            reported.append({"script": script, "status": "broken",
                             "detail": "unreadable: %s" % exc})
            continue
        match = SHEBANG.match(text.splitlines()[0] if text.splitlines() else "")
        interpreter = match.group(1) if match else ""
        if interpreter.endswith("sh"):
            trampoline = TRAMPOLINE.search(text)
            interpreter = trampoline.group(1) if trampoline else interpreter
        written = _inside(interpreter, roots)
        resolved = _inside(os.path.realpath(interpreter), roots) if interpreter else False
        invokes = target.split(":")[0] in text.replace("\n", " ")
        if not written:
            reported.append({"script": script, "status": "broken",
                             "detail": "interpreter %s is outside %s" % (interpreter, venv)})
        elif not invokes:
            reported.append({"script": script, "status": "broken",
                             "detail": "does not invoke %s" % target})
        elif not resolved:
            reported.append({"script": script, "status": "lead",
                             "detail": "interpreter resolves outside the venv"})
        else:
            reported.append({"script": script, "status": "ok", "detail": target})
    return reported


def command(venv, constraints_path, pins, index_options=()):
    """The one install argv: pinned, constrained, against the recorded venv.

    No `--upgrade` (uv keeps installed versions except where a pin requires a change), no
    `--no-config` (that would ignore the operator's own index configuration), and the
    recorded per-tool index options are replayed verbatim.
    """
    argv = ["uv", "pip", "install", "--python", str(Path(venv) / "bin" / "python"),
            "-c", str(constraints_path)]
    argv.extend(index_options or ())
    argv.extend(pin_text(pin) for pin in pins)
    return argv


def redacted(argv):
    """The argv with any credential-bearing URL stripped, for display and comparison."""
    return [sources.strip_credentials(token) if "://" in token else token for token in argv]
