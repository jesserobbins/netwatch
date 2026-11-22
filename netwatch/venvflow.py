"""check and preview for venv-bound kinds: the observation half.

The sequences here are the ones the design calls authoritative — `(c0)`–`(c5)` for check
and `(p-1)`–`(p11)` for preview — written in that order, because the ordering *is* the
guarantee: identity first, then publication, then the closing read that proves the venv
being reported is the venv that was read.
"""
import json
import os
import secrets
import time
from pathlib import Path

from . import adapters, lifecycle, pins, probe, sources, userlane, workflow
from .core import Error, canonical, digest

FINGERPRINT_ENV = ("UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX",
                   "UV_NO_CONFIG", "UV_CONFIG_FILE", "UV_OVERRIDE", "UV_CONSTRAINT",
                   "UV_INDEX_STRATEGY", "UV_FIND_LINKS", "UV_NO_INDEX", "UV_BREAK_SYSTEM_PACKAGES",
                   "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST")
CONSTRAINTS_DIR = "constraints"
LOCAL = {"name": "local", "kind": "uv", "host": "local"}


def local_runner(argv, **kw):
    """The default one-argv runner: local, bounded, and the same call the kinds use."""
    return adapters.run(LOCAL, argv, **kw)


def stored_state(store, t):
    row = store.db.execute(
        "SELECT state, generation, state_seq, removed FROM targets WHERE name=?",
        (t["name"],)).fetchone()
    if row is None:
        raise Error("Unknown environment; register it first")
    return {"state": row["state"], "generation": int(row["generation"] or 1),
            "state_seq": int(row["state_seq"] or 0), "removed": int(row["removed"] or 0)}


def previous_event(store, t):
    """The last check observation for this target, for the two-in-a-row rules."""
    row = store.db.execute(
        "SELECT body FROM events WHERE target=? AND kind IN ('observation','state_changed') "
        "ORDER BY id DESC LIMIT 1", (t["name"],)).fetchone()
    if row is None:
        return None
    try:
        body = json.loads(row["body"])
    except ValueError:
        return None
    return body if "path" in body else None


def co_claimants(store, t):
    """Other targets that hold this same venv — the set that blocks recovery."""
    path = t.get("path")
    if not path:
        return []
    found = []
    for other in store.targets():
        if other["name"] == t["name"] or other.get("removed"):
            continue
        if other.get("path") and workflow.same_venv(other["path"], path):
            found.append(other)
    return found


def recorded_realpath(t):
    """The realpath registration stored, or None for a target registered without one.

    Registration always records it now (scan and `add` both write `realpath`), so a target
    without one predates that: the drift test is skipped rather than faked, and the
    absence is named instead of being papered over with a tautology.
    """
    return t.get("realpath") or (t.get("registered_from_scan") or {}).get("realpath")


def _structural(t):
    """The recorded path, re-resolved now, must equal the realpath registration recorded.

    A path component that turned symlink after registration re-resolves somewhere else,
    which is an identity fact about the environment, not a detail of string handling.
    """
    path = t.get("path")
    if not path:
        return ("absent", "no recorded path")
    venv = Path(path)
    if not (venv / "pyvenv.cfg").is_file():
        return ("absent", "no pyvenv.cfg")
    recorded = t.get("realpath") or (t.get("registered_from_scan") or {}).get("realpath")
    live = os.path.realpath(path)
    if recorded and os.path.normcase(live) != os.path.normcase(recorded):
        return ("absent", "path now resolves to %s, not the recorded %s" % (live, recorded))
    return ("present", str(venv))


def _identity(t, runner):
    """Manager metadata names the registered tool, and the distribution is listed."""
    if not t.get("path"):
        return ("not_evaluated", "none", "no path")
    seen = userlane.describe(t["path"])
    if seen is None:
        return ("failed", "manager_metadata", "no manager metadata")
    if seen.get("kind") is None:
        return ("unreadable", "manager_metadata", seen.get("error") or "metadata unusable")
    if seen.get("name") != t["name"] or seen.get("kind") != t.get("kind"):
        return ("failed", "manager_metadata",
                "metadata names %s" % seen.get("name"))
    try:
        packages = userlane.inventory(t["path"], runner)
    except Error as exc:
        return ("unreadable", "listing", str(exc))
    wanted = t["name"].lower().replace("_", "-").replace(".", "-")
    present = {p["name"].lower().replace("_", "-").replace(".", "-") for p in packages}
    if wanted not in present:
        return ("failed", "listing", "distribution absent")
    return ("ok", "none", packages)


def _osv(packages, store, request, findings, warnings):
    complete = True
    for package in packages:
        body = {"package": {"name": package["name"], "ecosystem": "PyPI"},
                "version": package["version"]}
        key = "osv:" + digest(body)
        try:
            data = store.cached(key, lambda: request(sources.OSV, body), max_age=3600)
            rows = sources.osv(package, data)
        except (Error, ValueError, KeyError, TypeError) as exc:
            complete = False
            warnings.append("%s: advisory query failed (%s)" % (package["name"], exc))
            continue
        findings.extend(rows)
    return complete


def check(store, t, *, runner=local_runner, request=sources.fetch, now=None):
    """The `(c0)`–`(c5)` sequence for a venv-bound target."""
    now = int(time.time()) if now is None else int(now)
    row = stored_state(store, t)
    if row["removed"]:
        raise Error("Target is removed; nothing to check")
    twins = co_claimants(store, t)
    recovering = False
    event = {"path": "absent", "identity": "not_evaluated", "identity_input": "none",
             "token": "not_read", "complete": True,
             "generation": row["generation"], "state_seq": row["state_seq"],
             "superseded": False}

    # (c1) identity read
    struct, detail = _structural(t)
    event["path"] = struct
    if struct == "present":
        status, value = probe.read(t["path"])
        event["token"] = status
        identity, source, payload = _identity(t, runner)
        event["identity"], event["identity_input"] = identity, source
        if identity != "ok":
            event["complete"] = (identity != "unreadable")
        if identity == "ok":
            recovering = lifecycle.recovery_candidate(row) and not twins
            # (c2) publication, then (c3) the re-read, only when identity passed
            if not lifecycle.recovery_candidate(row):
                probe.cleanup(t["path"])
                published, token = probe.publish(t["path"])
                if published == "failed":
                    event["token"] = "write_failed"
                elif published in ("published", "present"):
                    event["token"] = "usable"
            again, source2, payload2 = _identity(t, runner)
            if again != "ok":
                event["identity"], event["identity_input"] = again, source2
                event["complete"] = False
            else:
                # (c4) inventory and the rest of the observation
                packages = payload2 if isinstance(payload2, list) else payload
                before = probe.witness(t["path"])
                findings, warnings = [], []
                complete_advisories = _osv(packages, store, request, findings, warnings)
                updates, update_error = [], None
                try:
                    updates = _outdated(t, runner, _index_options(t))
                except Error as exc:
                    update_error = str(exc)
                    warnings.append(update_error)
                try:
                    for entry in _consistency(t, runner):
                        findings.append({"key": digest(["consistency", t["name"], entry]),
                                         "package": t["name"],
                                         "installed": _version_of(packages, t["name"]),
                                         "advisory": "dependency-inconsistent",
                                         "state": "unknown", "fix_versions": [entry],
                                         "reason": entry, "url": ""})
                except Error as exc:
                    complete_advisories = False
                    warnings.append(str(exc))
                launcher_rows = _launchers(t)
                # (c5) closing read: the venv that is reported is the venv that was read
                after = probe.witness(t["path"])
                witness_ok = _witness_equal(before, after)
                presence, _, remaining = _identity(t, runner)
                if not witness_ok or presence != "ok":
                    event["complete"] = False
                    warnings.append("the environment changed while it was being read; "
                                    "no findings published, re-run the check")
                else:
                    if not lifecycle.publishable(row, twins, recovering=recovering):
                        _apply_state(store, t, row, next_state_of(row, event, store, t, twins),
                                     event, recovering)
                        store.event(t["name"], "check_incomplete",
                                    {"detail": "%s is out of service; nothing published" % t["name"]})
                        raise Error("%s is out of service; nothing published. Resolve the "
                                    "duplicate or re-check once the venv returns" % t["name"])
                    for row in launcher_rows:
                        if row["status"] == "ok":
                            continue
                        warnings.append("launcher %s: %s" % (row["script"], row["detail"]))
                        if row["status"] == "broken":
                            findings.append({"key": digest(["launcher", t["name"], row["script"]]),
                                             "package": t["name"],
                                             "installed": _version_of(packages, t["name"]),
                                             "advisory": "launcher:" + row["script"],
                                             "state": "unknown", "fix_versions": [],
                                             "reason": row["detail"], "url": ""})
                    report = _report(
                        t, packages, findings, warnings, complete_advisories, now,
                        [{"package": c["name"], "candidate": c["version"]} for c in updates],
                        update_error)
                    next_state = lifecycle.next_state(row, event, previous=previous_event(store, t),
                                                      co_claimant=bool(twins))
                    _apply_state(store, t, row, next_state, event, recovering)
                    store.save_scan(t["name"], report)
                    return report
    next_state = lifecycle.next_state(row, event, previous=previous_event(store, t),
                                      co_claimant=bool(twins))
    _apply_state(store, t, row, next_state, event, recovering)
    store.event(t["name"], "check_incomplete", {"detail": detail, "event": event})
    raise Error("Observation incomplete for %s: %s" % (t["name"], detail))


def next_state_of(row, event, store, t, twins):
    return lifecycle.next_state(row, event, previous=previous_event(store, t),
                                co_claimant=bool(twins))


def _witness_equal(before, after):
    """One rule: a token readable at either read must be readable and equal at both."""
    if before["kind"] == "token" or after["kind"] == "token":
        return before == after
    if before["kind"] == "none" or after["kind"] == "none":
        return False
    if before["kind"] != after["kind"]:
        return False
    return before["value"] == after["value"]


def _apply_state(store, t, row, next_state, event, recovering):
    """Compare-and-set on generation and state_seq: a stale observation writes nothing."""
    if next_state is None:
        store.event(t["name"], "observation", event)
        return
    bump = lifecycle.state_seq_bump(row["state"], next_state)
    with store.transaction():
        updated = store.db.execute(
            "UPDATE targets SET state=?, state_seq=state_seq+? "
            "WHERE name=? AND generation=? AND state_seq=? AND removed=0",
            (next_state, bump, t["name"], row["generation"], row["state_seq"]))
        event["superseded"] = updated.rowcount != 1
        store.event(t["name"], "state_changed" if not event["superseded"] else "observation",
                    {**event, "from": row["state"], "to": next_state})


def _version_of(packages, name):
    for package in packages:
        if package["name"] == name:
            return package["version"]
    return None


def _index_options(t):
    """The venv's recorded index options, read live; empty when it records none."""
    seen = userlane.describe(t["path"]) or {}
    return seen.get("index_options") or []


def _launchers(t):
    """Check the launchers where the manager exposed them, and in the venv's own bin."""
    seen = userlane.describe(t["path"]) or {}
    directories = [seen.get("bin_dir"), str(Path(t["path"]) / "bin")]
    rows, index = [], {}
    for directory in [d for d in directories if d]:
        try:
            for row in pins.launchers(t["path"], directory, t["name"]):
                existing = index.get(row["script"])
                # A real verdict beats "missing" from the other directory: the manager
                # may expose its scripts somewhere other than the venv's own bin.
                if existing is not None and not (existing["status"] == "broken"
                                                 and existing["detail"] == "missing"):
                    continue
                if existing is None:
                    index[row["script"]] = row
                    rows.append(row)
                else:
                    rows[rows.index(existing)] = row
                    index[row["script"]] = row
        except (Error, OSError) as exc:
            rows.append({"script": "*", "status": "lead",
                         "detail": "launcher check failed: %s" % exc})
    return rows


def _report(t, packages, findings, warnings, advisories_ok, now, updates=(), update_error=None):
    return {"target": t, "at": now, "packages": packages, "findings": findings,
            "updates": list(updates or []), "warnings": warnings, "advisory_check_ok": advisories_ok,
            "evidence": [{"source": sources.OSV, "coverage": {
                "complete": advisories_ok, "scanner": False,
                "note": "OSV exact-version queries against the venv's own inventory"}}],
            "update_error": update_error, "coverage": None, "matcher_revision": 1}


def fingerprint():
    """What the resolution would read: the UV/PIP environment plus uv's own bytes.

    Credential-bearing values are redacted before hashing, so rotating a token never
    stales an approval whose resolution inputs did not move.
    """
    env = {}
    for key in FINGERPRINT_ENV:
        value = os.environ.get(key)
        if value:
            env[key] = sources.strip_credentials(value) if "://" in value else "<set>"
    try:
        binary = Path(os.popen("command -v uv").read().strip()).resolve()
        env["uv_executable"] = digest([str(binary), binary.stat().st_size,
                                       int(binary.stat().st_mtime)])
    except OSError:
        env["uv_executable"] = "absent"
    return digest(env)


def preview(store, t, *, runner=local_runner, request=sources.fetch, now=None, state_dir=None):
    """Select the upgrade and save the plan, or refuse with the reason."""
    now = int(time.time()) if now is None else int(now)
    row = stored_state(store, t)
    if row["removed"]:
        raise Error("Target is removed; nothing to preview")
    if row["state"] in lifecycle.OUT_OF_SERVICE:
        raise Error("%s is %s; run a check that clears it first" % (t["name"], row["state"]))
    struct, detail = _structural(t)
    if struct != "present":
        raise Error("Recorded path is missing (%s); nothing to preview" % detail)
    identity, source, packages = _identity(t, runner)
    if identity != "ok":
        raise Error("Identity check failed (%s: %s); nothing to preview" % (source, identity))
    published, token = probe.publish(t["path"])
    if published == "failed":
        raise Error("Could not write a probe token into %s" % t["path"])
    seen = userlane.describe(t["path"]) or {}
    index_options = seen.get("index_options") or []
    first = fingerprint()
    outdated = _outdated(t, runner, index_options)
    second = fingerprint()
    if first != second:
        raise Error("Configuration changed while candidates were resolved; nothing saved")
    result = pins.derive(t["path"], packages, outdated,
                         extras=seen.get("extras") or [], tool=t["name"])
    if not result["pins"]:
        raise Error("No upgrade is available that respects this environment's bounds")
    if fingerprint() != first:
        raise Error("Configuration changed while the pins were derived; nothing saved")
    baseline = _consistency(t, runner)
    approved_origins = _origins(t["path"])
    constraints = _write_constraints(state_dir, result["pins"], seen.get("index_options") or [])
    plan_pins = result["pins"]
    body = {"target": t, "generation": row["generation"],
            "commands": [pins.command(t["path"], constraints["path"], plan_pins,
                                      seen.get("index_options") or [])],
            "pins": plan_pins, "extras": seen.get("extras") or [],
            "index_options": seen.get("index_options") or [],
            "token": token, "fingerprint": first,
            "consistency_baseline": baseline, "origins": approved_origins,
            "constraints": constraints,
            "inventory_digest": inventory_digest(t["path"], packages),
            "marker_env": marker_env(t),
            "index_digest": digest(index_options),
            "expires_at": now + 3600, "leads": result["leads"]}
    body["commands_redacted"] = [pins.redacted(argv) for argv in body["commands"]]
    with store.transaction():
        current = stored_state(store, t)
        if current != row:
            raise Error("Target changed while previewing; nothing saved")
        status, current_token = probe.read(t["path"])
        if status != "usable" or current_token != token:
            raise Error("The environment's probe changed while previewing; nothing saved")
        cur = store.db.execute(
            "INSERT INTO plans(target,at,status,body) VALUES(?,?,?,?)",
            (t["name"], now, "proposed", canonical(body)))
        plan_id = cur.lastrowid
        store.event(t["name"], "proposed", {"plan": plan_id, **body})
    return {"id": plan_id, "status": "proposed", **body}


def _outdated(t, runner, index_options=None):
    argv = ["uv", "pip", "list", "--outdated", "--format", "json",
            "--python", str(Path(t["path"]) / "bin" / "python")]
    argv.extend(index_options or ())
    try:
        data = json.loads(runner(argv))
    except (Error, ValueError) as exc:
        raise Error("Could not read available updates: %s" % exc) from exc
    candidates = []
    for entry in data if isinstance(data, list) else []:
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("latest_version"):
            continue
        if entry.get("latest_version") == entry.get("version"):
            continue
        candidates.append({"name": entry["name"], "version": entry["latest_version"]})
    return candidates


def _write_constraints(state_dir, plan_pins, index_options):
    """The approval carries its own constraint file, and the plan carries its digest."""
    base = Path(state_dir or os.path.expanduser("~/.local/state/netwatch"))
    directory = base / CONSTRAINTS_DIR
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / ("preview-%s.txt" % secrets.token_hex(8))
    body = "\n".join(pins.pin_text(pin) for pin in plan_pins) + "\n"
    path.write_text(body)
    return {"path": str(path), "digest": digest(body), "bytes": body}


def inventory_digest(venv, packages):
    """Versions plus the bytes that describe them: a same-version reinstall still differs.

    A version-only digest misses a same-version reinstall with different dependency
    metadata or a changed origin, which is exactly the swap an approval must not survive.
    """
    import hashlib
    rows = []
    for package in sorted(packages, key=lambda p: p["name"]):
        entry = [package["name"], package["version"]]
        for name, filename in (("metadata", "METADATA"), ("origin", "direct_url.json")):
            path = _dist_file(venv, package["name"], filename)
            if path is None:
                entry.append([name, None])
                continue
            try:
                entry.append([name, hashlib.sha256(path.read_bytes()).hexdigest()])
            except OSError:
                entry.append([name, "unreadable"])
        rows.append(entry)
    return digest(rows)


def _dist_file(venv, name, filename):
    wanted = name.lower().replace("_", "-").replace(".", "-")
    for site in sorted(Path(venv).glob("lib/python*/site-packages")):
        for dist in site.glob("*.dist-info"):
            if dist.name.lower().replace("_", "-").split("-")[0] == wanted:
                path = dist / filename
                return path if path.is_file() else None
    return None


def marker_env(t):
    """The interpreter's own marker values, read with `-I -S` so no site code runs."""
    argv = [str(Path(t["path"]) / "bin" / "python"), "-I", "-S", "-c",
            "import json,sys;print(json.dumps({'prefix':sys.prefix,"
            "'base_prefix':sys.base_prefix,'version':sys.version.split()[0],"
            "'implementation':sys.implementation.name}))"]
    try:
        return json.loads(adapters.run(LOCAL, argv, timeout=60))
    except (Error, ValueError, KeyError) as exc:
        raise Error("Could not read the interpreter's marker values: %s" % exc) from exc


def _consistency(t, runner):
    """`uv pip check` entries, as a baseline: what was already inconsistent."""
    argv = ["uv", "pip", "check", "--python", str(Path(t["path"]) / "bin" / "python")]
    try:
        output = runner(argv, ok=(0, 1))
    except Error as exc:
        raise Error("Could not read the dependency-consistency baseline: %s" % exc) from exc
    entries = []
    for line in str(output).splitlines():
        line = line.strip()
        if not line or line.startswith("No broken requirements"):
            continue
        entries.append(line)
    return sorted(entries)


def _origins(venv):
    """Every installed distribution's provenance, keyed by normalized name."""
    found = {}
    for site in sorted(Path(venv).glob("lib/python*/site-packages")):
        for dist in site.glob("*.dist-info"):
            name = dist.name.lower().replace("_", "-").split("-")[0]
            kind, data = pins.origin(dist)
            found[name] = [kind, sorted(data) if isinstance(data, dict) else data]
    return found


def _record_mismatches(venv):
    """Files that do not match their own RECORD — the damage metadata cannot show."""
    import hashlib
    broken = []
    for site in sorted(Path(venv).glob("lib/python*/site-packages")):
        for dist in site.glob("*.dist-info"):
            record = dist / "RECORD"
            if not record.is_file():
                broken.append({"dist": dist.name, "reason": "no RECORD"})
                continue
            for line in record.read_text(errors="replace").splitlines():
                parts = line.rsplit(",", 2)
                if len(parts) < 3 or not parts[1]:
                    continue          # no hash recorded (.pyc, direct_url.json, RECORD itself)
                rel, want = parts[0], parts[1].split("=")[-1]
                path = (site / rel).resolve()
                if not str(path).startswith(str(Path(venv).resolve().parent)) and \
                        not str(path).startswith(str(Path(venv).resolve())):
                    broken.append({"dist": dist.name, "file": rel, "reason": "outside the venv"})
                    continue
                try:
                    got = hashlib.sha256(path.read_bytes()).hexdigest()
                except OSError:
                    broken.append({"dist": dist.name, "file": rel, "reason": "missing"})
                    continue
                if got != want:
                    broken.append({"dist": dist.name, "file": rel, "reason": "changed"})
    return broken


def apply(store, plan_id, *, yes=False, runner=local_runner, request=sources.fetch, now=None):
    """Run the approved install, then say what actually happened."""
    import secrets
    now = int(time.time()) if now is None else int(now)
    if not yes:
        raise Error("Read preview first; apply requires --yes to approve the upgrade")
    row = store.db.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
    if not row or row["status"] != "proposed":
        raise Error("Plan missing or already attempted; never replay an interrupted update")
    body = json.loads(row["body"])
    t = store.target(row["target"])
    state = stored_state(store, t)

    # (0) workflow gates
    if body.get("target") != t:
        raise Error("Target changed; create a new preview")
    if state["removed"]:
        raise Error("Target is removed")
    if state["generation"] != body["generation"]:
        raise Error("Target was removed and revived since this preview; create a new one")
    if state["state"] in lifecycle.OUT_OF_SERVICE or state["state"] == "not_bindable":
        raise Error("%s is %s; apply is refused" % (t["name"], state["state"]))
    busy = workflow.busy_plan(store, t)
    if busy and busy != plan_id:
        raise Error("Another update for this venv is running or needs attention")
    if now >= body["expires_at"]:
        raise Error("Preview expired; create a new one")
    if fingerprint() != body["fingerprint"]:
        raise Error("Configuration changed since this preview; approval is stale")

    # (1) recorded path
    struct, detail = _structural(t)
    if struct != "present":
        raise Error("Recorded path is missing (%s); nothing to apply" % detail)

    # (2) runtime identity, and no second registration on this venv
    identity, source, packages = _identity(t, runner)
    if identity != "ok":
        raise Error("Identity check failed (%s: %s); nothing to apply" % (source, identity))
    if co_claimants(store, t):
        raise Error("Another target tracks this venv; remove it first")

    # (3) binding bracket
    status, token = probe.read(t["path"])
    if status != "usable" or token != body["token"]:
        raise Error("The environment's probe changed since this preview; approval is stale")
    if inventory_digest(t["path"], packages) != body["inventory_digest"]:
        raise Error("Installed versions or metadata changed since this preview; "
                    "approval is stale")
    if marker_env(t) != body.get("marker_env"):
        raise Error("The interpreter changed since this preview (a Python update is a "
                    "stale approval); create a new one")
    if (userlane.describe(t["path"]) or {}).get("extras") != body.get("extras"):
        raise Error("The requested extras changed since this preview; create a new one")
    if digest(_index_options(t)) != body.get("index_digest"):
        raise Error("The recorded index options changed since this preview; "
                    "approval is stale")
    if probe.read(t["path"]) != (status, token):
        raise Error("The environment changed while it was being verified; nothing applied")

    # (4) constraints digest
    constraints_path = Path(body["constraints"]["path"])
    if not constraints_path.is_file() or \
            digest(constraints_path.read_text()) != body["constraints"]["digest"]:
        raise Error("The plan's constraints file is missing or changed; create a new preview")

    # (5) verified temp copy, so what runs is the bytes that were approved
    state_dir = constraints_path.parent
    temp = state_dir / ("apply-%s-%s.tmp" % (now, secrets.token_hex(4)))
    handle = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(handle, "w") as stream:
        stream.write(body["constraints"]["bytes"])

    # claim: everything above re-checked once more, under the write lock
    before_records = _record_mismatches(t["path"])
    with store.transaction():
        if stored_state(store, t) != state:
            raise Error("Target changed under us; nothing applied")
        if fingerprint() != body["fingerprint"]:
            raise Error("Configuration changed during preflight; approval is stale")
        if _structural(t)[0] != "present":
            raise Error("The recorded path stopped resolving to the recorded realpath; "
                        "nothing applied")
        if co_claimants(store, t):
            raise Error("Another target began tracking this venv; nothing applied")
        if probe.read(t["path"]) != (status, token):
            raise Error("The probe changed during preflight; nothing applied")
        # The last check before any command starts: the inputs the approval named must
        # still be the inputs this run would use.
        if digest(_index_options(t)) != body.get("index_digest"):
            raise Error("The recorded index options changed during preflight; "
                        "approval is stale")
        if marker_env(t) != body.get("marker_env"):
            raise Error("The interpreter changed during preflight; approval is stale")
        if (userlane.describe(t["path"]) or {}).get("extras") != body.get("extras"):
            raise Error("The requested extras changed during preflight; approval is stale")
        updated = store.db.execute(
            "UPDATE plans SET status='running' WHERE id=? AND status='proposed'", (plan_id,))
        if updated.rowcount != 1:
            raise Error("Plan was already claimed")
        store.event(t["name"], "approved_and_started",
                    {"plan": plan_id, "operator_uid": os.getuid(),
                     "commands": body.get("commands_redacted") or body["commands"]})
    try:
        outcome, failure = "applied", None
        try:
            runner(body["commands"][0], timeout=1800)
        except Exception as exc:
            # Any failure of the install command is a failure to classify. What matters is
            # the state it left behind, never the exception's type.
            failure = str(exc) or type(exc).__name__
    finally:
        try:
            temp.unlink()
        except OSError:
            pass

    after_token = probe.read(t["path"])
    try:
        after_packages = userlane.inventory(t["path"], runner)
    except Error:
        after_packages = None
    after_consistency = None
    after_origins = None
    if after_packages is not None:
        try:
            after_consistency = _consistency(t, runner)
        except Error:
            after_consistency = None
        after_origins = _origins(t["path"])

    # The result row carries the generation it was produced under, so a plan result from
    # before a remove/revive never reads as current history.
    result = {"plan": plan_id, "failure": failure, "generation": state["generation"]}
    if failure is None:
        # The five-condition gate: the install's own exit code is only the first of them.
        problems = []
        if after_token != (status, token):
            problems.append("the probe token changed; the venv was replaced")
        if after_packages is None:
            problems.append("the inventory could not be read after the install")
        else:
            installed = {p["name"]: p["version"] for p in after_packages}
            for pin in body["pins"]:
                if installed.get(pin["name"]) != pin["version"]:
                    problems.append("%s is installed at %s, not the approved %s"
                                    % (pin["name"], installed.get(pin["name"]), pin["version"]))
            new_entries = sorted(set(after_consistency or []) - set(body["consistency_baseline"]))
            if new_entries:
                problems.append("dependency consistency got worse: " + new_entries[0])
            changed_origins = [name for name, value in (after_origins or {}).items()
                               if body["origins"].get(name) not in (None, value)]
            if changed_origins:
                problems.append("origin changed for " + changed_origins[0])
        if problems:
            outcome = "needs_attention"
            result["problems"] = problems
        result.update(pins=[p["name"] + "==" + p["version"] for p in body["pins"]],
                      token=after_token[1], inventory_digest=digest(after_packages or []))
    else:
        unchanged = (after_token == (status, token)
                     and after_packages is not None
                     and inventory_digest(t["path"], after_packages) == body["inventory_digest"]
                     and after_consistency == body["consistency_baseline"])
        # Only damage this install introduced counts: a venv that already disagreed with
        # its RECORD is baseline evidence, exactly as a pre-existing consistency conflict is.
        damage = ([row for row in _record_mismatches(t["path"]) if row not in before_records]
                  if unchanged else [])
        if unchanged and not damage:
            outcome = "failed_no_change"
        else:
            outcome = "needs_attention"
            result["record_mismatches"] = damage[:5]
        result["install_output"] = failure

    with store.transaction():
        if outcome == "failed_no_change":
            store.db.execute("UPDATE plans SET status='proposed' WHERE id=?", (plan_id,))
        else:
            store.db.execute("UPDATE plans SET status=?, result=? WHERE id=?",
                             (outcome, canonical(result), plan_id))
            # The terminal write and the sibling staling are one transaction: the gap
            # between them is exactly where a stale preflight could claim and downgrade.
            store.stale_siblings(t["name"], path=t.get("path"), venv_match=workflow.same_venv)
        store.event(t["name"], outcome if outcome != "failed_no_change" else "failed_no_change",
                    {"plan": plan_id, "result": result})
    return {"id": plan_id, "status": outcome, **result}
