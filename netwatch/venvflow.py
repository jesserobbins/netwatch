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
DEFAULT_STATE = os.path.expanduser("~/.local/state/netwatch")


def local_runner(argv, **kw):
    """Local, bounded, and run from netwatch's state directory.

    uv reads configuration from the working directory upward, so inheriting the launch
    directory would let a repo-local `[tool.uv]` shape resolution. Pinning the cwd keeps
    that out of the decision, and the fingerprint hashes whatever the state dir's own
    hierarchy still supplies.
    """
    return adapters.run({**LOCAL, "path": kw.pop("cwd", DEFAULT_STATE)}, argv, **kw)


def uv_config_files(state_dir=None):
    """Every uv configuration file discovery would read from the state directory up."""
    base = Path(state_dir or DEFAULT_STATE).expanduser().resolve()
    found = []
    for directory in [base, *base.parents]:
        for name in ("uv.toml", "pyproject.toml"):
            candidate = directory / name
            if candidate.is_file():
                found.append(str(candidate))
    for path in (Path(os.path.expanduser("~/.config/uv/uv.toml")),
                 Path("/etc/uv/uv.toml")):
        if path.is_file():
            found.append(str(path))
    explicit = os.environ.get("UV_CONFIG_FILE")
    if explicit and Path(explicit).is_file():
        found.append(explicit)
    return found


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
    for other in store.target_rows():
        if other["name"] == t["name"] or other["removed"]:
            continue
        if other["state"] == "unresolved_path":
            # The recorded path is gone for that row, so it cannot be holding the venv.
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
            # An unreadable input is recorded, counted and reported: the check ran to its
            # end and found nothing readable, so this event is complete. Marking it
            # incomplete would forbid the two-in-a-row rule from ever firing.
            event["complete"] = True
        if identity == "ok":
            recovering = lifecycle.recovery_candidate(row) and not twins
            # (c2) publication, then (c3) the re-read, only when identity passed. A
            # recovering venv is published into like any other: its token came back with it.
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
                    for launcher in launcher_rows:
                        if launcher["status"] == "ok":
                            continue
                        if launcher["status"] == "not-verifiable":
                            warnings.append("launcher not entry-point-verifiable: %s (%s)"
                                            % (launcher["script"], launcher["detail"]))
                            continue
                        warnings.append("launcher %s: %s"
                                        % (launcher["script"], launcher["detail"]))
                        if launcher["status"] == "broken":
                            findings.append({
                                "key": digest(["launcher", t["name"], launcher["script"]]),
                                "package": t["name"],
                                "installed": _version_of(packages, t["name"]),
                                "advisory": "launcher:" + launcher["script"],
                                "state": "unknown", "fix_versions": [],
                                "reason": launcher["detail"], "url": ""})
                    if event.get("token") in ("malformed", "write_failed") or (
                            row["state"] == "not_bindable" and event.get("token") != "usable"):
                        warnings.append(
                            "no usable probe token in %s: delete %s and re-run check "
                            "(it is safe; netwatch writes a fresh one)"
                            % (t["path"], Path(t["path"]) / ".netwatch-probe"))
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
    """The venv's recorded index options, raw, read live: what uv must authenticate with."""
    seen = userlane.describe(t["path"]) or {}
    return seen.get("index_options") or []


def _index_options_redacted(t):
    """The same list with credentials stripped: what may be stored, shown or compared."""
    seen = userlane.describe(t["path"]) or {}
    return seen.get("index_options_redacted") or []


def _launchers(t):
    """Verify the launchers the *manager* recorded as exposed.

    uv's receipt and pipx's metadata name the scripts a tool exposes and where they were
    installed; that is the list that must be present, because a native binary tool has no
    `entry_points.txt` at all and would otherwise silently pass with nothing checked.
    """
    seen = userlane.describe(t["path"]) or {}
    # The check uses the bin directory registration recorded: a later environment change
    # does not re-point what this target is expected to expose.
    bin_dir = t.get("bin_dir") or seen.get("bin_dir") or str(Path(t["path"]) / "bin")
    exposed = seen.get("exposed") or []
    rows = []
    for item in exposed:
        script = item.get("script")
        path = Path(item.get("path") or (Path(bin_dir) / script))
        if not path.exists():
            rows.append({"script": script, "status": "broken",
                         "detail": "exposed launcher is missing at %s" % path})
            continue
        try:
            head = path.open("rb").read(2)
            text = path.read_text(errors="replace") if head == b"#!" else None
        except OSError as exc:
            rows.append({"script": script, "status": "broken",
                         "detail": "unreadable: %s" % exc})
            continue
        if text is None:
            # A native binary: present and executable is all that can be verified without
            # running it, and the report says so rather than implying it was checked.
            rows.append({"script": script, "status": "not-verifiable",
                         "detail": "native binary in %s; presence checked, entry point not "
                                   "verifiable" % path.parent})
            continue
        rows.extend(pins.launchers(t["path"], str(path.parent), t["name"]))
    return rows


def _report(t, packages, findings, warnings, advisories_ok, now, updates=(), update_error=None):
    return {"target": t, "at": now, "packages": packages, "findings": findings,
            "updates": list(updates or []), "warnings": warnings, "advisory_check_ok": advisories_ok,
            "evidence": [{"source": sources.OSV, "coverage": {
                "complete": advisories_ok, "scanner": False,
                "note": "OSV exact-version queries against the venv's own inventory"}}],
            "update_error": update_error, "coverage": None, "matcher_revision": 1}


def fingerprint(state_dir=None):
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
    # The configuration files themselves, not just the variables that point at them.
    contents = {}
    for path in uv_config_files(state_dir):
        try:
            contents[path] = digest(Path(path).read_text(errors="replace"))
        except OSError:
            contents[path] = "unreadable"
    env["uv_config_files"] = contents
    return digest(env)


def preview(store, t, *, runner=local_runner, request=sources.fetch, now=None, state_dir=None):
    """Select the upgrade and save the plan, or refuse with the reason."""
    now = int(time.time()) if now is None else int(now)
    # Approval artifacts live beside the database that records the plan, which is also
    # where cleanup looks: one directory, wherever --db points.
    state_dir = state_dir or Path(getattr(store, "db_path", DEFAULT_STATE)).parent
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
    # (p0) the token is read before anything is written, so a malformed or unreadable probe
    # is decided here rather than after the whole resolution bracket.
    token_status, existing_token = probe.read(t["path"])
    if token_status == "unreadable":
        raise Error("The probe token in %s could not be read; nothing to preview" % t["path"])
    # (p1) stale temp cleanup on every run that reaches this step.
    probe.cleanup(t["path"])
    published, token = probe.publish(t["path"])
    if published == "failed":
        raise Error("Could not write a probe token into %s" % t["path"])
    # (p1) the identity read repeats after publication: a venv that took the path between
    # the read and the write would have received this marker.
    after_publish, source2, packages2 = _identity(t, runner)
    if after_publish != "ok":
        raise Error("The environment changed while it was being tokened (%s: %s); "
                    "nothing to preview" % (source2, after_publish))
    packages = packages2 if isinstance(packages2, list) else packages
    seen = userlane.describe(t["path"]) or {}
    index_options = seen.get("index_options") or []
    held, undetermined = _origin_policy(t["path"], packages)
    if undetermined:
        raise Error("%s has an undetermined origin (%s); netwatch cannot say what its "
                    "bytes mean, so it will not plan an upgrade"
                    % (undetermined[0], undetermined[1]))
    first = fingerprint(state_dir)
    outdated = _outdated(t, runner, index_options)
    second = fingerprint(state_dir)
    if first != second:
        raise Error("Configuration changed while candidates were resolved; nothing saved")
    result = pins.derive(t["path"], [p for p in packages if p["name"] not in held],
                         [c for c in outdated if c["name"] not in held],
                         extras=seen.get("extras") or [], tool=t["name"])
    result["leads"] = list(result.get("leads") or []) + [
        {"type": "origin", "package": name,
         "detail": "installed from %s; held at its current version" % kind}
        for name, kind in sorted(held.items())]
    result["held"] = sorted(held)
    if not result["pins"]:
        # (p11): no eligible update is an observation, not a failure. The token recovered, so
        # a not_bindable target is cleared, the run records what it saw, and no plan is saved.
        with store.transaction():
            if row["state"] == "not_bindable":
                status_now, token_now = probe.read(t["path"])
                if status_now == "usable" and token_now == token:
                    store.db.execute(
                        "UPDATE targets SET state='live', state_seq=state_seq+1 "
                        "WHERE name=? AND state='not_bindable' AND generation=? AND state_seq=?",
                        (t["name"], row["generation"], row["state_seq"]))
                    store.event(t["name"], "state_changed",
                                {"from": "not_bindable", "to": "live",
                                 "reason": "token recovered; no eligible update"})
            store.event(t["name"], "preview_no_update",
                        {"candidates": [c["name"] for c in outdated],
                         "excluded": result.get("excluded") or [],
                         "leads": result.get("leads") or []})
        return {"status": "no_update", "target": t["name"], "pins": [],
                "excluded": result.get("excluded") or [],
                "leads": result.get("leads") or [],
                "detail": "No eligible update: every candidate is excluded by this "
                          "environment's own bounds"}
    if fingerprint(state_dir) != first:
        raise Error("Configuration changed while the pins were derived; nothing saved")
    # (p7) the inventory the plan records is a listing inside the bracket, not the identity
    # read: a change between them means the candidate set and the digest describe different
    # environments.
    try:
        bracket_packages = userlane.inventory(t["path"], runner)
    except Error as exc:
        raise Error("Could not read the inventory while selecting: %s" % exc) from exc
    if bracket_packages != packages:
        raise Error("The installed set changed while candidates were selected; nothing saved")
    # (p9) the third fingerprint, at the far end of the bracket
    if fingerprint(state_dir) != first:
        raise Error("Configuration changed before the plan was saved; nothing saved")
    packages = bracket_packages
    baseline = _consistency(t, runner)
    approved_origins = _origins(t["path"])
    constraints = _write_constraints(state_dir, result["pins"], result.get("constraints") or [])
    plan_pins = result["pins"]
    body = {"target": t, "generation": row["generation"],
            "pins": plan_pins, "extras": seen.get("extras") or [],
            "index_options": _index_options_redacted(t),
            "token": token, "fingerprint": first,
            "consistency_baseline": baseline, "origins": approved_origins,
            "constraints": constraints,
            "inventory_digest": inventory_digest(t["path"], packages),
            "marker_env": marker_env(t),
            "index_digest": digest(_index_options_redacted(t)),
            "expires_at": now + 3600, "leads": result["leads"],
            # Distributions the plan holds at their version (direct/VCS/local origins):
            # their absence after the install fails the gate.
            "held": sorted(result.get("held") or [])}
    # Only the redacted form is stored: the raw index URL is read from the venv's own
    # metadata at the moment of use, so no credential ever lands in the database.
    body["commands_redacted"] = [pins.redacted(
        pins.command(t["path"], constraints["path"], plan_pins,
                     seen.get("index_options") or []))]
    # (p6) confirmation: the venv being approved is the venv that was read and tokened.
    confirmed, source3, _ = _identity(t, runner)
    if confirmed != "ok":
        raise Error("The environment changed while the plan was being built (%s: %s); "
                    "nothing saved" % (source3, confirmed))
    with store.transaction():
        current = stored_state(store, t)
        if current != row:
            raise Error("Target changed while previewing; nothing saved")
        # the artifact the plan names must still be the artifact on disk
        if not Path(constraints["path"]).is_file() or \
                digest(Path(constraints["path"]).read_text()) != constraints["digest"]:
            raise Error("The plan's constraints file changed while the plan was being "
                        "saved; nothing saved")
        status, current_token = probe.read(t["path"])
        if status != "usable" or current_token != token:
            raise Error("The environment's probe changed while previewing; nothing saved")
        # Recovering the token is what preview is for, so the state is cleared here — only
        # if the token on disk is still the one this run read.
        if row["state"] == "not_bindable":
            status_now, token_now = probe.read(t["path"])
            if status_now == "usable" and token_now == token:
                store.db.execute(
                    "UPDATE targets SET state='live', state_seq=state_seq+1 "
                    "WHERE name=? AND state='not_bindable' AND generation=? AND state_seq=?",
                    (t["name"], row["generation"], row["state_seq"]))
                store.event(t["name"], "state_changed",
                            {"from": "not_bindable", "to": "live", "reason": "token recovered"})
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


def _write_constraints(state_dir, plan_pins, bounds=()):
    """The approval carries its own constraint file, and the plan carries its digest.

    The retained bounds go in with the pins: selecting under a bound and then not passing
    the bound to the installer lets uv resolve a transitive dependency past it.
    """
    base = Path(state_dir or DEFAULT_STATE)
    directory = base / CONSTRAINTS_DIR
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / ("preview-%s.txt" % secrets.token_hex(8))
    lines = [pins.pin_text(pin) for pin in plan_pins] + list(bounds)
    body = "\n".join(lines) + "\n"
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


def _origin_policy(venv, packages):
    """Which distributions are held at their version, and which make planning impossible.

    An index upgrade replaces an install whose provenance is not the index. A direct, VCS
    or local install is held (its upgrades come from that source); an origin that cannot be
    read at all makes the target unplannable, because a plan that silently held it back
    would be a guess presented as a decision.
    """
    held, undetermined = {}, None
    for package in packages:
        path = _dist_file(venv, package["name"], "direct_url.json")
        if path is None:
            continue
        kind, data = pins.origin(path.parent)
        if kind == "undetermined":
            undetermined = (package["name"], (data or {}).get("error", "unreadable provenance"))
        elif kind in ("direct", "vcs", "local"):
            held[package["name"]] = kind
    return held, undetermined


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
    state_dir = Path(body.get("constraints", {}).get("path", DEFAULT_STATE)).parent

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
        # Lazy expiry on this path too: the plan moves to stale and its artifact goes, so a
        # refusal never leaves an applicable-looking proposal behind.
        with store.transaction():
            store.db.execute("UPDATE plans SET status='stale' WHERE id=? AND status='proposed'",
                             (plan_id,))
            store.event(t["name"], "plan_expired", {"plan": plan_id})
        try:
            Path(body["constraints"]["path"]).unlink()
        except OSError:
            pass
        raise Error("Preview expired; it has been staled and its constraints file removed. "
                    "Create a new one")
    if fingerprint(state_dir) != body["fingerprint"]:
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

    # (3) binding bracket — first token read, then the bracket's *own* listing (the
    # step-(2) listing is an identity observation, not the digest observation), then a
    # second token read.
    status, token = probe.read(t["path"])
    if status != "usable" or token != body["token"]:
        raise Error("The environment's probe changed since this preview; approval is stale")
    try:
        bracket_packages = userlane.inventory(t["path"], runner)
    except Error as exc:
        raise Error("Could not read the inventory inside the binding bracket: %s" % exc) from exc
    if inventory_digest(t["path"], bracket_packages) != body["inventory_digest"]:
        raise Error("Installed versions or metadata changed since this preview; "
                    "approval is stale")
    if marker_env(t) != body.get("marker_env"):
        raise Error("The interpreter changed since this preview (a Python update is a "
                    "stale approval); create a new one")
    if (userlane.describe(t["path"]) or {}).get("extras") != body.get("extras"):
        raise Error("The requested extras changed since this preview; create a new one")
    if digest(_index_options_redacted(t)) != body.get("index_digest"):
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
    approved_bytes = body["constraints"]["bytes"]
    if digest(approved_bytes) != body["constraints"]["digest"]:
        # The plan carries the bytes and their digest; if they disagree, what would run is
        # not what was approved, whoever wrote it.
        raise Error("The plan's stored constraints do not match their digest; nothing applied")
    temp = state_dir / ("apply-%s-%s.tmp" % (now, secrets.token_hex(4)))
    handle = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(handle, "w") as stream:
        stream.write(approved_bytes)

    # claim: everything above re-checked once more, under the write lock
    before_records = _record_mismatches(t["path"])
    try:
        with store.transaction():
            if stored_state(store, t) != state:
                raise Error("Target changed under us; nothing applied")
            if fingerprint(state_dir) != body["fingerprint"]:
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
            if digest(_index_options_redacted(t)) != body.get("index_digest"):
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
                         "commands": body.get("commands_redacted")})
    except BaseException:
        # A refused claim must not leave the verified copy behind.
        try:
            temp.unlink()
        except OSError:
            pass
        raise
    try:
        outcome, failure = "applied", None
        # Step (5)'s verified copy is what runs: the approved bytes, at a path this apply
        # owns. The equality gate folds that path back so it still compares like with like.
        approved_path = body["constraints"]["path"]
        argv = pins.command(t["path"], str(temp), body["pins"], _index_options(t))
        folded = [approved_path if token == str(temp) else token
                  for token in pins.redacted(argv)]
        if folded != (body.get("commands_redacted") or [None])[0]:
            raise Error("The command no longer matches the approved shape; nothing run")
        try:
            runner(argv, timeout=1800)
        except Exception as exc:
            # Any failure of the install command is a failure to classify. What matters is
            # the state it left behind, never the exception's type.
            failure = str(exc) or type(exc).__name__
    finally:
        try:
            temp.unlink()
        except OSError:
            pass

    # The post-upgrade sequence, in the spec's order: probe, identity and inventory, the
    # consistency check, then the probe again.
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
    # Identity is read after the inventory and consistency check: a venv that stopped being
    # this tool during those reads must not be reported as a successful upgrade.
    after_identity = _identity(t, runner)
    second_token = probe.read(t["path"])

    # The result row carries the generation it was produced under, so a plan result from
    # before a remove/revive never reads as current history.
    result = {"plan": plan_id, "failure": failure, "generation": state["generation"]}
    if failure is None:
        # The five-condition gate: the install's own exit code is only the first of them.
        problems = []
        if after_token != (status, token):
            problems.append("the probe token changed; the venv was replaced")
        if second_token != after_token:
            problems.append("the probe changed during the post-install observation")
        if after_identity[0] != "ok":
            problems.append("identity no longer holds after the install (%s: %s)"
                            % (after_identity[1], after_identity[0]))
        if after_packages is None:
            problems.append("the inventory could not be read after the install")
        else:
            installed = {p["name"]: p["version"] for p in after_packages}
            for pin in body["pins"]:
                if installed.get(pin["name"]) != pin["version"]:
                    problems.append("%s is installed at %s, not the approved %s"
                                    % (pin["name"], installed.get(pin["name"]), pin["version"]))
            if after_consistency is None:
                problems.append("the post-install consistency check was unreadable")
            else:
                new_entries = sorted(set(after_consistency)
                                     - set(body["consistency_baseline"]))
                if new_entries:
                    problems.append("dependency consistency got worse: " + new_entries[0])
            changed_origins = [name for name, value in (after_origins or {}).items()
                               if body["origins"].get(name) not in (None, value)]
            if changed_origins:
                problems.append("origin changed for " + changed_origins[0])
            # A distribution the plan held (direct/VCS/local) must still be there: its pin
            # was supposed to hold it, so its absence means the resolution removed it.
            held = set(body.get("held") or [])
            installed_now = {p["name"] for p in after_packages}
            removed = sorted(name for name in held if name not in installed_now)
            if removed:
                problems.append("%s was removed although the plan held it" % removed[0])
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
