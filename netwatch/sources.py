"""Advisory evidence, never installation commands. Explicit coverage limits."""
import email.utils
import json
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from . import adapters
from .core import Error, digest, text
from .versions import compare_versions

USN = "https://usn.ubuntu.com/usn-db/database.json"
ARCH = "https://security.archlinux.org/issues/all.json"
OSV = "https://api.osv.dev/v1/query"
PWN = "https://pwn.watch/incidents.json"
CVE_NOW = "https://cve.now/api/v1/entries/"
ZERO_WIRE = "https://radar.cloudflare.com/security/zero-wire/rss"
CVE_ID = r"CVE-[0-9]{4}-[0-9]{4,19}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Only the documented cve.now entry-to-storage hop; never follow feed links.
        cve = req.full_url.removeprefix(CVE_NOW)
        dest = urllib.parse.urlsplit(newurl)
        if (req.full_url == CVE_NOW + cve and re.fullmatch(CVE_ID, cve) and
                dest.scheme == "https" and dest.hostname and
                dest.hostname.endswith(".public.blob.vercel-storage.com") and
                dest.netloc == dest.hostname and not dest.query and not dest.fragment and
                dest.path == f"/public/entries/{cve}.json"):
            return super().redirect_request(req, fp, code, msg, headers, newurl)
        raise Error("Advisory endpoint redirected; check source configuration in code")


def fetch(url, body=None):
    cve_lookup = url.startswith(CVE_NOW) and re.fullmatch(CVE_ID, url[len(CVE_NOW):])
    if url not in (USN, ARCH, OSV, PWN, ZERO_WIRE) and not cve_lookup:
        raise Error("Unknown advisory endpoint")
    briefing = cve_lookup or url in (PWN, ZERO_WIRE)
    if briefing and body is not None:
        raise Error("Context sources accept only public GET requests")
    request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"User-Agent": "netwatch/0.2", "Content-Type": "application/json",
                                              "Accept-Encoding": "identity"})
    limit = 512 * 1024 * 1024 if url == USN else (2 if cve_lookup else 5 if url == ZERO_WIRE else 20) * 1024 * 1024
    timeout = 10 if briefing else 30
    start, chunks, size = time.monotonic(), [], 0
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            if response.headers.get("Content-Encoding", "identity") != "identity":
                raise Error("Unsupported compressed advisory response")
            while chunk := response.read(64 * 1024):
                size += len(chunk)
                if size > limit or time.monotonic() - start > (20 if briefing else 120):
                    raise Error("Advisory response exceeds byte/time limit")
                chunks.append(chunk)
        raw = b"".join(chunks)
        return raw.decode("utf-8") if url == ZERO_WIRE else json.loads(raw)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise Error("Advisory request failed; previous findings retained") from exc


def finding(p, advisory, state, fixes, reason, link):
    return {"key": digest([p["ecosystem"], p["name"], p.get("architecture"), advisory]),
            "package": p["name"], "installed": p["version"], "advisory": advisory,
            "state": state, "fix_versions": sorted(set(fixes)), "reason": reason, "url": link}


def compact_usn(data):
    """Cache only Noble matching evidence, not the large historical artifact corpus."""
    result = {}
    for key, notice in data.items():
        entry = notice.get("releases", {}).get("noble")
        if entry is not None:
            result[key] = {"id": notice["id"], "is_hidden": notice.get("is_hidden", False),
                           "cves": notice.get("cves", []), "releases": {"noble": {
                               "sources": {n: {"version": r.get("version")} for n, r in entry.get("sources", {}).items()},
                               "allbinaries": {n: {k: r.get(k) for k in ("source", "version", "pocket")}
                                               for n, r in entry.get("allbinaries", {}).items()}}}}
    if not result:
        raise Error("No Noble evidence in Ubuntu feed")
    return result


def ubuntu(packages, data):
    if not isinstance(data, dict) or not data:
        raise Error("Ubuntu feed is empty or malformed")
    result = []
    by_source = {}
    for p in packages:
        by_source.setdefault(p["source"], []).append(p)
    for key, notice in data.items():
        if notice.get("id") not in (key, "USN-" + key):
            raise Error("Malformed USN identity")
        entry = notice.get("releases", {}).get("noble", {})
        for source, info in entry.get("sources", {}).items():
            for p in by_source.get(source, []):
                binary = entry.get("allbinaries", {}).get(p["name"], {})
                fixed = info.get("version")
                supported = (notice.get("is_hidden", False) in (False, "false") and
                             binary.get("source") == source and binary.get("pocket") == "security" and
                             p.get("architecture") in ("amd64", "all") and fixed and fixed != "0" and
                             binary.get("version") and binary["version"] != "0" and
                             "esm" not in (fixed + binary["version"] + p["version"] + p["source_version"]).lower())
                state, fixes = "unknown", []
                reason = "Notice lacks supported standard-security binary/source evidence"
                if supported:
                    try:
                        if compare_versions(p["source_version"], fixed) >= 0:
                            continue
                        state, fixes = "affected", [fixed]
                        reason = "Installed source version is below this Noble notice fix"
                    except Error:
                        reason = "Unsupported version comparison"
                row = finding(p, "USN-" + key, state, fixes, reason,
                              "https://ubuntu.com/security/notices/USN-" + key)
                row["references"] = notice.get("cves", [])  # Notice-level links, not per-package CVE claims.
                result.append(row)
    return result


def arch(packages, data, kind, *, compare=None, stats=None):
    if not isinstance(data, list) or not data:
        raise Error("Arch feed is empty or malformed")
    installed = {p["name"]: p for p in packages}
    matches = [(installed[n], row) for row in data for n in row["packages"] if n in installed]
    def comparable(p, row):
        return (not p.get("foreign") and row.get("fixed") != "0" and
                adapters.valid_arch_version(p["version"]) and adapters.valid_arch_version(row.get("fixed")))
    pairs = sorted({(p["version"], row["fixed"]) for p, row in matches if comparable(p, row)})
    if pairs and compare is None:
        raise Error("Arch matching requires vercmp on the target")
    orders = compare(pairs) if pairs else {}
    result, omitted = [], 0
    for p, row in matches:
        if comparable(p, row) and orders[(p["version"], row["fixed"])] >= 0:
            omitted += 1
            continue
        exact = (kind == "arch" and not p.get("foreign") and p["version"] == row.get("affected")
                 and row.get("status") in ("Vulnerable", "Fixed"))
        item = finding(p, row["name"], "affected" if exact else "unknown",
                       [row["fixed"]] if row.get("fixed") else [],
                       "Exact published affected version" if exact else
                       "Installed version needs review against this notice; package lineage or fix evidence is uncertain",
                       "https://security.archlinux.org/" + row["name"])
        item.update(references=row.get("issues", []), severity=row.get("severity", "Unknown"))
        result.append(item)
    if stats is not None:
        stats["fixed_notices_omitted"] = omitted
    return result


def osv(p, data):
    if not isinstance(data, dict) or "error" in data or not isinstance(data.get("vulns", []), list):
        raise Error("OSV response is malformed")
    result = []
    for row in data.get("vulns", []):
        if row.get("withdrawn"):
            continue
        fixes = []
        for affected in row.get("affected", []):
            ap = affected.get("package", {})
            normalize = lambda n: n.lower().replace("_", "-").replace(".", "-") if p["ecosystem"] == "PyPI" else n
            if ap.get("ecosystem") != p["ecosystem"] or normalize(ap.get("name", "")) != normalize(p["name"]):
                continue
            for r in affected.get("ranges", []):
                fixes.extend(e["fixed"] for e in r.get("events", []) if "fixed" in e)
        item = finding(p, row["id"], "affected", fixes,
                       "OSV exact installed-version query; fixes are evidence, not installation targets",
                       "https://osv.dev/vulnerability/" + row["id"])
        item.update(references=row.get("aliases", []), severity=row.get("severity", []))
        result.append(item)
    return result



BREW_FIXED = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~,-]{0,127}")


def strip_credentials(url):
    """A repository URL without userinfo or a query string, so no secret reaches the report."""
    parts = urllib.parse.urlsplit(url)
    if parts.username is None and not parts.query:
        return url
    netloc = parts.hostname or ""
    if ":" in netloc:  # a bracketed IPv6 host must keep its brackets
        netloc = f"[{netloc}]"
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, "", parts.fragment))


def advisory_fields(advisory):
    """Validate the optional fields instead of trusting Homebrew's JSON types.

    A numeric overflow (1e400) decodes to infinity, which the store cannot
    serialise; an object where a string belongs is equally able to replace a
    recorded fix with nonsense.
    """
    aliases = advisory.get("aliases")
    if aliases is None:
        aliases = []
    elif not isinstance(aliases, list) or any(not isinstance(alias, str) for alias in aliases):
        raise TypeError("unexpected aliases type")
    fixed = advisory.get("fixed_versions")
    if fixed is None:
        fixed = []
    elif not isinstance(fixed, list) or any(not isinstance(value, str) or BREW_FIXED.fullmatch(value) is None
                                            for value in fixed):
        raise TypeError("unexpected fixed_versions type")
    severity, summary = advisory.get("severity"), advisory.get("summary")
    if summary is None:
        summary = ""
    elif isinstance(summary, str):
        # A display string: empty is fine, newlines collapse so it cannot break the
        # report layout. Only a non-string is malformed.
        summary = " ".join(summary.split())[:500]
    else:
        raise TypeError("unexpected advisory summary type")
    return {"id": text(advisory["id"], "advisory id"),
            "severity": "Unknown" if severity is None else text(severity, "advisory severity"),
            "summary": summary, "aliases": aliases, "fixed": fixed}


def brew_scan(t, packages, runner, *, offline=False):
    """Homebrew's own OSV scan.

    Returns (findings, warnings, coverage). Partial coverage counts as evidence
    collected: what it could not cover is named in `retained`, which is the set
    the store keeps as `unknown` instead of clearing. A missing scanner or an
    offline check collected no evidence at all, so both are incomplete.
    """
    pairs = {(p["name"], p["version"]) for p in packages if p["ecosystem"] == "Homebrew"}
    # Scan rows name the upstream version; installed kegs are indexed by base only. A keg
    # whose literal version is also another keg's base (`1_2` installed alongside `1_2_1`)
    # is ambiguous — it could be upstream 1 at revision 2 — so it is excluded from the
    # index and its findings stay unknown rather than inheriting another version's advisory.
    def is_ambiguous(name, version):
        # A bare version (base == itself) is upstream at revision 0: unambiguous.
        if adapters.brew_base(version) == version:
            return False
        # A revised keg (`1_2_1` = upstream 1_2 rev 1) is ambiguous only when another
        # keg claims its literal as that keg's own upstream version AND that keg is
        # itself revised (`1_2` = upstream 1 rev 2), so `1_2` is claimed both as an
        # upstream version and as a revision of `1`.
        return any(other != version and adapters.brew_base(other) == version
                   and adapters.brew_base(other) != other
                   for other in (v for n, v in pairs if n == name))
    # Kegs are keyed by their tap-qualified identity; scan rows are looked up by the raw
    # name Homebrew reported (its `full_name`), so a core row for a name our inventory
    # knows only under a tap is not evidence about that keg.
    ambiguous = {(p.get("tap") or p["name"], p["version"])
                 for p in packages if p["ecosystem"] == "Homebrew" and is_ambiguous(p["name"], p["version"])}
    by_base = {}
    for p in (p for p in packages if p["ecosystem"] == "Homebrew"):
        if p.get("unloadable"):
            # A keg the metadata read does not describe is never assessed; a scan row
            # must not publish a finding for it.
            continue
        key_name = p.get("tap") or p["name"]
        if (key_name, p["version"]) in ambiguous:
            continue
        by_base.setdefault((key_name, adapters.brew_base(p["version"])), []).append(p["version"])
    formulae = {name for name, _ in pairs}
    coverage = {"scanner": None, "checked": 0, "complete": False, "deferred": False,
                "skipped": [], "unscanned": {}, "outdated_without_sbom": [],
                "scanned": [], "retained": sorted(formulae),
                "retained_versions": sorted([name, version] for name, version in pairs)}
    if offline:
        coverage["deferred"] = True
        # Retention pairs carry the inventory's tap identity so JSON consumers can join
        # them with the findings in the same report.
        coverage["retained_versions"] = sorted([p.get("tap") or p["name"], p["version"]]
                                               for p in packages if p["ecosystem"] == "Homebrew")
        return [], ["Coverage: Homebrew's scan needs the target and was skipped in offline mode; prior findings retained"], coverage
    words = runner(t, adapters.brew_env("brew", "commands")).split()
    if "vulns" not in words:
        coverage["scanner"] = False
        coverage["retained_versions"] = sorted([p.get("tap") or p["name"], p["version"]]
                                               for p in packages if p["ecosystem"] == "Homebrew")
        return [], ["Coverage: this Homebrew has no vulnerability scanner; no formula was assessed"], coverage
    coverage["scanner"] = True
    raw = runner(t, adapters.brew_env("brew", "vulns", "--json"), ok=(0, 1), timeout=300)
    try:
        data = json.loads(raw)
        if not isinstance(data["findings"], list) or not isinstance(data["skipped_formulae"], list) \
                or not isinstance(data["unscanned_formulae"], dict) or not isinstance(data["checked"], int) \
                or not isinstance(data["complete"], bool) \
                or not isinstance(data.get("outdated_without_sbom", []), list):
            raise TypeError("unexpected scan field types")
        if type(data["checked"]) is not int or data["checked"] < 0:
            raise TypeError("unexpected checked type")
        coverage.update(checked=data["checked"], complete=data["complete"],
                        skipped=sorted(text(name, "skipped formula") for name in data["skipped_formulae"]),
                        unscanned={text(k, "unscanned formula"): text(v, "reason")
                                   for k, v in data["unscanned_formulae"].items()},
                        # Homebrew reports these against the current formula version, not the
                        # installed one, so they cannot clear a finding either.
                        outdated_without_sbom=sorted(text(n, "outdated formula")
                                                     for n in data.get("outdated_without_sbom") or []))
        parsed = []
        for row in data["findings"]:
            formula, version = text(row["formula"], "formula name"), text(row["version"], "installed version")
            vulnerabilities = row["vulnerabilities"]
            if not isinstance(vulnerabilities, list):
                raise TypeError("unexpected vulnerabilities type")
            repository = text(row["repo_url"], "repository URL")
            parsed.append({"formula": formula, "full_name": formula, "version": version,
                           "repository": strip_credentials(repository), "tag": text(row["tag"], "upstream tag"),
                           "vulnerabilities": [advisory_fields(a) for a in vulnerabilities]})
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise Error("Homebrew vulnerability scan output is malformed") from exc
    # The scanner considers what `brew info --installed` knows, and the inventory this
    # check already collected holds exactly that: loadable formulae with their
    # tap-qualified identity. Unloadable kegs (present in the Cellar, formula gone) are
    # never scanned. The post-scan reconciliation re-reads the metadata and discards the
    # scan if anything changed.
    considered = {p["name"] for p in packages
                  if p["ecosystem"] == "Homebrew" and not p.get("unloadable")} & formulae
    # Only loadable rows define the tap map: a Cellar-only keg's formula is gone, and a
    # bare self-map would make the bare-name identity depend on sort order.
    full_names = {p["tap"]: p["name"] for p in packages
                  if p["ecosystem"] == "Homebrew" and p.get("tap") and not p.get("unloadable")}
    coverage["considered"] = sorted(considered)
    # `brew vulns` reports `full_name`, tap-qualified for third-party taps; map those onto
    # the inventory's short names before any comparison.
    full_names_inverse = {}
    for qualified, short in full_names.items():
        full_names_inverse.setdefault(short, qualified)
    identity = lambda name: full_names_inverse.get(name, name)
    def resolve(name):
        # A raw scan name is either tap-qualified (mapped to its short name) or a bare
        # name that no tap-qualified formula claims. A bare name shadowed by a tap
        # competitor (`foo` when the inventory only knows `acme/tools/foo`) names a
        # formula that is not installed here.
        if name in full_names:
            return full_names[name]
        return None if name in full_names_inverse else name
    skipped = {resolved for name in coverage["skipped"] if (resolved := resolve(name)) is not None}
    unscanned = {resolved: reason for name, reason in coverage["unscanned"].items()
                 if (resolved := resolve(name)) is not None}
    stale = {resolved for name in coverage["outdated_without_sbom"]
             if (resolved := resolve(name)) is not None}
    # A stale target that names no installed formula consumed one of Homebrew's checked
    # slots that cannot be credited to any keg here.
    stale_unresolved = [name for name in coverage["outdated_without_sbom"] if resolve(name) is None]
    # A formula that is both skipped and stale is a contradictory scan: it cannot be
    # both refused and assessed against a stale target.
    contradictory = skipped & stale | unscanned.keys() & stale
    # `checked` is `queryable.size` in Homebrew's scanner, so it counts queryable formulae —
    # skipped and refused ones are excluded, stale ones are included.
    claimed = considered - skipped - unscanned.keys()
    # Homebrew assessed stale targets against the current formula version, and refused
    # others outright; findings for either are not evidence about this host. Rows for
    # those formulas are dropped first: they are outside `checked`, so they must not be
    # counted against its budget.
    unreliable = unscanned.keys() | stale | skipped
    parsed = [row for row in parsed if resolve(row["formula"]) not in unreliable]
    # A row is evidence only about the formula identity it names: a core row for a name our
    # inventory knows only under a tap is not evidence about that keg.
    considered_identities = {identity(n) for n in considered}
    outside = {row["formula"] for row in parsed if row["formula"] not in considered_identities}
    # A stale target consumes one of Homebrew's checked slots; if its identity is not an
    # installed formula, the slot cannot be credited to any keg that was scanned.
    if any(identity(n) not in considered_identities for n in stale) or stale_unresolved or contradictory:
        outside.add("\x00stale-outside-inventory")
    # Homebrew reports an incomplete scan: the gap must be named by an installed
    # formula, or no keg can be tied to an assessment.
    if not coverage["complete"] and not ((skipped | unscanned.keys() | stale) & considered):
        coverage["unaccounted"] = True
        coverage["unexplained_gap"] = True
    if len(claimed) != coverage["checked"] or \
            len({row["formula"] for row in parsed}) > coverage["checked"]:
        coverage["unaccounted"] = True
        claimed = set()
    if outside:
        # A finding for a formula `brew info --installed` does not know contradicts the
        # scan's own accounting; none of its evidence can be used.
        coverage["unaccounted"] = True
    for row in parsed:
        resolved = resolve(row["full_name"])
        if resolved is not None:
            row["formula"] = resolved
    # Homebrew scans one keg per formula (`formula.any_installed_prefix`) and reports the
    # upstream version as-is; installed kegs are indexed by base so a revision suffix
    # (`9.0.2_1`) still matches its upstream version (`9.0.2`). Other kegs stay unknown.
    # Duplicates are counted on the raw reported name: the scan identifies formulas by
    # their full name, whatever the inventory's short name is.
    seen_formulas = [row["full_name"] for row in parsed]
    duplicated = {name for name in seen_formulas if seen_formulas.count(name) > 1}
    if duplicated:
        # Homebrew scans one keg per formula (`any_installed_prefix`); two rows for one
        # formula contradict the scanner's own model.
        coverage["unaccounted"] = True
    matched_versions, matched_names = set(), set()
    unmatched = set()
    for row in parsed:
        # The index is keyed by the tap-qualified identity and base-only: one scan row for
        # upstream 9.0.2 reaches the revised keg 9.0.2_1. Kegs whose upstream identity is
        # uncertain (`is_ambiguous`) are absent.
        installed = by_base.get((row["full_name"], row["version"]))
        if installed:
            if row["vulnerabilities"]:
                matched_names.add(row["formula"])
                matched_versions.update((row["formula"], version) for version in installed)
            else:
                # A matched row without vulnerabilities is malformed evidence: it
                # describes nothing, so the kegs stay unknown rather than covered.
                unmatched.add(row["formula"])
        else:
            unmatched.add(row["formula"])
    # A formula with one matching and one mismatched row is not covered either way: its
    # name and every keg version drop out, so all its prior findings stay unknown.
    matched_names -= unmatched
    matched_versions = {(name, version) for name, version in matched_versions
                        if name not in unmatched}
    matched_names = {identity(name) for name in matched_names}
    matched_versions = {(identity(name), version) for name, version in matched_versions}
    # A clean formula has no row at all; absence of a finding is evidence of assessment.
    # A stale target was assessed against the wrong version, so it is never covered.
    if coverage.get("unaccounted"):
        # The accounting does not balance, so no formula can be claimed as covered.
        matched_names, matched_versions, clean = set(), set(), set()
    else:
        clean = claimed - unmatched - stale - matched_names
    # A matched row covers only the kegs sharing its base. A clean assessment describes the
    # keg Homebrew built (`any_installed_prefix`), which is identifiable only when one keg
    # of the formula is installed.
    multi_keg = {name for name, count in
                 ((name, sum(1 for n, _ in pairs if n == name)) for name in formulae) if count > 1}
    # Coverage names carry the tap-qualified identity; `retained` stays in the inventory's
    # short names, which is what the report and the store match on.
    covered_identities = matched_names | {identity(name) for name in clean if name not in multi_keg}
    covered_versions = matched_versions | {(identity(name), version) for name, version in pairs
                                           if name in clean and name not in multi_keg}
    coverage["scanned"] = sorted(covered_identities)
    covered_short_names = {full_names.get(i, i) for i in covered_identities}
    coverage["retained"] = sorted(formulae - covered_short_names)
    # Retention is keyed by the tap-qualified identity, so a formula replaced by a
    # different tap's formula of the same short name and version cannot inherit the
    # removed formula's advisory.
    covered_versions = {(identity(name), version) for name, version in covered_versions
                        if (identity(name), version) not in ambiguous}
    unloadable = {(p["name"], p["version"]) for p in packages
                  if p["ecosystem"] == "Homebrew" and p.get("unloadable")}
    # An unloadable keg's retention pair is its bare short name: the tap-qualified
    # identity its earlier finding recorded no longer exists.
    coverage["retained_versions"] = sorted(
        [name, version, "unloadable"] if (name, version) in unloadable
         else [identity(name), version]
         for name, version in pairs if (name, version) in unloadable
         or (identity(name), version) not in covered_versions)
    # A retained formula is not covered, whatever Homebrew reported; nor is a retained keg
    # of a partially covered formula.
    coverage["reported_complete"] = coverage["complete"]
    coverage["complete"] = coverage["complete"] and not coverage.get("unaccounted") \
        and not coverage["retained_versions"] and not coverage["retained"]
    warnings, result = [], []
    # Scanned names are tap-qualified identities; an unloadable keg's retained pair uses
    # the formula's short name, so compare against both forms.
    scanned_identities = {identity(n) for n in coverage["scanned"]} \
        | {full_names.get(n, n) for n in coverage["scanned"]}
    partially = sorted({pair[0] for pair in coverage["retained_versions"]} & scanned_identities)
    if partially:
        warnings.append(f"Coverage: {', '.join(partially)}: other installed kegs were not assessed by "
                        "Homebrew; their earlier findings are retained")
    if unmatched:
        empty = {row["formula"] for row in parsed if not row["vulnerabilities"]}
        ambiguous_names = {full_names.get(n, n) for n, _ in ambiguous}
        changed, empty = unmatched - empty - ambiguous_names, unmatched & empty
        unresolved = unmatched & ambiguous_names
        if unresolved:
            warnings.append(f"Coverage: {', '.join(sorted(unresolved))}: an installed keg's upstream version "
                            "cannot be determined from Homebrew's naming; earlier findings are retained")
        if changed:
            warnings.append(f"Coverage: {', '.join(sorted(changed))} changed version between collection and "
                            "Homebrew's scan; their earlier findings are retained and their scan results "
                            "are not used — re-run the check")
        if empty:
            warnings.append(f"Coverage: {', '.join(sorted(empty))}: Homebrew's scan returned a row without "
                            "advisory evidence; their earlier findings are retained and their scan results "
                            "are not used")

    for row in parsed:
        if row["formula"] in unmatched or coverage.get("unaccounted"):
            continue
        for advisory in row["vulnerabilities"]:
            for installed in by_base[(row["full_name"], row["version"])]:
                item = finding({"ecosystem": "Homebrew", "name": row["formula"], "version": installed},
                               advisory["id"], "affected", advisory["fixed"],
                               "Homebrew OSV scan matched the upstream repository and tag; coverage limited to scanned formulae",
                               "https://osv.dev/vulnerability/" + advisory["id"])
                item["key"] = digest(["Homebrew", row["full_name"], installed, advisory["id"]])
                item["upstream_version"] = row["version"]
                item.update(repository=row["repository"], tag=row["tag"], severity=advisory["severity"],
                            summary=advisory["summary"], references=advisory["aliases"],
                            tap=row["full_name"])
                result.append(item)
    if coverage.get("unexplained_gap"):
        warnings.append("Coverage: Homebrew reported an incomplete scan without a gap among the installed "
                        "formulae; no formula is claimed as covered and earlier findings are retained")
    if coverage["retained"]:
        warnings.append(f"Coverage: {len(coverage['retained'])} installed formulae were not scanned by Homebrew; "
                        "their earlier findings are retained and absence of findings is absence of evidence")
    if coverage.get("unaccounted"):
        warnings.append("Coverage: Homebrew's scan count does not match the installed set; no formula is "
                        "claimed as covered and earlier findings are retained")
    if coverage["outdated_without_sbom"]:
        warnings.append(f"Coverage: {len(coverage['outdated_without_sbom'])} formulae were scanned against the current "
                        "formula version, not the installed one; their results are not used")
    return result, sorted(set(warnings)), coverage


def advisory_references(findings, *, cves_only=False):
    """Notice-level links are context, not per-package applicability claims."""
    values = set()
    for row in findings:
        refs = row.get("references", [])
        refs = refs if isinstance(refs, list) else [refs]
        for value in [row["advisory"], *refs]:
            if isinstance(value, str) and re.fullmatch(CVE_ID if cves_only else r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", value):
                values.add(value)
    return sorted(values)


def cve_context(cve, data):
    if not isinstance(data, dict) or data.get("id") != cve or data.get("status") not in ("published", "rejected", "superseded"):
        raise Error("Invalid cve.now entry identity or status")
    summary = data.get("summary")
    if summary is not None:
        summary = {"text": text(summary["text"], "summary"), "model": text(summary["model"], "summary model"),
                   "license": "CC-BY-4.0"}
    severity = data.get("severity")
    if severity is not None:
        score = severity["cvss"]
        if type(score) not in (int, float) or not 0 <= score <= 10:
            raise Error("Invalid cve.now severity")
        severity = {"cvss": score, "source": text(severity["source"], "severity source")}
    exploitation = data.get("exploitation", {})
    signals = {}
    for key, fields in (("kev", ("dateAdded", "dueDate")), ("epssReached", ("date",))):
        value = exploitation.get(key)
        if value is not None and not isinstance(value, dict):
            raise Error("Invalid cve.now exploitation signal")
        signals[key] = {field: text(value[field], field) for field in fields if field in value} if value is not None else None
        if value is not None and not signals[key]:
            raise Error("Invalid cve.now exploitation signal")
    signals["public_exploit_sources"] = [key for key in ("exploitDb", "metasploit", "nuclei", "githubPoc") if exploitation.get(key)]
    upstream = []
    if not isinstance(data.get("sources", []), list) or len(data.get("sources", [])) > 100:
        raise Error("Invalid cve.now sources")
    for source in data.get("sources", []):
        link = text(source["url"], "source URL")
        if urllib.parse.urlsplit(link).scheme not in ("http", "https"):
            raise Error("Invalid cve.now source URL")
        upstream.append({"name": text(source["name"], "source name"), "url": link,
                         "license": text(source.get("license", "Not specified"), "source license")})
    return {"id": cve, "url": "https://cve.now/" + cve, "status": data["status"],
            "modified_at": text(data["modifiedAt"], "entry timestamp"), "summary": summary,
            "severity": severity, "signals": signals, "sources": upstream}


def pwn_context(packages, findings, data):
    if not isinstance(data, dict) or not isinstance(data.get("incidents"), list) or not data["incidents"] or len(data["incidents"]) > 20000:
        raise Error("Invalid or empty pwn.watch incident catalog")
    text(data["generatedAt"], "catalog timestamp")
    # Fixed aliases only. Tags and exact names identify review leads, never affected versions.
    aliases = {"linux-lts": "linux", "linux-zen": "linux", "linux-hardened": "linux",
               "nodejs": "node", "bind9": "bind"}
    names = {}
    for p in packages:
        # Cask names collide with unrelated projects: a cask "gemini" on this
        # host is MacPaw Gemini, not Google's gemini-cli.
        if p["ecosystem"] == "Homebrew-cask":
            continue
        normalize = lambda n: re.sub(r"[-_.]+", "-", n.lower()) if p["ecosystem"] == "PyPI" else n.lower()
        for name in {p["name"], p.get("source", p["name"])}:
            tag = normalize(name)
            for value in {tag, aliases.get(tag, tag)}:
                names.setdefault(value, set()).add(p["name"])
    references = set(advisory_references(findings))
    result, seen = [], set()
    for row in data["incidents"]:
        slug = row["slug"]
        if not isinstance(slug, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,199}", slug) or slug in seen:
            raise Error("Invalid or duplicate pwn.watch incident identity")
        seen.add(slug)
        for field in ("title", "product", "severity", "patchStatus", "updatedAt"):
            text(row[field], "incident " + field)
        if len(row["updatedAt"]) != 10 and datetime.fromisoformat(row["updatedAt"]).tzinfo is None:
            raise Error("Incident timestamp lacks a time zone")
        datetime.fromisoformat(row["updatedAt"])  # Older catalog entries may contain only a date.
        if (type(row.get("isExample")) is not bool or row["category"] not in ("patch", "supply-chain", "breach") or
                row["status"] not in ("live", "closed")):
            raise Error("Invalid pwn.watch category or status")
        tags, ids = row["tags"], row["cveIds"]
        if (not isinstance(tags, list) or len(tags) > 100 or any(not isinstance(t, str) for t in tags) or
                not isinstance(ids, list) or len(ids) > 1000 or any(not isinstance(c, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,99}", c) for c in ids)):
            raise Error("Invalid pwn.watch tags or advisory references")
        if row["isExample"] or row["category"] == "breach" or row["status"] != "live":
            continue
        matched_tags = sorted(names.keys() & set(tags))
        # A generic Linux platform tag must not associate every Linux application with the kernel.
        if "linux" in matched_tags and not row["product"].lower().startswith("linux kernel"):
            matched_tags.remove("linux")
        matched_refs = sorted(references & set(ids))
        if not matched_tags and not matched_refs:
            continue
        result.append({"id": slug, "url": "https://pwn.watch/i/" + slug,
                       "title": row["title"], "product": row["product"], "category": row["category"],
                       "severity": text(row["severity"], "incident severity"),
                       "patch_status": text(row["patchStatus"], "incident patch status"),
                       "updated_at": text(row["updatedAt"], "incident timestamp"),
                       "references": sorted(set(ids)), "matched_references": matched_refs, "matched_tags": matched_tags,
                       "packages": sorted({n for tag in matched_tags for n in names[tag]}),
                       "state": "review", "reason": "Advisory reference or package/source tag overlap only; applicability is not established"})
    return sorted(result, key=lambda r: (datetime.fromisoformat(r["updated_at"]).replace(tzinfo=timezone.utc)
                                         if len(r["updated_at"]) == 10 else datetime.fromisoformat(r["updated_at"]), r["id"]), reverse=True)


def zero_wire_catalog(raw):
    """Keep identities, dates, status and CVE tags; drop prose remediation and version advice."""
    if not isinstance(raw, str) or re.search(r"<!(DOCTYPE|ENTITY)", raw, re.I):
        raise Error("Invalid Zero Wire feed")
    channel = ET.fromstring(raw).find("channel")
    def date(value, label):
        parsed = email.utils.parsedate_to_datetime(text(value, label))
        if parsed.tzinfo is None:
            raise Error("Zero Wire date lacks a time zone")
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    items, seen = [], set()
    for row in channel.findall("item"):
        slug, at, updated = text(row.findtext("guid"), "briefing identity").partition("@")
        if (not at or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,199}", slug) or slug in seen or
                not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", updated) or
                row.findtext("link") != "https://radar.cloudflare.com/security/zero-wire/" + slug):
            raise Error("Invalid or duplicate Zero Wire briefing identity")
        datetime.fromisoformat(updated)
        seen.add(slug)
        tags = [text(c.text, "briefing tag") for c in row.findall("category")]
        if len(tags) > 100 or len(set(tags)) != len(tags):
            raise Error("Invalid Zero Wire briefing tags")
        priority = [t for t in tags if t in ("Needs attention", "Reference")]
        items.append({"id": slug, "url": row.findtext("link"), "title": text(row.findtext("title"), "briefing title"),
                      "published_at": date(row.findtext("pubDate"), "briefing date"), "updated_at": updated,
                      "priority": priority[0] if len(priority) == 1 else "Unspecified",
                      "references": sorted(t for t in tags if re.fullmatch(CVE_ID, t)),
                      "tags": sorted(t for t in tags if t not in priority and not re.fullmatch(CVE_ID, t))})
    if not items or len(items) > 1000:
        raise Error("Invalid or empty Zero Wire feed")
    return {"built_at": date(channel.findtext("lastBuildDate"), "feed date"), "items": items}


def zero_wire_context(findings, catalog):
    # Exact CVE tags only: product/topic tags such as "Node.js" or "Kernel" are not package identities.
    references = set(advisory_references(findings, cves_only=True))
    result = [{**row, "matched_references": sorted(references & set(row["references"])), "state": "review",
               "reason": "Exact CVE reference overlap only; applicability and fixes are not established"}
              for row in catalog["items"] if references & set(row["references"])]
    return sorted(result, key=lambda r: (r["updated_at"], r["id"]), reverse=True)


def context(packages, findings, store, *, offline=False, refresh=False, refreshed=None, request=fetch):
    """Optional context is stored separately; it cannot change findings or commands."""
    refreshed = set() if refreshed is None else refreshed
    result = {}
    def cached(key, url, parse, evidence):
        value = store.cached(key, lambda: parse(request(url)), offline=offline,
                             max_age=0 if refresh and key not in refreshed else 3600)
        refreshed.add(key)
        evidence.append({"source": url, "fetched_at": store.db.execute("SELECT at FROM cache WHERE key=?", (key,)).fetchone()[0]})
        return value
    failures = (Error, KeyError, TypeError, ValueError, AttributeError, RecursionError)
    cves = advisory_references(findings, cves_only=True)
    items, errors, evidence = [], [], []
    start = time.monotonic()
    for cve in cves[:20]:
        if time.monotonic() - start > 60:
            errors.append(cve + ": lookup time budget exhausted; prior context retained if present")
            continue
        try:
            item = cached("cve-now:" + cve, CVE_NOW + cve, lambda data: cve_context(cve, data), evidence)
            items.append({**item, "fetched_at": evidence[-1]["fetched_at"]})
        except failures:
            errors.append(cve + ": context unavailable or invalid; prior context retained if present")
    if len(cves) > 20:
        errors.append(f"CVE context limited to 20 of {len(cves)} referenced IDs")
    result["cve_now"] = {"status": "incomplete" if errors else "ok", "items": items, "errors": errors, "evidence": evidence}
    try:
        # Cache the public catalog once for all targets; relevance is evaluated locally each time.
        def compact(data):
            pwn_context([], [], data)  # Validate before replacing the last usable cache.
            fields = ("slug", "title", "product", "category", "status", "severity", "patchStatus", "tags", "cveIds", "updatedAt", "isExample")
            return {"generatedAt": data["generatedAt"],
                    "incidents": [{key: row[key] for key in fields} for row in data["incidents"]]}
        catalog = cached("pwn-watch", PWN, compact, evidence := [])
        incidents = [{**row, "fetched_at": evidence[-1]["fetched_at"]} for row in pwn_context(packages, findings, catalog)]
        result["pwn_watch"] = {"status": "ok", "items": incidents, "errors": [], "evidence": evidence,
                               "generated_at": catalog["generatedAt"]}
    except failures:
        result["pwn_watch"] = {"status": "incomplete", "items": [], "evidence": [],
                               "errors": ["Incident context unavailable or invalid; prior context retained if present"]}
    try:
        feed = cached("zero-wire", ZERO_WIRE, zero_wire_catalog, evidence := [])
        briefings = [{**row, "fetched_at": evidence[-1]["fetched_at"]} for row in zero_wire_context(findings, feed)]
        result["zero_wire"] = {"status": "ok", "items": briefings, "errors": [], "evidence": evidence,
                               "built_at": feed["built_at"]}
    except failures + (ET.ParseError,):
        result["zero_wire"] = {"status": "incomplete", "items": [], "evidence": [],
                               "errors": ["Zero Wire briefings unavailable or invalid; prior context retained if present"]}
    return result


def assess(t, packages, store, *, offline=False, refresh=False, refreshed=None, request=fetch, runner=adapters.run):
    findings, warnings, evidence, complete = [], [], [], True
    refreshed = set() if refreshed is None else refreshed
    kind = t["kind"]
    def cached(key, url, body=None):
        def load():
            data = request(url, body)
            return compact_usn(data) if url == USN else data
        value = store.cached(key, load, offline=offline, max_age=0 if refresh and key not in refreshed else 3600)
        refreshed.add(key)
        at = store.db.execute("SELECT at FROM cache WHERE key=?", (key,)).fetchone()[0]
        evidence.append({"source": url, "cache_key": key, "fetched_at": at})
        return value
    try:
        if kind == "ubuntu":
            findings = ubuntu(packages, cached("ubuntu-usn", USN))
            warnings.append("Coverage: Noble published security notices only, not all CVEs or pre-patch vulnerabilities; Pro/ESM excluded")
        elif kind in ("arch", "cachyos"):
            data = cached("arch-tracker", ARCH)
            stats = {}
            findings = arch(packages, data, kind, compare=lambda pairs: adapters.arch_compare(t, pairs, runner), stats=stats)
            evidence[-1]["matching"] = stats
            warnings.append("Coverage: Arch tracker may lag releases; remaining CachyOS and foreign-package matches require investigation")
        elif kind == "brew":
            findings, brew_warnings, coverage = brew_scan(t, packages, runner, offline=offline)
            warnings.extend(brew_warnings)
            evidence.append({"source": "Homebrew OSV scan", "coverage": coverage})
            # No scanner, an offline scan, or a scan whose accounting does not balance
            # collected no usable evidence.
            if coverage["scanner"] is not True or coverage["deferred"] or coverage.get("unaccounted"):
                complete = False
        else:
            unknown = sum(p["ecosystem"] == "Conda" for p in packages)
            if unknown:
                warnings.append(f"Coverage unknown for {unknown} conda-native packages; not mapped to PyPI")
            for p in packages:
                if p["ecosystem"] in ("PyPI", "npm"):
                    body = {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
                    findings.extend(osv(p, cached("osv:" + digest(body), OSV, body)))
            warnings.append("Coverage: OSV exact-version matches for collected PyPI/npm packages only; source forks and uncollected environments are not assessed")
    except (Error, KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        complete = False
        warnings.append("Advisory check failed: " + (str(exc) if isinstance(exc, Error) else "unexpected source format"))
    # Multiple installed versions can share an advisory: retain every affected version.
    merged = {}
    for row in findings:
        if row["key"] in merged:
            old = merged[row["key"]]
            row["installed"] = ", ".join(sorted(set(old["installed"].split(", ") + [row["installed"]])))
        merged[row["key"]] = row
    return list(merged.values()), warnings, complete, evidence
