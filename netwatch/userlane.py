"""Read what a manager recorded inside its own venv.

The scan discovers venvs by walking; this module answers what each one is, from the
receipt the manager left in it. Nothing here enumerates managers, and nothing writes.
"""
import json
import os
import stat
import tomllib
from pathlib import Path

from . import adapters, sources
from .core import Error

UVTOOL = "uvtool"
PIPX = "pipx"

UV_RECEIPT = "uv-receipt.toml"
PIPX_METADATA = "pipx_metadata.json"

# Index flags are the only pip_args entries replayed at install time; anything else is
# either dropped with a lead or blocks planning, and that decision belongs to preview.
INDEX_FLAGS = ("--index-url", "--extra-index-url", "--trusted-host", "--index",
               "--default-index", "--find-links", "--no-index", "--index-strategy")
VALUE_FLAGS = {f for f in INDEX_FLAGS if f != "--no-index"}


def _stat_pair(path: Path):
    info = path.stat()
    return info.st_dev, info.st_ino


def _receipt_index_options(receipt):
    """uv records install options in the receipt; today that means a `[tool] index` key."""
    options = []
    tool = receipt.get("tool") or {}
    for key in ("index", "default-index", "index-url", "extra-index-url", "find-links"):
        value = tool.get(key)
        if isinstance(value, str) and value:
            options.extend(["--" + key, value])
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    options.extend(["--" + key, item])
    return options


def _pip_args_index_options(pip_args):
    options, i = [], 0
    while i < len(pip_args or []):
        flag = pip_args[i]
        if flag in INDEX_FLAGS:
            options.append(flag)
            if flag != "--no-index" and i + 1 < len(pip_args):
                i += 1
                options.append(pip_args[i])
        i += 1
    return _redact(options)


def _redact(options):
    """No credential reaches the store, a plan, or a message.

    Index URLs routinely carry a token in the userinfo; the redaction strips it (and any
    query string) so what gets recorded, hashed and displayed is the shape of the option,
    never the secret.
    """
    out = []
    for option in options:
        if isinstance(option, str) and ("://" in option):
            out.append(sources.strip_credentials(option))
        else:
            out.append(option)
    return out


def _uv_tool(venv: Path):
    receipt = tomllib.loads((venv / UV_RECEIPT).read_text())
    tool = receipt.get("tool") or {}
    requirements = tool.get("requirements") or []
    if not requirements or not isinstance(requirements[0], dict):
        raise Error("uv receipt names no requirement")
    main = requirements[0]
    extras = [e for e in (main.get("extras") or []) if isinstance(e, str)]
    entry = (tool.get("entrypoints") or [{}])[0]
    install_path = entry.get("install-path") if isinstance(entry, dict) else None
    bin_dir = Path(install_path).parent if install_path else venv / "bin"
    return {"kind": UVTOOL, "name": main.get("name"), "extras": extras,
            "bin_dir": str(bin_dir),
            "index_options": _redact(_receipt_index_options(receipt))}


def _pipx(venv: Path):
    data = json.loads((venv / PIPX_METADATA).read_text())
    main = data.get("main_package") or {}
    name, spec = main.get("package"), main.get("package_or_url") or ""
    extras = []
    if "[" in spec and spec.rstrip().endswith("]"):
        extras = [e.strip() for e in spec[spec.index("[") + 1:spec.rindex("]")].split(",") if e.strip()]
    apps = main.get("app_paths") or []
    bin_dir = venv / "bin"
    if apps and isinstance(apps[0], dict) and apps[0].get("__Path__"):
        bin_dir = Path(str(apps[0]["__Path__"]).replace("VENV", str(venv))).parent
    return {"kind": PIPX, "name": name, "extras": extras, "bin_dir": str(bin_dir),
            "index_options": _redact(_pip_args_index_options(main.get("pip_args")))}


def describe(path):
    """Everything registration will need about this venv, or None if no manager claims it."""
    venv = Path(path)
    try:
        if (venv / UV_RECEIPT).is_file():
            row = _uv_tool(venv)
        elif (venv / PIPX_METADATA).is_file():
            row = _pipx(venv)
        else:
            return None
        dev, ino = _stat_pair(venv)
    except (Error, OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        return {"kind": None, "name": None, "error": "%s: %s" % (type(exc).__name__, exc)}
    if not row.get("name"):
        return {"kind": None, "name": None, "error": "manager metadata names no package"}
    row.update(realpath=os.path.realpath(venv), path_as_written=str(venv),
               st_dev=dev, st_ino=ino)
    return row


def inventory(venv, runner=adapters.run) -> list:
    """The venv's own listing: dependencies included, not just the entry point."""
    argv = ["uv", "pip", "list", "--format", "json", "--python", str(Path(venv) / "bin" / "python")]
    out = runner(argv)
    try:
        rows = json.loads(out)
    except ValueError as exc:
        raise Error("inventory output is not JSON") from exc
    if not isinstance(rows, list):
        raise Error("inventory output is malformed")
    packages = []
    for row in rows:
        if not isinstance(row, dict) or "name" not in row or "version" not in row:
            raise Error("inventory output is malformed")
        packages.append({"name": row["name"], "version": row["version"], "ecosystem": "PyPI"})
    return packages


def _installed_names(packages):
    return {p["name"].lower().replace("_", "-").replace(".", "-") for p in packages}


def identity(row, runner=adapters.run) -> dict:
    """Re-verify the scanned row on disk, then run both identity reads.

    The stat comparison is the scan-staleness test: a path component that turned symlink,
    or a different venv that now sits at the same path, is a registration error telling
    the operator to rescan — never a silent adoption of an environment the scan never saw.
    """
    venv = Path(row["realpath"])
    if not (venv / "pyvenv.cfg").is_file():
        raise Error("no venv at %s; rescan" % venv)
    if os.path.realpath(venv) != row["realpath"]:
        raise Error("%s no longer resolves to %s; rescan" % (row["path_as_written"], row["realpath"]))
    try:
        dev, ino = _stat_pair(venv)
    except OSError as exc:
        raise Error("cannot stat %s: %s; rescan" % (venv, exc)) from exc
    if (dev, ino) != (row["st_dev"], row["st_ino"]):
        raise Error("%s changed since the scan (directory replaced); rescan" % venv)
    seen = describe(venv)
    if not seen or seen.get("kind") != row.get("kind") or seen.get("name") != row.get("name"):
        raise Error("%s no longer holds %s; rescan" % (venv, row.get("name")))
    packages = inventory(venv, runner)
    wanted = (row["name"] or "").lower().replace("_", "-").replace(".", "-")
    if wanted not in _installed_names(packages):
        raise Error("%s is not installed in %s; rescan" % (row["name"], venv))
    return {"venv": str(venv), "packages": packages, "metadata": seen,
            "mode": stat.S_IMODE(venv.stat().st_mode)}
