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
    return options


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
    raw = _receipt_index_options(receipt)
    return {"kind": UVTOOL, "name": main.get("name"), "extras": extras,
            "bin_dir": str(bin_dir), "index_options": raw,
            "index_options_redacted": _redact(raw)}


PIP_CONFIG_PATHS = ("pip.conf", "pip/pip.conf", ".pip/pip.conf",
                    "Library/Application Support/pip/pip.conf")
PIP_KEYS = (("global.index-url", "--index-url"),
            ("global.extra-index-url", "--extra-index-url"),
            ("global.trusted-host", "--trusted-host"))


def _pip_conf_files(home=None):
    """The pip configuration files this machine would read, most specific first."""
    import sys
    paths = []
    explicit = os.environ.get("PIP_CONFIG_FILE")
    if explicit:
        paths.append(Path(explicit))
    base = Path(home or os.path.expanduser("~"))
    for rel in PIP_CONFIG_PATHS:
        paths.append(base / rel)
    if sys.platform == "darwin":
        paths.append(Path("/Library/Application Support/pip/pip.conf"))
    paths.append(Path("/etc/pip.conf"))
    return [p for p in paths if p.is_file()]


def _pip_config_raw(home=None):
    """The same translation, unredacted: the values uv has to authenticate with."""
    options = []
    env = (("PIP_INDEX_URL", "--index-url"), ("PIP_EXTRA_INDEX_URL", "--extra-index-url"),
           ("PIP_TRUSTED_HOST", "--trusted-host"))
    for variable, flag in env:
        value = os.environ.get(variable)
        if value:
            options.extend([flag, value])
    if not options:
        import configparser
        for path in _pip_conf_files(home):
            parser = configparser.ConfigParser()
            try:
                parser.read(path)
            except (configparser.Error, OSError):
                continue
            for key, flag in PIP_KEYS:
                try:
                    value = parser.get("global", key.split(".", 1)[1])
                except (configparser.Error, KeyError):
                    continue
                if value:
                    options.extend([flag, value])
            if options:
                break
    return options


def pip_config_index_options(home=None):
    """pip's effective index options, translated to the flags uv understands.

    A pipx tool installed from a private index configured in `pip.conf` has empty
    `pip_args` — pip reads pip.conf, uv reads neither it nor PIP_* — so replaying only
    `pip_args` would silently resolve that tool against uv's default index.
    """
    return _redact(_pip_config_raw(home))


def _pipx(venv: Path):
    data = json.loads((venv / PIPX_METADATA).read_text())
    main = data.get("main_package") or {}
    name, spec = main.get("package"), main.get("package_or_url") or ""
    extras = []
    if "[" in spec and spec.rstrip().endswith("]"):
        extras = [e.strip() for e in spec[spec.index("[") + 1:spec.rindex("]")].split(",") if e.strip()]
    apps = main.get("app_paths") or []
    # pipx exposes the apps it installed into its own bin directory and symlinks them
    # there; the venv's bin is where the generated script lives, not where the operator's
    # launcher does.
    bin_dir = Path(os.environ.get("PIPX_BIN_DIR") or Path(os.path.expanduser("~/.local/bin")))
    if apps and isinstance(apps[0], dict) and apps[0].get("__Path__"):
        inside = Path(str(apps[0]["__Path__"]).replace("VENV", str(venv)))
        if inside.parent != venv / "bin":
            bin_dir = inside.parent
    recorded = _pip_args_index_options(main.get("pip_args"))
    # pip_args only carry what pipx itself was told; pip's own configuration is what a
    # pip.conf-only install resolves against, so it is the fallback.
    raw = recorded or _pip_config_raw()
    return {"kind": PIPX, "name": name, "extras": extras, "bin_dir": str(bin_dir),
            "index_options": raw, "index_options_redacted": _redact(raw),
            "index_source": "pip_args" if recorded else "pip_config"}


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
