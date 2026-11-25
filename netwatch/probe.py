"""The provenance token: one random UUID per venv, written once, never rewritten.

The token answers a question the package manager cannot: is the environment at this path
still the one an approval was bound to? It is created by `os.link` (never `rename`, which
would silently replace a probe another run just published), so two racing writers leave
exactly one token and at most one stray temp file.
"""
import os
import re
import secrets
import time
import uuid
from pathlib import Path

NAME = ".netwatch-probe"
TEMP_PREFIX = ".netwatch-probe.tmp-"
TEMP_AGE = 3600
LINE = re.compile(r"^netwatch-probe: ([0-9a-fA-F-]{36})$")


def _temp_name():
    return TEMP_PREFIX + secrets.token_hex(16)


def read(venv):
    """(status, value): usable, absent, malformed, or unreadable (an I/O error)."""
    path = Path(venv) / NAME
    try:
        text = path.read_text()
    except FileNotFoundError:
        return ("absent", None)
    except OSError as exc:
        return ("unreadable", str(exc))
    match = LINE.match(text.strip())
    if not match:
        return ("malformed", text[:80])
    try:
        uuid.UUID(match.group(1))
    except ValueError:
        return ("malformed", text[:80])
    return ("usable", match.group(1))


def cleanup(venv):
    """Remove this venv's stale temp files: strict name pattern plus age, nothing else.

    Content is not the test. An interrupted write leaves a truncated file, and the temp
    exists precisely because that crash is possible, so the name and the age decide.
    """
    removed = 0
    cutoff = time.time() - TEMP_AGE
    try:
        entries = list(Path(venv).iterdir())
    except OSError:
        return 0
    for entry in entries:
        name = entry.name
        if not name.startswith(TEMP_PREFIX):
            continue
        suffix = name[len(TEMP_PREFIX):]
        if len(suffix) != 32 or any(c not in "0123456789abcdef" for c in suffix):
            continue
        try:
            if entry.stat().st_mtime < cutoff:
                entry.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def publish(venv):
    """Create the token if absent. Returns (status, token).

    `published` — this run wrote it; `present` — another run won the race, and its token
    is the one to use; `failed` — the write itself failed (a read-only venv is the common
    case), which is unambiguous evidence for `not_bindable`.
    """
    venv = Path(venv)
    status, value = read(venv)
    if status in ("usable", "malformed", "unreadable"):
        return ("present" if status == "usable" else status, value)
    token = str(uuid.uuid4())
    temp = venv / _temp_name()
    try:
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w") as handle:
            handle.write("netwatch-probe: %s\n" % token)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        try:
            temp.unlink()
        except OSError:
            pass
        return ("failed", str(exc))
    try:
        os.link(temp, venv / NAME)
    except FileExistsError:
        # Lost the race: the winner's complete token is the one that counts.
        return ("present", read(venv)[1])
    except OSError as exc:
        return ("failed", str(exc))
    finally:
        try:
            temp.unlink()
        except OSError:
            pass
    return ("published", token)


def witness(venv):
    """What the closing read compares: the token, or the directory's inodes.

    A token readable at either read must be readable and equal at both. Falling back to
    inode numbers when a token vanished mid-check would pass a genuinely swapped venv,
    because a freed inode number can be reused by the directory that replaced it.
    """
    status, value = read(venv)
    if status == "usable":
        return {"kind": "token", "value": value}
    if status in ("malformed", "unreadable"):
        return {"kind": "unusable-token", "value": status}
    try:
        info = Path(venv).stat()
        config = (Path(venv) / "pyvenv.cfg").stat()
    except OSError:
        return {"kind": "none", "value": None}
    return {"kind": "inodes", "value": [info.st_dev, info.st_ino, config.st_ino]}
