"""Walk a filesystem and classify what it holds, without touching anything.

Two lanes come out of one walk: user-lane venvs (upgradeable, registrable as targets)
and repo-lane checkouts (never targets — they get a `.netwatch` ticket instead). The
classification uses directory structure and file presence only, so `--list` can run on a
root full of unknown checkouts before anything invokes git in them.
"""
import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

SKIP = (".git", "node_modules", ".venv", "__pycache__")
DEFAULT_DEPTH = 4

USER = "user"
REPO = "repo"
UNCLASSIFIED = "unclassified"


@dataclass
class Item:
    path: Path
    lane: str
    evidence: list = field(default_factory=list)


def _is_repo(path: Path) -> bool:
    entry = path / ".git"
    return entry.is_dir() or entry.is_file()


def _user_lane_evidence(path: Path) -> list:
    """A venv is only a candidate when a manager left its own receipt in it.

    `pyvenv.cfg` alone marks an ordinary virtualenv, which netwatch has no kind for and
    must not offer to upgrade; the receipt is what makes the environment the manager's.
    """
    if not (path / "pyvenv.cfg").is_file():
        return []
    if (path / "uv-receipt.toml").is_file():
        return ["uv-receipt.toml", "pyvenv.cfg"]
    if (path / "pipx_metadata.json").is_file():
        return ["pipx_metadata.json", "pyvenv.cfg"]
    return []


def classify(path: Path) -> Item:
    evidence = _user_lane_evidence(path)
    if evidence:
        return Item(path, USER, evidence)
    if _is_repo(path):
        return Item(path, REPO, [".git"])
    if (path / "pyvenv.cfg").is_file():
        # A venv no manager claims: worth showing, never worth offering to upgrade.
        return Item(path, UNCLASSIFIED, ["pyvenv.cfg without a manager receipt"])
    return Item(path, UNCLASSIFIED, [])


def walk(root, depth=DEFAULT_DEPTH, excludes=(), skip=SKIP):
    """Yield items under `root`, stopping at each repo root.

    The stop matters: a repo's contents are read through git by the repo lane, and
    descending would both duplicate that work and walk a tree the operator did not ask
    about. Symlinks to directories are not followed — a scan is not a filesystem crawler.
    """
    root = Path(root).expanduser()
    if not root.is_dir():
        raise NotADirectoryError(str(root))

    def descend(path: Path, level: int):
        try:
            entries = sorted(os.scandir(path), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if entry.name in skip:
                continue
            if any(fnmatch.fnmatch(entry.name, pattern) for pattern in excludes):
                continue
            if entry.is_symlink() and entry.is_dir(follow_symlinks=False):
                continue
            child = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                item = classify(child)
                if item.evidence:
                    yield item
                    continue
                if level + 1 < depth:
                    yield from descend(child, level + 1)

    return descend(root, 0)


def summary(items) -> str:
    repos = sum(1 for i in items if i.lane == REPO)
    users = sum(1 for i in items if i.lane == USER)
    boundaries = sum(1 for i in items if i.lane == UNCLASSIFIED)
    return "%d repo%s, %d user-lane, %d unclassified" % (
        repos, "" if repos == 1 else "s", users, boundaries)


def _row(item: Item, root: Path) -> tuple:
    try:
        rel = item.path.relative_to(root).as_posix() or "."
    except ValueError:
        rel = str(item.path)
    if item.lane == USER:
        lane, note = "user-lane", "tool enumeration skipped in --list"
    elif item.lane == REPO:
        lane, note = "repo-lane", "ticket, not a target"
    else:
        lane, note = "unclassified", ", ".join(item.evidence) or "no environment markers"
    return rel, lane, note


def list_only(root, depth=DEFAULT_DEPTH, excludes=(), db=None) -> str:
    """Classification table, and nothing else.

    No git, no `gh`, no tool enumeration, and no store: this mode never opens the
    database, so it neither creates a file nor runs the version migration. The `db`
    argument exists only so callers can pass the state path they resolved; it is not
    touched here.
    """
    del db
    root = Path(root).expanduser()
    items = list(walk(root, depth=depth, excludes=excludes))
    lines = [summary(items), ""]
    width = max([len(_row(i, root)[0]) for i in items] + [4])
    for item in items:
        rel, lane, note = _row(item, root)
        lines.append("%-*s  %-11s  %s" % (width, rel, lane, note))
    return "\n".join(lines)
