#!/usr/bin/env bash
# Prepare a local virtual environment for netwatch and run it from there.
#
#   ./netwatch-run.sh                          # the overview page
#   ./netwatch-run.sh status                   # any netwatch command
#   ./netwatch-run.sh scan ~/GitHub --list
#   ./netwatch-run.sh --db /tmp/t.db check     # so do the global flags
#
# The environment is created once and then reused: it is only rebuilt when it is
# missing or when pyproject.toml or requirements.lock change, so repeat runs cost
# a process start rather than an install. Progress notes go to stderr, so
# `--json` output stays machine-readable on stdout.
#
# Environment:
#   NETWATCH_VENV      where the environment lives   (default: <repo>/.venv)
#   NETWATCH_PYTHON    interpreter used to build it  (default: python3, >= 3.12)
#   NETWATCH_SETUP     set to "always" to reinstall even when nothing changed
#   NETWATCH_QUIET     set to "0" to watch the installer work
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
venv="${NETWATCH_VENV:-$root/.venv}"
python="${NETWATCH_PYTHON:-python3}"
stamp_file="$venv/.netwatch-setup"
log_file="$venv/.netwatch-setup.log"

note() { printf 'netwatch-run: %s\n' "$*" >&2; }

# 1. An interpreter new enough to run netwatch.
if ! command -v "$python" >/dev/null 2>&1; then
    note "no '$python' on PATH; set NETWATCH_PYTHON to a Python 3.12+ interpreter"
    exit 127
fi
if ! "$python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
    note "netwatch needs Python 3.12 or newer; '$python' reports $("$python" -V 2>&1)"
    exit 1
fi

# 2. What the environment must match for a repeat run to be a no-op.
if command -v shasum >/dev/null 2>&1; then
    digest() { shasum -a 256 "$@" | awk '{print $1}' | paste -sd: -; }
elif command -v sha256sum >/dev/null 2>&1; then
    digest() { sha256sum "$@" | awk '{print $1}' | paste -sd: -; }
elif command -v openssl >/dev/null 2>&1; then
    digest() { openssl dgst -sha256 "$@" | awk '{print $NF}' | paste -sd: -; }
else
    digest() { cksum "$@" | awk '{print $1 "-" $2}' | paste -sd: -; }
fi
wanted="$(digest "$root/pyproject.toml" "$root/requirements.lock")"

# 3. Build or refresh the environment. Installer chatter is kept in a log so a
#    normal run is silent; a failure prints the tail of that log.
if [ ! -x "$venv/bin/python" ]; then
    note "creating $venv with $("$python" -V 2>&1)"
    rm -f "$stamp_file"
    "$python" -m venv "$venv" || {
        note "could not create $venv; set NETWATCH_VENV to a writable path"
        exit 1
    }
fi

if [ "${NETWATCH_SETUP:-}" = "always" ] || [ "$(cat "$stamp_file" 2>/dev/null || true)" != "$wanted" ]; then
    note "installing netwatch into $venv (first run or changed pins)"
    if command -v uv >/dev/null 2>&1; then
        installer() {
            uv pip install --python "$venv/bin/python" --require-hashes \
                -r "$root/requirements.lock"
            uv pip install --python "$venv/bin/python" -e "$root"
        }
    else
        installer() {
            "$venv/bin/python" -m pip install --disable-pip-version-check \
                --require-hashes -r "$root/requirements.lock"
            "$venv/bin/python" -m pip install --disable-pip-version-check -e "$root"
        }
    fi
    if [ "${NETWATCH_QUIET:-1}" = "0" ]; then
        installer || { note "install failed"; exit 1; }
    else
        if ! installer >>"$log_file" 2>&1; then
            tail -n 20 "$log_file" >&2 || true
            note "install failed; full log at $log_file"
            exit 1
        fi
    fi
    printf '%s\n' "$wanted" >"$stamp_file"
fi

# 4. Run it. `exec` keeps netwatch's exit status and signal handling intact.
exec "$venv/bin/python" -m netwatch "$@"
