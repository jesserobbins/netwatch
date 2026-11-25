"""The target lifecycle: what one check observation means for a target's state.

Pure functions over a row and an event. No filesystem, no database, no clock — the
sensors live in the adapters and the writes live in the store, and this module only
decides *where a target should land* given what a check saw.

The rules that hold across every observation:

- **Two consecutive observations** of the same failing value are needed for ambiguous
  evidence (a missing path, an unreadable identity input, a token read that errors).
  Consecutive means: the previous event pairs with this one — same generation, same
  `state_seq`, same field values, and (for an unreadable identity input) the same input.
- **One observation** is enough for unambiguous evidence: manager metadata naming another
  tool, a malformed probe, a token write that failed.
- A **superseded** event (its state write lost the compare-and-set) or an **incomplete**
  one (the run could not finish its own sequence) writes nothing and pairs with nothing.
- A **removed** row is written by no writer at all.
"""
import math

FIELDS = ("path", "identity", "token")
OUT_OF_SERVICE = ("unresolved_path", "identity_mismatch")


def _same(field, a, b):
    if a.get(field) != b.get(field):
        return False
    if field == "identity" and a.get("identity") == "unreadable":
        return a.get("identity_input") == b.get("identity_input")
    return True


def pair(previous, current):
    """May these two observations count as consecutive for a two-in-a-row rule?"""
    if not previous or not current:
        return False
    if previous.get("superseded") or current.get("superseded"):
        return False
    if not previous.get("complete", True) or not current.get("complete", True):
        return False
    if previous.get("generation") != current.get("generation"):
        return False
    if previous.get("state_seq") != current.get("state_seq"):
        return False
    return all(_same(field, previous, current) for field in FIELDS)


def recovery_candidate(row):
    """A run on an out-of-service target exists to decide whether it may come back."""
    return row.get("state") in OUT_OF_SERVICE and not row.get("removed")


def publishable(row, co_claimants, recovering=False):
    """May this run report findings and coverage under the target's name?

    An out-of-service target publishes nothing, which is what keeps one venv's packages
    from being reported under two names when two registrations claim it. A run that
    actually recovers the target does publish: it is the run that puts the target back in
    service, so its own observation is the evidence for the report.
    """
    if row.get("removed"):
        return False
    if row.get("state") in OUT_OF_SERVICE:
        # An out-of-service target publishes only when this run recovered it, and recovery
        # is blocked while another registration still holds the venv.
        return bool(recovering) and not co_claimants
    # An in-service target publishes normally even beside a twin: the conflict silences the
    # demoted twin, never the target that is in service.
    return True


def next_state(row, event, previous=None, co_claimant=False):
    """The state this observation justifies, or None to leave the target as it is."""
    if row.get("removed"):
        return None
    if event.get("superseded") or not event.get("complete", True):
        return None

    identity, token, path = event.get("identity"), event.get("token"), event.get("path")
    state = row.get("state")

    # Unambiguous, single-observation facts. Identity first: a venv that is not this tool
    # is a bigger fact than anything its token says.
    if identity == "failed":
        return "identity_mismatch"
    if token == "malformed":
        # A malformed probe does not demote an identity diagnosis that still stands.
        if state == "identity_mismatch" and identity != "ok":
            return "identity_mismatch"
        return "not_bindable"
    if token == "write_failed":
        return "not_bindable"

    # Recovery: the venv came back, and came back as this tool.
    if state in OUT_OF_SERVICE and path == "present" and identity == "ok":
        if co_claimant:
            return None
        return "live"
    if state == "not_bindable" and token == "usable":
        return "live"

    # Ambiguous evidence needs the second observation, and the pairing rule is the test.
    if path == "absent":
        return "unresolved_path" if pair(previous, event) else None
    if identity == "unreadable":
        return "identity_mismatch" if pair(previous, event) else None
    if token == "unreadable":
        return "not_bindable" if pair(previous, event) else None
    return None


def state_seq_bump(old_state, new_state):
    """Only a real change moves the counter, which is what lets two events pair."""
    return 0 if new_state is None or new_state == old_state else 1


def expires(plan, now, ttl_seconds):
    """Lazy expiry: a proposal nobody acted on stops being applicable."""
    if not plan or plan.get("status") != "proposed":
        return False
    at = plan.get("at")
    if not isinstance(at, (int, float)) or math.isnan(at):
        return False
    return now - at > ttl_seconds
