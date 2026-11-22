import unittest

from netwatch import lifecycle


def row(state="live", generation=1, state_seq=0, removed=0):
    return {"state": state, "generation": generation, "state_seq": state_seq, "removed": removed}


def ev(**kw):
    base = {"path": "present", "identity": "ok", "identity_input": "none",
            "token": "usable", "complete": True, "generation": 1, "state_seq": 0,
            "superseded": False}
    base.update(kw)
    return base


ABSENT = dict(path="absent", identity="not_evaluated", token="not_read")


class PairingTests(unittest.TestCase):
    def test_identical_observations_pair(self):
        self.assertTrue(lifecycle.pair(ev(**ABSENT), ev(**ABSENT)))

    def test_a_different_generation_never_pairs(self):
        self.assertFalse(lifecycle.pair(ev(**ABSENT, generation=1), ev(**ABSENT, generation=2)))

    def test_a_transition_between_them_never_pairs(self):
        self.assertFalse(lifecycle.pair(ev(**ABSENT, state_seq=0), ev(**ABSENT, state_seq=1)))

    def test_superseded_or_incomplete_events_never_pair(self):
        self.assertFalse(lifecycle.pair(ev(**ABSENT, superseded=True), ev(**ABSENT)))
        self.assertFalse(lifecycle.pair(ev(**ABSENT), ev(**ABSENT, complete=False)))

    def test_a_different_field_value_does_not_pair(self):
        self.assertFalse(lifecycle.pair(ev(**ABSENT), ev()))

    def test_unreadable_identity_pairs_only_on_the_same_input(self):
        a = ev(identity="unreadable", identity_input="receipt")
        b = ev(identity="unreadable", identity_input="listing")
        self.assertFalse(lifecycle.pair(a, b))
        self.assertTrue(lifecycle.pair(a, ev(identity="unreadable", identity_input="receipt")))


class OneShotTests(unittest.TestCase):
    def test_a_clean_identity_failure_sets_identity_mismatch_at_once(self):
        self.assertEqual(lifecycle.next_state(row(), ev(identity="failed")), "identity_mismatch")

    def test_a_malformed_probe_sets_not_bindable_at_once(self):
        self.assertEqual(lifecycle.next_state(row(), ev(token="malformed")), "not_bindable")

    def test_a_failed_token_write_sets_not_bindable_at_once(self):
        self.assertEqual(lifecycle.next_state(row(), ev(token="write_failed")), "not_bindable")

    def test_a_clean_read_recovers_identity_mismatch(self):
        self.assertEqual(lifecycle.next_state(row("identity_mismatch"), ev()), "live")

    def test_a_usable_probe_recovers_not_bindable(self):
        self.assertEqual(lifecycle.next_state(row("not_bindable"), ev()), "live")

    def test_a_malformed_probe_does_not_demote_a_failing_identity_read(self):
        state = lifecycle.next_state(row("identity_mismatch"),
                                     ev(identity="failed", token="malformed"))
        self.assertEqual(state, "identity_mismatch")


class StreakTests(unittest.TestCase):
    def test_two_consecutive_absences_set_unresolved_path(self):
        prev, cur = ev(**ABSENT), ev(**ABSENT)
        self.assertEqual(lifecycle.next_state(row(), cur, previous=prev), "unresolved_path")

    def test_one_absence_changes_nothing(self):
        self.assertIsNone(lifecycle.next_state(row(), ev(**ABSENT)))

    def test_a_present_observation_resets_the_absence_streak(self):
        self.assertIsNone(lifecycle.next_state(row(), ev(**ABSENT), previous=ev()))

    def test_two_unreadable_identity_reads_set_identity_mismatch(self):
        a = ev(identity="unreadable", identity_input="receipt")
        self.assertEqual(lifecycle.next_state(row(), a, previous=a), "identity_mismatch")

    def test_one_unreadable_identity_read_changes_nothing(self):
        a = ev(identity="unreadable", identity_input="receipt")
        self.assertIsNone(lifecycle.next_state(row(), a))

    def test_two_unreadable_token_reads_set_not_bindable(self):
        a = ev(token="unreadable")
        self.assertIsNone(lifecycle.next_state(row(), a))
        self.assertEqual(lifecycle.next_state(row(), a, previous=a), "not_bindable")

    def test_a_complete_event_that_could_not_finish_publishes_nothing(self):
        cur = ev(**ABSENT, complete=False)
        self.assertIsNone(lifecycle.next_state(row(), cur, previous=ev(**ABSENT, complete=False)))


class RecoveryTests(unittest.TestCase):
    def test_an_unresolved_path_target_recovers_when_the_venv_returns(self):
        self.assertEqual(lifecycle.next_state(row("unresolved_path"), ev()), "live")

    def test_recovery_is_refused_while_a_co_claimant_holds_the_venv(self):
        self.assertIsNone(lifecycle.next_state(row("unresolved_path"), ev(), co_claimant=True))

    def test_a_returned_venv_with_an_unusable_probe_recovers_to_not_bindable(self):
        self.assertEqual(lifecycle.next_state(row("unresolved_path"), ev(token="malformed")),
                         "not_bindable")

    def test_a_returned_read_only_venv_lands_on_not_bindable(self):
        self.assertEqual(lifecycle.next_state(row("unresolved_path"), ev(token="write_failed")),
                         "not_bindable")

    def test_a_foreign_venv_at_the_path_is_an_identity_mismatch_not_missing_path(self):
        self.assertEqual(lifecycle.next_state(row("unresolved_path"), ev(identity="failed")),
                         "identity_mismatch")


class PolicyTests(unittest.TestCase):
    def test_a_removed_row_is_written_by_no_writer(self):
        self.assertIsNone(lifecycle.next_state(row(removed=1), ev(identity="failed")))

    def test_a_superseded_event_writes_no_state(self):
        self.assertIsNone(lifecycle.next_state(row(), ev(identity="failed", superseded=True)))

    def test_an_unchanged_observation_returns_no_state(self):
        self.assertIsNone(lifecycle.next_state(row(), ev()))

    def test_recovery_candidate_is_true_only_for_out_of_service_states(self):
        self.assertTrue(lifecycle.recovery_candidate(row("unresolved_path")))
        self.assertTrue(lifecycle.recovery_candidate(row("identity_mismatch")))
        self.assertFalse(lifecycle.recovery_candidate(row("live")))
        self.assertFalse(lifecycle.recovery_candidate(row("not_bindable")))

    def test_publishable_is_false_for_out_of_service_targets(self):
        self.assertTrue(lifecycle.publishable(row("live"), []))
        self.assertFalse(lifecycle.publishable(row("identity_mismatch"), []))
        self.assertFalse(lifecycle.publishable(row("unresolved_path"), []))
        self.assertFalse(lifecycle.publishable(row("live"), [{"name": "twin"}]))
        self.assertTrue(lifecycle.publishable(row("not_bindable"), []))

    def test_a_recovering_run_publishes(self):
        self.assertTrue(lifecycle.publishable(row("unresolved_path"), [], recovering=True))


if __name__ == "__main__":
    unittest.main()
