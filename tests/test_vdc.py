import tempfile
import unittest
from datetime import date
from pathlib import Path

from sector_atks.engagement import parse_time

from sector_atks import engagement, vdc

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "fictional_org"


def V(*args, **kwargs):
    """A validation record with evidence attached (event id and verifier)."""
    kwargs.setdefault("event_id", "EVT-1")
    kwargs.setdefault("verifier", "tester")
    kwargs.setdefault("engagement_id", "E1")
    return vdc.Validation(*args, **kwargs)


def P(technique_id, procedure_id, engagement_id="E1", plan_id="PLAN", plan_version="1"):
    return engagement.PlannedProcedure("S", 1, technique_id, procedure_id, "",
                                       engagement_id, plan_id, plan_version)


class FictionalOrgTest(unittest.TestCase):
    """The worked example in the research notes (06_検証済み検知カバレッジ.md)."""

    def setUp(self):
        self.report = vdc.compute(
            vdc.load_weights(EXAMPLE / "weights.csv"),
            vdc.load_validations(EXAMPLE / "validations.csv"),
            as_of=date(2026, 10, 26),
            claimed=vdc.load_claimed(EXAMPLE / "claimed.csv"),
            previous_as_of=date(2026, 8, 31),
        )
        self.by_id = {t.technique_id: t for t in self.report.techniques}

    def test_vdc_matches_notes(self):
        self.assertAlmostEqual(self.report.vdc, 0.50)

    def test_claim_gap(self):
        self.assertAlmostEqual(self.report.claimed_coverage, 1.0)
        self.assertAlmostEqual(self.report.claim_gap, 0.50)

    def test_detection_rates_use_latest_result_per_procedure(self):
        self.assertAlmostEqual(self.by_id["T1059"].detection_rate, 0.60)
        self.assertAlmostEqual(self.by_id["T1078"].detection_rate, 0.25)

    def test_stale_validation_scores_zero(self):
        t = self.by_id["T1021"]
        self.assertEqual(t.detection_rate, 1.0)
        self.assertEqual(t.freshness, 0.0)
        self.assertEqual(t.contribution, 0.0)

    def test_regression_and_remediation(self):
        self.assertEqual(self.report.regressed, ["T1078"])
        self.assertAlmostEqual(self.report.regression_rate, 0.5)
        self.assertEqual(self.report.remediations, 1)
        self.assertAlmostEqual(self.report.mean_days_to_remediate, 30.0)

    def test_priority_order(self):
        self.assertEqual(self.report.techniques[0].technique_id, "T1021")  # ties sort by id
        self.assertEqual(self.report.techniques[-1].technique_id, "T1566")

    def test_navigator_layer(self):
        layer = vdc.navigator_layer(self.report, "test", "20")
        scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        self.assertEqual(scores["T1566"], 1.0)
        self.assertEqual(scores["T1059"], 0.6)
        self.assertEqual(scores["T1021"], 0.0)
        self.assertEqual(layer["versions"]["attack"], "20")


class UnitTest(unittest.TestCase):
    weights = {"T1059": ("Command and Scripting Interpreter", 0.5), "T1078": ("Valid Accounts", 0.5)}
    as_of = date(2026, 10, 26)

    def test_freshness_modes(self):
        self.assertEqual(vdc.freshness(90, "step", window=90), 1.0)
        self.assertEqual(vdc.freshness(91, "step", window=90), 0.0)
        self.assertAlmostEqual(vdc.freshness(90, "exp", half_life=90), 0.5)
        with self.assertRaises(ValueError):
            vdc.freshness(-1)

    def test_freshness_is_per_procedure(self):
        # An expired success must not be refreshed by a recent failure of another procedure.
        v = [
            V("T1059", "a", date(2026, 6, 28), "detected"),  # 120 days old
            V("T1059", "b", self.as_of, "none"),
        ]
        r = vdc.compute(self.weights, v, self.as_of)
        t = next(x for x in r.techniques if x.technique_id == "T1059")
        self.assertAlmostEqual(t.detection_rate, 0.5)
        self.assertAlmostEqual(t.freshness, 0.5)
        self.assertEqual(t.verified_rate, 0.0)
        self.assertEqual(r.vdc, 0.0)

    def test_mixed_freshness_counts_only_fresh_successes(self):
        v = [
            V("T1059", "a", date(2026, 6, 28), "detected"),  # expired
            V("T1059", "b", date(2026, 10, 1), "detected"),
        ]
        r = vdc.compute(self.weights, v, self.as_of)
        self.assertAlmostEqual(r.vdc, 0.5 * 0.5)
        r = vdc.compute(self.weights, v, self.as_of, mode="exp", half_life=90)
        expected = 0.5 * (0.5 ** (120 / 90) + 0.5 ** (25 / 90)) / 2
        self.assertAlmostEqual(r.vdc, expected)

    def test_subtechnique_rolls_up_and_untested_is_zero(self):
        v = [V("T1059.001", "a", date(2026, 10, 1), "detected")]
        r = vdc.compute(self.weights, v, as_of=self.as_of)
        by_id = {t.technique_id: t for t in r.techniques}
        self.assertEqual(by_id["T1059"].procedures, 1)
        self.assertEqual(by_id["T1078"].procedures, 0)
        self.assertAlmostEqual(r.vdc, 0.5)

    def test_prevention_without_alert_or_log_is_not_detection_or_visibility(self):
        v = [V("T1059", "a", date(2026, 10, 1), "prevented")]
        r = vdc.compute(self.weights, v, self.as_of)
        t = next(x for x in r.techniques if x.technique_id == "T1059")
        self.assertEqual((t.detection_rate, t.prevention_rate, t.log_rate), (0.0, 1.0, 0.0))
        self.assertEqual(r.vdc, 0.0)
        self.assertAlmostEqual(vdc.compute(self.weights, v, self.as_of, counts_prevented=True).vdc, 0.5)

    def test_explicit_flags_override_outcome(self):
        v = [V("T1059", "a", date(2026, 10, 1), "prevented", alerted=True, logged=True)]
        t = next(x for x in vdc.compute(self.weights, v, self.as_of).techniques if x.technique_id == "T1059")
        self.assertEqual((t.detection_rate, t.prevention_rate, t.log_rate), (1.0, 1.0, 1.0))
        v = [V("T1059", "a", date(2026, 10, 1), "detected", logged=False)]
        t = next(x for x in vdc.compute(self.weights, v, self.as_of).techniques if x.technique_id == "T1059")
        self.assertEqual((t.detection_rate, t.log_rate), (1.0, 0.0))

    def test_flag_columns_are_parsed(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "v.csv"
            path.write_text(
                "technique_id,procedure_id,tested_on,outcome,prevented,alerted,logged\n"
                "T1059,a,2026-10-01,prevented,,yes,0\n"
            )
            (v,) = vdc.load_validations(path)
            self.assertEqual(v.flags(), (True, True, False))
            path.write_text(
                "technique_id,procedure_id,tested_on,outcome,alerted\nT1059,a,2026-10-01,none,maybe\n"
            )
            with self.assertRaises(ValueError):
                vdc.load_validations(path)

    def test_future_records_are_ignored(self):
        v = [V("T1059", "a", date(2026, 11, 1), "detected")]
        self.assertEqual(vdc.compute(self.weights, v, self.as_of).vdc, 0.0)


class EvidencePlanFreshnessTest(unittest.TestCase):
    weights = {"T1059": ("Command and Scripting Interpreter", 0.5), "T1078": ("Valid Accounts", 0.5)}
    as_of = date(2026, 10, 26)

    def test_alert_without_evidence_is_not_counted(self):
        bare = [vdc.Validation("T1059", "a", date(2026, 10, 1), "detected")]
        r = vdc.compute(self.weights, bare, self.as_of)
        self.assertEqual(r.vdc, 0.0)
        self.assertEqual(r.unverified, 1)
        no_verifier = [vdc.Validation("T1059", "a", date(2026, 10, 1), "detected", event_id="E1")]
        self.assertEqual(vdc.compute(self.weights, no_verifier, self.as_of).vdc, 0.0)
        uri = [vdc.Validation("T1059", "a", date(2026, 10, 1), "detected",
                              evidence_uri="https://siem/x", verifier="v")]
        self.assertAlmostEqual(vdc.compute(self.weights, uri, self.as_of).vdc, 0.5)
        self.assertAlmostEqual(vdc.compute(self.weights, bare, self.as_of, requires_evidence=False).vdc, 0.5)

    def test_plan_counts_untested_procedures_as_misses(self):
        plan = [P("T1059", p) for p in ("a", "b", "c", "d")]
        v = [V("T1059", "a", date(2026, 10, 1), "detected")]
        r = vdc.compute(self.weights, v, self.as_of)
        self.assertAlmostEqual(r.vdc, 0.5)  # one easy procedure would score 100% without a plan
        r = vdc.compute(self.weights, v, self.as_of, plan=plan)
        t = next(x for x in r.techniques if x.technique_id == "T1059")
        self.assertEqual((t.planned, t.executed_planned, t.unplanned), (4, 1, 0))
        self.assertAlmostEqual(t.execution_rate, 0.25)
        self.assertAlmostEqual(t.verified_rate, 0.25)
        self.assertAlmostEqual(r.vdc, 0.125)
        self.assertAlmostEqual(r.execution_rate, 0.25)

    def test_unplanned_runs_are_kept_in_the_denominator(self):
        plan = [P("T1059", "a")]
        v = [V("T1059", "a", date(2026, 10, 1), "detected"), V("T1059", "x", date(2026, 10, 1), "none")]
        t = next(x for x in vdc.compute(self.weights, v, self.as_of, plan=plan).techniques
                 if x.technique_id == "T1059")
        self.assertEqual((t.planned, t.unplanned), (1, 1))
        self.assertAlmostEqual(t.verified_rate, 0.5)

    def test_freshness_debt_is_separate_from_regression(self):
        v = [V("T1059", "a", date(2026, 6, 1), "detected")]
        r = vdc.compute(self.weights, v, self.as_of, previous_as_of=date(2026, 7, 1))
        self.assertEqual(r.regression_rate, 0.0)  # capability did not change
        self.assertAlmostEqual(r.vdc_previous, 0.5)
        self.assertEqual(r.vdc, 0.0)
        self.assertAlmostEqual(r.freshness_debt, 0.5)  # but the verification expired
        self.assertEqual(r.freshness_debt_previous, 0.0)

    def test_invalid_freshness_parameters(self):
        for kwargs in ({"mode": "exp", "half_life": 0}, {"mode": "exp", "half_life": -5},
                       {"window": -1}, {"mode": "linear"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                vdc.compute(self.weights, [], self.as_of, **kwargs)

    def test_example_plan(self):
        r = vdc.compute(
            vdc.load_weights(EXAMPLE / "weights.csv"),
            vdc.load_validations(EXAMPLE / "validations.csv"),
            as_of=self.as_of,
            plan=engagement.load_plan(EXAMPLE / "plan.csv"),
        )
        self.assertAlmostEqual(r.vdc, 0.475)
        self.assertAlmostEqual(r.execution_rate, 18 / 20)
        self.assertEqual((r.engagement_id, r.plan_id, r.excluded_records), ("FO-2026", "FO-PLAN", 0))


class ReviewRegressionTest(unittest.TestCase):
    """Regression tests for the PR #2 review (P1-2, P1-3, P1-4, P2)."""

    weights = {"T1059": ("Command and Scripting Interpreter", 0.5), "T1078": ("Valid Accounts", 0.5)}
    as_of = date(2026, 11, 7)

    def _t1059(self, report):
        return next(t for t in report.techniques if t.technique_id == "T1059")

    def test_same_day_rerun_does_not_depend_on_row_order(self):
        fail = V("T1059", "a", date(2026, 11, 3), "none", event_id="", verifier="",
                 tested_at=parse_time("2026-11-03T01:00:00Z"))
        ok = V("T1059", "a", date(2026, 11, 3), "detected",
               tested_at=parse_time("2026-11-03T10:30:00+09:00"))  # 01:30Z, later
        for rows in ([fail, ok], [ok, fail]):
            with self.subTest(order=[v.outcome for v in rows]):
                self.assertAlmostEqual(vdc.compute(self.weights, rows, self.as_of).vdc, 0.5)
        fixed_later = V("T1059", "a", date(2026, 11, 3), "none", event_id="", verifier="",
                        tested_at=parse_time("2026-11-03T02:00:00Z"))
        for rows in ([ok, fixed_later], [fixed_later, ok]):
            self.assertEqual(vdc.compute(self.weights, rows, self.as_of).vdc, 0.0)

    def test_same_day_records_without_time_or_same_time_are_rejected(self):
        a = V("T1059", "a", date(2026, 11, 3), "none")
        b = V("T1059", "a", date(2026, 11, 3), "detected")
        with self.assertRaisesRegex(ValueError, "tested_at"):
            vdc.compute(self.weights, [a, b], self.as_of)
        t = parse_time("2026-11-03T01:00:00Z")
        with self.assertRaisesRegex(ValueError, "same tested_at"):
            vdc.compute(self.weights, [V("T1059", "a", date(2026, 11, 3), "none", tested_at=t),
                                       V("T1059", "a", date(2026, 11, 3), "detected", tested_at=t)],
                        self.as_of)

    def test_tested_at_must_agree_with_tested_on(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "v.csv"
            path.write_text("technique_id,procedure_id,tested_on,tested_at,outcome\n"
                            "T1059,a,2026-11-03,2026-11-03T08:00:00+09:00,none\n")  # 11-02 in UTC
            with self.assertRaisesRegex(ValueError, "UTC date"):
                vdc.load_validations(path)
            path.write_text("technique_id,procedure_id,tested_at,outcome\n"
                            "T1059,a,2026-11-03T01:00:00,none\n")
            with self.assertRaisesRegex(ValueError, "offset"):
                vdc.load_validations(path)

    def test_prevention_claim_without_block_evidence_is_not_verified(self):
        claim = vdc.Validation("T1059", "a", date(2026, 11, 3), "prevented", prevention_claimed=True)
        r = vdc.compute(self.weights, [claim], self.as_of, counts_prevented=True)
        self.assertEqual((r.vdc, r.prevention_rate), (0.0, 0.0))
        self.assertEqual(r.prevention_rate_claimed, 1.0)
        self.assertEqual(r.prevention_claims_unverified, 1)
        blocked = V("T1059", "a", date(2026, 11, 3), "prevented", prevention_claimed=True)
        r = vdc.compute(self.weights, [blocked], self.as_of, counts_prevented=True)
        self.assertEqual((r.prevention_rate, r.prevention_claims_unverified), (1.0, 0))

    def test_log_rate_needs_evidence(self):
        bare = vdc.Validation("T1059", "a", date(2026, 11, 3), "logged")
        r = vdc.compute(self.weights, [bare], self.as_of)
        self.assertEqual((r.log_rate, r.log_rate_claimed), (0.0, 1.0))
        logged = vdc.Validation("T1059", "a", date(2026, 11, 3), "logged", log_event_id="L1", verifier="v")
        self.assertEqual(vdc.compute(self.weights, [logged], self.as_of).log_rate, 1.0)

    def test_ambiguous_match_is_not_counted(self):
        v = V("T1059", "a", date(2026, 11, 3), "detected", match_status="ambiguous")
        r = vdc.compute(self.weights, [v], self.as_of)
        self.assertEqual((r.vdc, r.ambiguous, r.unverified), (0.0, 1, 0))

    def test_past_engagement_records_do_not_execute_a_new_plan(self):
        plan = [P("T1059", p, engagement_id="E2", plan_id="P2") for p in ("a", "b")]
        old = [V("T1059", "a", date(2026, 10, 1), "detected", engagement_id="E1"),
               V("T1059", "b", date(2026, 10, 1), "detected", engagement_id="")]
        r = vdc.compute(self.weights, old, self.as_of, plan=plan)
        self.assertEqual((r.vdc, r.execution_rate, r.excluded_records), (0.0, 0.0, 2))
        new = old + [V("T1059", "a", date(2026, 11, 3), "detected", engagement_id="E2")]
        r = vdc.compute(self.weights, new, self.as_of, plan=plan)
        self.assertAlmostEqual(r.execution_rate, 0.5)
        self.assertAlmostEqual(r.vdc, 0.25)
        other_plan = [V("T1059", "b", date(2026, 11, 3), "detected", engagement_id="E2",
                        plan_id="P1")]
        r = vdc.compute(self.weights, new + other_plan, self.as_of, plan=plan)
        self.assertEqual((r.excluded_records, self._t1059(r).executed_planned), (3, 1))

    def test_plan_needs_one_identity(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            vdc.compute(self.weights, [], self.as_of, plan=[P("T1059", "a", engagement_id="")])
        with self.assertRaisesRegex(ValueError, "one engagement_id"):
            vdc.compute(self.weights, [], self.as_of,
                        plan=[P("T1059", "a"), P("T1059", "b", plan_version="2")])


class WeightValidationTest(unittest.TestCase):
    def _load(self, body):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "w.csv"
            path.write_text("technique_id,name,weight\n" + body)
            return vdc.load_weights(path)

    def test_rejects_negative_nan_inf_duplicates_and_text(self):
        for body in (
            "T1059,a,1.0\nT1078,b,-0.5\n",
            "T1059,a,nan\n",
            "T1059,a,inf\n",
            "T1059,a,0.5\nT1059,a,0.5\n",
            "T1059,a,heavy\n",
            "T1059,a,0\n",
            "T1059,a,\n",
        ):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self._load(body)

    def test_normalises_and_bounds_result(self):
        w = self._load("T1059,a,3\nT1078,b,1\n")
        self.assertAlmostEqual(w["T1059"][1], 0.75)
        v = [V(t, "a", date(2026, 10, 1), "detected") for t in w]
        self.assertAlmostEqual(vdc.compute(w, v, date(2026, 10, 26)).vdc, 1.0)

    def test_compute_rejects_unnormalised_weights(self):
        for w in ({"T1059": ("a", 2.0), "T1078": ("b", -1.0)}, {"T1059": ("a", 0.5)}):
            with self.subTest(w=w), self.assertRaises(ValueError):
                vdc.compute(w, [], date(2026, 10, 26))


if __name__ == "__main__":
    unittest.main()
