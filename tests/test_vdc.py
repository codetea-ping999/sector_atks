import tempfile
import unittest
from datetime import date
from pathlib import Path

from sector_atks import vdc

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "fictional_org"


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
            vdc.Validation("T1059", "a", date(2026, 6, 28), "detected"),  # 120 days old
            vdc.Validation("T1059", "b", self.as_of, "none"),
        ]
        r = vdc.compute(self.weights, v, self.as_of)
        t = next(x for x in r.techniques if x.technique_id == "T1059")
        self.assertAlmostEqual(t.detection_rate, 0.5)
        self.assertAlmostEqual(t.freshness, 0.5)
        self.assertEqual(t.verified_rate, 0.0)
        self.assertEqual(r.vdc, 0.0)

    def test_mixed_freshness_counts_only_fresh_successes(self):
        v = [
            vdc.Validation("T1059", "a", date(2026, 6, 28), "detected"),  # expired
            vdc.Validation("T1059", "b", date(2026, 10, 1), "detected"),
        ]
        r = vdc.compute(self.weights, v, self.as_of)
        self.assertAlmostEqual(r.vdc, 0.5 * 0.5)
        r = vdc.compute(self.weights, v, self.as_of, mode="exp", half_life=90)
        expected = 0.5 * (0.5 ** (120 / 90) + 0.5 ** (25 / 90)) / 2
        self.assertAlmostEqual(r.vdc, expected)

    def test_subtechnique_rolls_up_and_untested_is_zero(self):
        v = [vdc.Validation("T1059.001", "a", date(2026, 10, 1), "detected")]
        r = vdc.compute(self.weights, v, as_of=self.as_of)
        by_id = {t.technique_id: t for t in r.techniques}
        self.assertEqual(by_id["T1059"].procedures, 1)
        self.assertEqual(by_id["T1078"].procedures, 0)
        self.assertAlmostEqual(r.vdc, 0.5)

    def test_prevention_without_alert_or_log_is_not_detection_or_visibility(self):
        v = [vdc.Validation("T1059", "a", date(2026, 10, 1), "prevented")]
        r = vdc.compute(self.weights, v, self.as_of)
        t = next(x for x in r.techniques if x.technique_id == "T1059")
        self.assertEqual((t.detection_rate, t.prevention_rate, t.log_rate), (0.0, 1.0, 0.0))
        self.assertEqual(r.vdc, 0.0)
        self.assertAlmostEqual(vdc.compute(self.weights, v, self.as_of, counts_prevented=True).vdc, 0.5)

    def test_explicit_flags_override_outcome(self):
        v = [vdc.Validation("T1059", "a", date(2026, 10, 1), "prevented", alerted=True, logged=True)]
        t = next(x for x in vdc.compute(self.weights, v, self.as_of).techniques if x.technique_id == "T1059")
        self.assertEqual((t.detection_rate, t.prevention_rate, t.log_rate), (1.0, 1.0, 1.0))
        v = [vdc.Validation("T1059", "a", date(2026, 10, 1), "detected", logged=False)]
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
        v = [vdc.Validation("T1059", "a", date(2026, 11, 1), "detected")]
        self.assertEqual(vdc.compute(self.weights, v, self.as_of).vdc, 0.0)


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
        v = [vdc.Validation(t, "a", date(2026, 10, 1), "detected") for t in w]
        self.assertAlmostEqual(vdc.compute(w, v, date(2026, 10, 26)).vdc, 1.0)

    def test_compute_rejects_unnormalised_weights(self):
        for w in ({"T1059": ("a", 2.0), "T1078": ("b", -1.0)}, {"T1059": ("a", 0.5)}):
            with self.subTest(w=w), self.assertRaises(ValueError):
                vdc.compute(w, [], date(2026, 10, 26))


if __name__ == "__main__":
    unittest.main()
