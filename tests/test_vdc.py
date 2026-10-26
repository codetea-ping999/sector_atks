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
        self.assertEqual(scores["T1021"], 0.0)
        self.assertEqual(layer["versions"]["attack"], "20")


class UnitTest(unittest.TestCase):
    weights = {"T1059": ("Command and Scripting Interpreter", 0.5), "T1078": ("Valid Accounts", 0.5)}

    def test_freshness_modes(self):
        self.assertEqual(vdc.freshness(90, "step", window=90), 1.0)
        self.assertEqual(vdc.freshness(91, "step", window=90), 0.0)
        self.assertAlmostEqual(vdc.freshness(90, "exp", half_life=90), 0.5)
        with self.assertRaises(ValueError):
            vdc.freshness(-1)

    def test_subtechnique_rolls_up_and_untested_is_zero(self):
        v = [vdc.Validation("T1059.001", "a", date(2026, 10, 1), "detected")]
        r = vdc.compute(self.weights, v, as_of=date(2026, 10, 26))
        by_id = {t.technique_id: t for t in r.techniques}
        self.assertEqual(by_id["T1059"].procedures, 1)
        self.assertEqual(by_id["T1078"].procedures, 0)
        self.assertAlmostEqual(r.vdc, 0.5)

    def test_prevented_can_be_excluded(self):
        v = [vdc.Validation("T1059", "a", date(2026, 10, 1), "prevented")]
        self.assertAlmostEqual(vdc.compute(self.weights, v, date(2026, 10, 26)).vdc, 0.5)
        self.assertAlmostEqual(
            vdc.compute(self.weights, v, date(2026, 10, 26), prevented_counts=False).vdc, 0.0
        )

    def test_future_records_are_ignored(self):
        v = [vdc.Validation("T1059", "a", date(2026, 11, 1), "detected")]
        self.assertEqual(vdc.compute(self.weights, v, date(2026, 10, 26)).vdc, 0.0)


if __name__ == "__main__":
    unittest.main()
