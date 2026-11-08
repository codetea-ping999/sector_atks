import copy
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from sector_atks import engagement, evidence, vdc

LAB = Path(__file__).resolve().parent.parent / "examples" / "lab_engagement"
T = engagement.parse_time


class RoeTest(unittest.TestCase):
    def setUp(self):
        self.roe = json.loads((LAB / "roe.json").read_text(encoding="utf-8"))

    def test_example_is_complete(self):
        self.assertEqual(engagement.check_roe(self.roe), [])

    def test_problems_are_reported(self):
        cases = {
            "authorized_by": lambda d: d.pop("authorized_by"),
            "stop_conditions": lambda d: d.update(stop_conditions=[]),
            "environment": lambda d: d.update(environment="anywhere"),
            "production_approval_ref": lambda d: d.update(environment="approved-production"),
            "scope.hosts": lambda d: d["scope"].update(hosts=[]),
            "window.end": lambda d: d["window"].update(end="2026-11-01T00:00:00Z"),
            "offset": lambda d: d["window"].update(start="2026-11-02T00:00:00"),
            "log_retention_days": lambda d: d.update(log_retention_days=0),
        }
        for needle, mutate in cases.items():
            with self.subTest(needle=needle):
                data = copy.deepcopy(self.roe)
                mutate(data)
                problems = engagement.check_roe(data)
                self.assertTrue(any(needle in p for p in problems), problems)

    def test_load_roe_rejects_incomplete(self):
        data = copy.deepcopy(self.roe)
        del data["emergency_contact"]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "roe.json"
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                engagement.load_roe(path)

    def test_plan_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "plan.csv"
            path.write_text("scenario_id,step,technique_id,procedure_id,reference\n"
                            "S,1,T1059,a,x\nS,2,T1059,a,y\n")
            with self.assertRaises(ValueError):
                engagement.load_plan(path)


class MatchTest(unittest.TestCase):
    def run_(self, **kw):
        base = dict(run_id="R1", technique_id="T1059", procedure_id="a", host="lab-ws01",
                    started_at=T("2026-11-03T01:00:00Z"), ended_at=T("2026-11-03T01:05:00Z"))
        base.update(kw)
        return evidence.Run(**base)

    def alert(self, ts, host="lab-ws01", tags=("T1059.001",), eid="A1"):
        return evidence.Event(eid, T(ts), host, "RULE-1", tags, f"https://siem/{eid}")

    def test_alert_in_window_on_same_host_matches(self):
        (row,) = evidence.match([self.run_()], [self.alert("2026-11-03T01:04:00Z")], verifier="v").rows
        self.assertEqual((row["outcome"], row["alerted"], row["event_id"], row["verifier"]),
                         ("detected", "true", "A1", "v"))

    def test_grace_period_and_offsets(self):
        late = self.alert("2026-11-03T10:09:00+09:00")  # 01:09Z, 4 minutes after the run
        self.assertEqual(evidence.match([self.run_()], [late]).rows[0]["outcome"], "detected")
        self.assertEqual(evidence.match([self.run_()], [late], grace_seconds=60).rows[0]["outcome"], "none")

    def test_other_host_or_technique_does_not_match(self):
        alerts = [self.alert("2026-11-03T01:01:00Z", host="lab-ws02", eid="A1"),
                  self.alert("2026-11-03T01:01:00Z", tags=("T1105",), eid="A2")]
        result = evidence.match([self.run_()], alerts)
        self.assertEqual(result.rows[0]["outcome"], "none")
        self.assertEqual(result.unmatched_alerts, ["A1", "A2"])

    def test_untagged_alert_matches_and_logs_give_visibility(self):
        log = evidence.Event("L1", T("2026-11-03T01:01:00Z"), "lab-ws01")
        row = evidence.match([self.run_()], [], logs=[log], verifier="v").rows[0]
        self.assertEqual((row["outcome"], row["logged"], row["event_id"]), ("logged", "true", "L1"))
        row = evidence.match([self.run_()], [self.alert("2026-11-03T01:01:00Z", tags=())]).rows[0]
        self.assertEqual(row["outcome"], "detected")

    def test_prevented_without_alert(self):
        row = evidence.match([self.run_(prevented=True)], []).rows[0]
        self.assertEqual((row["outcome"], row["alerted"], row["verifier"]), ("prevented", "false", ""))

    def test_runs_outside_roe_are_rejected(self):
        roe = engagement.load_roe(LAB / "roe.json")
        result = evidence.match(
            [self.run_(host="lab-ws09"), self.run_(run_id="R2", started_at=T("2026-12-01T00:00:00Z"),
                                                   ended_at=T("2026-12-01T00:01:00Z"))],
            [], roe=roe)
        self.assertEqual(result.rows, [])
        self.assertEqual([r for r, _ in result.rejected], ["R1", "R2"])

    def test_naive_timestamps_are_rejected(self):
        with self.assertRaises(ValueError):
            T("2026-11-03T01:00:00")


class LabPipelineTest(unittest.TestCase):
    def test_end_to_end(self):
        result = evidence.match(
            evidence.load_runs(LAB / "runs.csv"),
            evidence.load_events(LAB / "alerts.csv"),
            evidence.load_events(LAB / "logs.csv"),
            roe=engagement.load_roe(LAB / "roe.json"),
            verifier="blue-lead",
        )
        self.assertEqual([r for r, _ in result.rejected], ["R-006"])
        self.assertEqual(result.unmatched_alerts, ["A-9004"])
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "validations.csv"
            evidence.write_validations(result.rows, path)
            report = vdc.compute(
                vdc.load_weights(LAB / "weights.csv"),
                vdc.load_validations(path),
                as_of=date(2026, 11, 7),
                plan=engagement.load_plan(LAB / "plan.csv"),
            )
        # T1059: 1 of 3 planned detected; T1087 logged only; T1003, T1070 detected
        self.assertAlmostEqual(report.vdc, 0.4 / 3 + 0.2 + 0.2)
        self.assertAlmostEqual(report.execution_rate, 5 / 6)


if __name__ == "__main__":
    unittest.main()
