import contextlib
import copy
import io
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from sector_atks import cli, engagement, evidence, vdc

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
            head = "engagement_id,plan_id,plan_version,scenario_id,step,technique_id,procedure_id,reference\n"
            path.write_text(head + "E,P,1,S,1,T1059,a,x\nE,P,1,S,2,T1059,a,y\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                engagement.load_plan(path)

    def test_plan_needs_identity_columns_and_one_version(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "plan.csv"
            path.write_text("scenario_id,step,technique_id,procedure_id,reference\nS,1,T1059,a,x\n")
            with self.assertRaisesRegex(ValueError, "engagement_id"):
                engagement.load_plan(path)
            head = "engagement_id,plan_id,plan_version,scenario_id,step,technique_id,procedure_id,reference\n"
            path.write_text(head + "E,P,1,S,1,T1059,a,x\nE,P,2,S,2,T1059,b,y\n")
            with self.assertRaisesRegex(ValueError, "one engagement_id"):
                engagement.load_plan(path)


class MatchTest(unittest.TestCase):
    def run_(self, **kw):
        base = dict(run_id="R1", technique_id="T1059", procedure_id="a", host="lab-ws01",
                    started_at=T("2026-11-03T01:00:00Z"), ended_at=T("2026-11-03T01:05:00Z"))
        base.update(kw)
        return evidence.Run(**base)

    def alert(self, ts, host="lab-ws01", tags=("T1059.001",), eid="A1", run_id="", action="alert"):
        return evidence.Event(eid, T(ts), host, "RULE-1", tags, f"https://siem/{eid}", run_id, action)

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

    def test_logs_give_visibility_but_not_alert_evidence(self):
        log = evidence.Event("L1", T("2026-11-03T01:01:00Z"), "lab-ws01")
        row = evidence.match([self.run_()], [], logs=[log], verifier="v").rows[0]
        self.assertEqual((row["outcome"], row["logged"], row["event_id"], row["log_event_id"]),
                         ("logged", "true", "", "L1"))

    # --- regression tests for the PR #2 review -------------------------------------------

    def test_alert_overlapping_two_runs_is_ambiguous(self):
        runs = [self.run_(), self.run_(run_id="R2", procedure_id="b",
                                       started_at=T("2026-11-03T01:03:00Z"),
                                       ended_at=T("2026-11-03T01:06:00Z"))]
        result = evidence.match(runs, [self.alert("2026-11-03T01:04:00Z")], verifier="v")
        self.assertEqual(result.contested_events, ["A1"])
        self.assertEqual(result.ambiguous, ["R1", "R2"])
        self.assertEqual(result.status, "needs_review")
        for row in result.rows:
            self.assertEqual((row["match_status"], row["alerted"], row["event_id"],
                              row["candidate_event_id"], row["verifier"]),
                             ("ambiguous", "false", "", "A1", ""))

    def test_run_id_on_the_alert_resolves_the_overlap(self):
        runs = [self.run_(), self.run_(run_id="R2", procedure_id="b",
                                       started_at=T("2026-11-03T01:03:00Z"),
                                       ended_at=T("2026-11-03T01:06:00Z"))]
        result = evidence.match(runs, [self.alert("2026-11-03T01:04:00Z", run_id="R2")], verifier="v")
        self.assertEqual(result.status, "complete")
        by_run = {r["run_id"]: r for r in result.rows}
        self.assertEqual((by_run["R1"]["alerted"], by_run["R2"]["alerted"]), ("false", "true"))

    def test_untagged_alert_is_not_a_confirmed_detection(self):
        result = evidence.match([self.run_()], [self.alert("2026-11-03T01:01:00Z", tags=())],
                                verifier="v")
        row = result.rows[0]
        self.assertEqual((row["outcome"], row["alerted"], row["match_status"], row["candidate_event_id"]),
                         ("none", "false", "ambiguous", "A1"))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "v.csv"
            evidence.write_validations(result.rows, path)
            report = vdc.compute({"T1059": ("x", 1.0)}, vdc.load_validations(path), date(2026, 11, 7))
        self.assertEqual((report.vdc, report.ambiguous), (0.0, 1))

    def test_prevention_claim_without_block_event_is_not_verified(self):
        row = evidence.match([self.run_(prevention_claimed=True)], [], verifier="v").rows[0]
        self.assertEqual((row["outcome"], row["prevented"], row["prevention_claimed"], row["verifier"]),
                         ("none", "false", "true", ""))
        self.assertIn("no blocking event", row["notes"])
        block = self.alert("2026-11-03T01:02:00Z", action="blocked")
        row = evidence.match([self.run_(prevention_claimed=True)], [block], verifier="v").rows[0]
        self.assertEqual((row["outcome"], row["prevented"], row["alerted"], row["event_id"]),
                         ("prevented", "true", "false", "A1"))

    def test_invalid_booleans_and_actions_are_errors(self):
        with tempfile.TemporaryDirectory() as d:
            runs = Path(d) / "runs.csv"
            runs.write_text("run_id,technique_id,procedure_id,host,started_at,ended_at,prevention_claimed\n"
                            "R1,T1059,a,h,2026-11-03T01:00:00Z,2026-11-03T01:05:00Z,maybe\n")
            with self.assertRaisesRegex(ValueError, "true/false"):
                evidence.load_runs(runs)
            alerts = Path(d) / "alerts.csv"
            alerts.write_text("event_id,rule_id,timestamp,host,action\nA1,R,2026-11-03T01:00:00Z,h,maybe\n")
            with self.assertRaisesRegex(ValueError, "action"):
                evidence.load_events(alerts)

    def test_runs_outside_roe_are_rejected(self):
        roe = engagement.load_roe(LAB / "roe.json")
        result = evidence.match(
            [self.run_(host="lab-ws09"), self.run_(run_id="R2", started_at=T("2026-12-01T00:00:00Z"),
                                                   ended_at=T("2026-12-01T00:01:00Z"))],
            [], roe=roe)
        self.assertEqual(result.rows, [])
        self.assertEqual([r for r, _ in result.rejected], ["R1", "R2"])
        self.assertEqual(result.status, "rejected")

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
            plan=engagement.load_plan(LAB / "plan.csv"),
        )
        self.assertEqual([r for r, _ in result.rejected], ["R-006"])
        self.assertEqual(result.unmatched_alerts, ["A-9004"])
        self.assertEqual(result.ambiguous, [])
        r004 = next(r for r in result.rows if r["run_id"] == "R-004")
        self.assertEqual((r004["prevented"], r004["alerted"], r004["event_id"]),
                         ("true", "true", "A-9002;A-9005"))
        self.assertEqual({(r["engagement_id"], r["plan_id"]) for r in result.rows},
                         {("LAB-2026-11", "FIN-PLAN")})
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


class MatchEvidenceCliTest(unittest.TestCase):
    """Runs outside the RoE: no official output unless --allow-partial, and the status says so."""

    def _run(self, d, *extra):
        out = Path(d) / "validations.csv"
        argv = ["match-evidence", "--roe", str(LAB / "roe.json"), "--runs", str(LAB / "runs.csv"),
                "--alerts", str(LAB / "alerts.csv"), "--logs", str(LAB / "logs.csv"),
                "--plan", str(LAB / "plan.csv"), "--verifier", "blue-lead", "-o", str(out), *extra]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main(argv)
        status = json.loads((Path(d) / "validations.status.json").read_text(encoding="utf-8"))
        return code, out, status, err.getvalue()

    def test_rejected_runs_block_the_output(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, status, err = self._run(d)
            self.assertEqual(code, 1)
            self.assertFalse(out.exists())
            self.assertEqual((status["status"], status["output"], status["runs_written"]),
                             ("rejected", None, 0))
            self.assertEqual([r["run_id"] for r in status["rejected"]], ["R-006"])
            self.assertIn("was not written", err)

    def test_allow_partial_marks_the_output(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, status, _ = self._run(d, "--allow-partial")
            self.assertEqual(code, 0)
            self.assertTrue(out.exists())
            self.assertEqual((status["status"], status["runs_written"]), ("partial", 5))

    def test_complete_run(self):
        with tempfile.TemporaryDirectory() as d:
            runs = Path(d) / "runs.csv"
            lines = (LAB / "runs.csv").read_text(encoding="utf-8").splitlines()
            runs.write_text("\n".join(l for l in lines if not l.startswith("R-006")) + "\n")
            out = Path(d) / "validations.csv"
            with contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(["match-evidence", "--roe", str(LAB / "roe.json"), "--runs", str(runs),
                                 "--alerts", str(LAB / "alerts.csv"), "--verifier", "v", "-o", str(out)])
            status = json.loads((Path(d) / "validations.status.json").read_text(encoding="utf-8"))
            self.assertEqual((code, status["status"]), (0, "complete"))
