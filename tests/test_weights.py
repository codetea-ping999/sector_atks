import json
import tempfile
import unittest
from pathlib import Path

from sector_atks import sectors, weights
from sector_atks.attack import load_attack


def _ref(eid):
    return [{"source_name": "mitre-attack", "external_id": eid}]


def _bundle():
    objs = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "99.0",
         "modified": "2026-01-01T00:00:00Z"},
        {"type": "attack-pattern", "id": "attack-pattern--a", "name": "Phishing",
         "external_references": _ref("T1566")},
        {"type": "attack-pattern", "id": "attack-pattern--b", "name": "Valid Accounts",
         "external_references": _ref("T1078")},
        {"type": "attack-pattern", "id": "attack-pattern--b1", "name": "Cloud Accounts",
         "external_references": _ref("T1078.004"), "x_mitre_is_subtechnique": True},
        {"type": "attack-pattern", "id": "attack-pattern--r", "name": "Acquire Infrastructure",
         "external_references": _ref("T1583"),
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "resource-development"}]},
        {"type": "attack-pattern", "id": "attack-pattern--old", "name": "Old", "revoked": True,
         "external_references": _ref("T9999")},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Bank Group",
         "external_references": _ref("G0001"),
         "description": "Bank Group has targeted banks and financial institutions.(Citation: X)"},
        {"type": "intrusion-set", "id": "intrusion-set--2", "name": "State Group",
         "external_references": _ref("G0002"),
         "description": "State Group is attributed to a Ministry of State Security. "
                        "It has targeted telecommunications companies."},
        {"type": "intrusion-set", "id": "intrusion-set--3", "name": "Other Group",
         "external_references": _ref("G0003"),
         "description": "Other Group is financially motivated and has targeted hotels."},
        {"type": "campaign", "id": "campaign--1", "name": "C0001", "external_references": _ref("C0001")},
        {"type": "x-mitre-data-component", "id": "x-mitre-data-component--1", "name": "Logon Session"},
        {"type": "x-mitre-analytic", "id": "x-mitre-analytic--1", "x_mitre_log_source_references": [
            {"x_mitre_data_component_ref": "x-mitre-data-component--1", "name": "WinEventLog:Security",
             "channel": "EventCode=4624"}]},
        {"type": "x-mitre-detection-strategy", "id": "x-mitre-detection-strategy--1",
         "x_mitre_analytic_refs": ["x-mitre-analytic--1"]},
    ]
    rels = [
        ("intrusion-set--1", "uses", "attack-pattern--a"),
        ("intrusion-set--1", "uses", "attack-pattern--b1"),
        ("intrusion-set--2", "uses", "attack-pattern--a"),
        ("intrusion-set--2", "uses", "attack-pattern--r"),
        ("intrusion-set--3", "uses", "attack-pattern--old"),
        ("campaign--1", "attributed-to", "intrusion-set--3"),
        ("campaign--1", "uses", "attack-pattern--b"),
        ("x-mitre-detection-strategy--1", "detects", "attack-pattern--b"),
    ]
    for i, (s, k, t) in enumerate(rels):
        objs.append({"type": "relationship", "id": f"relationship--{i}", "source_ref": s,
                     "relationship_type": k, "target_ref": t})
    return {"type": "bundle", "objects": objs}


class WeightsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name) / "bundle.json"
        path.write_text(json.dumps(_bundle()))
        self.attack = load_attack(path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_load(self):
        self.assertEqual(self.attack.version, "99.0")
        self.assertNotIn("T9999", self.attack.techniques)
        self.assertEqual(self.attack.groups["G0001"].techniques, {"T1566", "T1078.004"})
        self.assertEqual(self.attack.groups["G0003"].techniques, {"T1078"})  # via campaign
        self.assertEqual(self.attack.log_sources["T1078"], ["WinEventLog:Security"])

    def test_sector_tags_skip_attribution_and_motive(self):
        tags = {(t.group_id, t.sector) for t in sectors.tag_groups(self.attack.groups)}
        self.assertIn(("G0001", "finance"), tags)
        self.assertIn(("G0002", "telecommunications"), tags)
        self.assertNotIn(("G0002", "government"), tags)  # "attributed to a Ministry"
        self.assertNotIn(("G0003", "finance"), tags)  # "financially motivated"
        self.assertIn(("G0003", "retail_hospitality"), tags)

    def test_overrides(self):
        tags = sectors.tag_groups(
            self.attack.groups, [("G0002", "government", "add"), ("G0001", "finance", "remove")]
        )
        pairs = {(t.group_id, t.sector, t.evidence) for t in tags}
        self.assertIn(("G0002", "government", "manual"), pairs)
        self.assertFalse(any(g == "G0001" and s == "finance" for g, s, _ in pairs))

    def test_sector_weights(self):
        rows = weights.sector_weights(self.attack, {"G0001", "G0002"}, top_n=1)
        self.assertEqual(rows[0].technique_id, "T1566")
        self.assertEqual(rows[0].groups_using, 2)
        self.assertAlmostEqual(rows[0].weight, 1.0)
        self.assertIsNone(rows[1].weight)
        # T1078 is used by 1 of 2 sector groups and 2 of 3 groups overall
        t1078 = next(r for r in rows if r.technique_id == "T1078")
        self.assertAlmostEqual(t1078.share, 0.5)
        self.assertAlmostEqual(t1078.lift, 0.5 / (2 / 3))

    def test_pre_compromise_excluded_by_default(self):
        ids = {r.technique_id for r in weights.sector_weights(self.attack, {"G0002"})}
        self.assertNotIn("T1583", ids)
        ids = {r.technique_id for r in weights.sector_weights(self.attack, {"G0002"}, exclude_tactics=frozenset())}
        self.assertIn("T1583", ids)

    def test_prevalence_blend(self):
        rows = weights.sector_weights(
            self.attack, {"G0001", "G0002"}, top_n=2, prevalence={"T1078": 1.0}, beta=1.0
        )
        self.assertEqual(rows[0].technique_id, "T1078")
        with self.assertRaises(ValueError):
            weights.sector_weights(self.attack, {"G0001"}, beta=2.0)


if __name__ == "__main__":
    unittest.main()
