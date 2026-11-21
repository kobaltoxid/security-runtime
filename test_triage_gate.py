import types
import unittest

import triage_gate


def review(reachability="conditional", components=("pkg@1",)):
    return types.SimpleNamespace(finding={
        "exploitability": {"reachability": reachability},
        "affected_component_ids": list(components),
    })


def proposal(verdict):
    return {"action": "finish", "verdict": verdict, "evidence_refs": ["checks"],
            "reason": "model prose is not trusted"}


def checks(*values, evidence=True):
    return {"checks": {"kind": "checks", "results": [
        {"component_id": component, "proposed_reachability": value,
         "evidence": ["observed"] if evidence else []}
        for component, value in values
    ]}}


class AcceptanceGateTest(unittest.TestCase):
    def test_support_is_accepted_with_runtime_reason(self):
        result = triage_gate.assess(proposal("evidence_supports_report"), review(),
                                    checks(("pkg@1", "conditional")))
        self.assertTrue(result["accepted"])
        self.assertFalse(result["actionable"])
        self.assertIn("Verified checks", result["proposal"]["reason"])
        self.assertNotIn("model prose", result["proposal"]["reason"])

    def test_conflict_is_accepted_when_all_components_disagree(self):
        result = triage_gate.assess(proposal("evidence_conflicts_with_report"), review(),
                                    checks(("pkg@1", "reachable")))
        self.assertTrue(result["accepted"])

    def test_missing_or_mixed_facts_are_not_actionable(self):
        missing = triage_gate.assess(proposal("evidence_supports_report"), review(),
                                     checks(("pkg@1", "conditional"), evidence=False))
        mixed = triage_gate.assess(proposal("evidence_supports_report"), review(),
                                   {"checks": {"results": [
                                       {"component_id": "pkg@1", "proposed_reachability": "conditional", "evidence": ["a"]},
                                       {"component_id": "pkg@1", "proposed_reachability": "reachable", "evidence": ["b"]},
                                   ]}})
        self.assertFalse(missing["actionable"])
        self.assertFalse(mixed["actionable"])

    def test_mismatched_verdict_is_actionable_for_one_correction(self):
        result = triage_gate.assess(proposal("evidence_conflicts_with_report"), review(),
                                    checks(("pkg@1", "conditional")))
        self.assertFalse(result["accepted"])
        self.assertTrue(result["actionable"])


if __name__ == "__main__":
    unittest.main()
