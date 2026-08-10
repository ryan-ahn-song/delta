import unittest

from stack_delta.models import Declaration, DocumentAnalysis, ObservedEvent
from stack_delta.policy import PolicyEngine
from stack_delta.scoring import score_events


class PolicyScoringTests(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyEngine()

    def test_sensitive_document_claim_is_never_auto_approved(self):
        analysis = DocumentAnalysis(
            categories={"pure_javascript": 0.9},
            declarations=[Declaration("file_read", "/home/sandbox/.ssh/id_rsa", "claimed need", "README says so", 0.99)],
        )
        expected = self.policy.expectations(analysis)
        self.assertFalse(any(item.target.endswith("id_rsa") for item in expected))

    def test_native_expected_events_score_zero(self):
        analysis = DocumentAnalysis(categories={"native_addon": 0.95})
        expected = self.policy.expectations(analysis)
        events = [
            ObservedEvent("process_spawn", "/usr/bin/node-gyp"),
            ObservedEvent("file_write", "/work/package/build/addon.node"),
        ]
        result = score_events(events, expected, self.policy)
        self.assertEqual(result.final_score, 0)
        self.assertEqual(result.decision, "NO MISMATCH OBSERVED")

    def test_attempted_network_is_half_weight(self):
        result = score_events(
            [ObservedEvent("network_connect", "198.51.100.10:443", "attempted")], [], self.policy
        )
        self.assertEqual(result.base_score, 1.5)

    def test_credential_and_network_chain_bonus(self):
        events = [
            ObservedEvent("file_read", "/home/sandbox/.ssh/id_rsa"),
            ObservedEvent("network_connect", "198.51.100.10:443", "attempted"),
        ]
        result = score_events(events, [], self.policy)
        self.assertEqual(result.base_score, 6.5)
        self.assertEqual(result.chain_bonus, 3)
        self.assertEqual(result.decision, "REVIEW REQUIRED")

    def test_one_critical_success_requires_review(self):
        result = score_events([ObservedEvent("file_read", "/home/sandbox/.ssh/id_rsa")], [], self.policy)
        self.assertEqual(result.final_score, 5)
        self.assertEqual(result.decision, "REVIEW REQUIRED")


if __name__ == "__main__":
    unittest.main()

