import json
import os
import tempfile
import unittest

from memwall.models import Severity
from memwall.policy import Policy


class PolicyTests(unittest.TestCase):
    def test_builtin_thresholds(self):
        policy = Policy(default_block_at=Severity.HIGH)
        self.assertEqual(policy.threshold_for("web"), Severity.MEDIUM)
        self.assertEqual(policy.threshold_for("email"), Severity.MEDIUM)
        self.assertEqual(policy.threshold_for("user"), Severity.CRITICAL)
        self.assertEqual(policy.threshold_for("agent"), Severity.HIGH)
        self.assertEqual(policy.threshold_for("unknown"), Severity.HIGH)
        self.assertEqual(policy.threshold_for(None), Severity.HIGH)
        self.assertEqual(policy.threshold_for("WEB"), Severity.MEDIUM)

    def test_from_file_merges_over_builtins(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"default_block_at": "medium",
                           "origins": {"web": "low", "voicemail": "low"}}, fh)
            policy = Policy.from_file(path)
        self.assertEqual(policy.default_block_at, Severity.MEDIUM)
        self.assertEqual(policy.threshold_for("web"), Severity.LOW)          # overridden
        self.assertEqual(policy.threshold_for("voicemail"), Severity.LOW)    # custom origin
        self.assertEqual(policy.threshold_for("email"), Severity.MEDIUM)     # builtin kept
        self.assertEqual(policy.threshold_for("something-else"), Severity.MEDIUM)  # default


if __name__ == "__main__":
    unittest.main()
