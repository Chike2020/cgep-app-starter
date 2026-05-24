"""
Unit tests for the drift_detector Lambda handler.
Runs without AWS credentials — all AWS API calls are mocked with unittest.mock.

Coverage:
  - No violations → SNS not called, published=False
  - Violations found → SNS published with correctly structured message
  - Missing Config rule (NoSuchConfigRuleException) → skipped, processing continues
  - Config API error (ClientError) → logged and skipped, processing continues
  - handler() always returns dict with 'violations' (list) and 'published' (bool)
  - Each violation dict contains 'rule', 'resource_type', and 'resource_id'
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Environment setup — MUST happen before the module is imported because
# drift_detector reads ALERT_TOPIC_ARN at module scope.
# ---------------------------------------------------------------------------
os.environ.setdefault("ALERT_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:test-alerts")
os.environ.setdefault("RULE_PREFIX", "test")

# Add terraform/lambda/ to the module search path so we can import drift_detector
# without installing it as a package.
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "terraform", "lambda"),
)

import drift_detector  # noqa: E402 — must follow env/sys.path setup


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh_exception_class(name: str = "NoSuchConfigRuleException"):
    """Return a new exception class that simulates a botocore client exception."""
    return type(name, (Exception,), {})


def _make_config_client(pages=None):
    """
    Return a mock boto3 Config client.

    pages – list of page dicts the paginator will yield on each paginate() call.
            Pass None (default) when you intend to override paginate.side_effect
            yourself in the test body.
    """
    NoSuchRule = _fresh_exception_class("NoSuchConfigRuleException")

    client = MagicMock()
    client.exceptions.NoSuchConfigRuleException = NoSuchRule

    paginator = MagicMock()
    if pages is not None:
        # Return a fresh iterator on *every* paginate() call so that each of
        # the 7 HIPAA_RULES gets its own page sequence.
        paginator.paginate.side_effect = lambda **_kwargs: iter(pages)

    client.get_paginator.return_value = paginator
    return client


def _one_violation_page(resource_type="AWS::S3::Bucket", resource_id="bad-bucket"):
    """Return a single Config page containing one NON_COMPLIANT evaluation result."""
    return {
        "EvaluationResults": [
            {
                "EvaluationResultIdentifier": {
                    "EvaluationResultQualifier": {
                        "ResourceType": resource_type,
                        "ResourceId": resource_id,
                    }
                }
            }
        ]
    }


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------


class TestDriftDetectorHandler(unittest.TestCase):

    # ------------------------------------------------------------------
    # Happy path: all rules compliant
    # ------------------------------------------------------------------

    def test_no_violations_no_sns_published(self):
        """All Config rules compliant → SNS must NOT be called, published=False."""
        mock_config = _make_config_client(pages=[{"EvaluationResults": []}])
        mock_sns = MagicMock()

        with patch.object(drift_detector, "config_client", mock_config), \
                patch.object(drift_detector, "sns_client", mock_sns):
            result = drift_detector.handler({}, None)

        mock_sns.publish.assert_not_called()
        self.assertEqual(result["violations"], [])
        self.assertFalse(result["published"])

    # ------------------------------------------------------------------
    # Happy path: violations detected
    # ------------------------------------------------------------------

    def test_violations_found_publishes_sns_with_correct_message(self):
        """NON_COMPLIANT resources found → SNS.publish called with structured body."""
        mock_config = _make_config_client(pages=[_one_violation_page()])
        mock_sns = MagicMock()

        with patch.object(drift_detector, "config_client", mock_config), \
                patch.object(drift_detector, "sns_client", mock_sns):
            result = drift_detector.handler({}, None)

        self.assertTrue(result["published"])
        self.assertGreater(len(result["violations"]), 0)

        mock_sns.publish.assert_called_once()
        kwargs = mock_sns.publish.call_args.kwargs
        self.assertEqual(kwargs["TopicArn"], drift_detector.ALERT_TOPIC)
        self.assertEqual(kwargs["Subject"], "HIPAA Drift Detected")

        body = json.loads(kwargs["Message"])
        self.assertIn("summary", body)
        self.assertIn("violations", body)
        # Summary string must mention the word "violation"
        self.assertIn("violation", body["summary"].lower())

    # ------------------------------------------------------------------
    # Error handling: Config rule not deployed yet
    # ------------------------------------------------------------------

    def test_missing_config_rule_is_skipped(self):
        """NoSuchConfigRuleException must be silently skipped; other rules continue."""
        mock_config = _make_config_client()
        # Make every paginate() call raise NoSuchConfigRuleException
        mock_config.get_paginator.return_value.paginate.side_effect = (
            mock_config.exceptions.NoSuchConfigRuleException("rule-not-deployed")
        )
        mock_sns = MagicMock()

        with patch.object(drift_detector, "config_client", mock_config), \
                patch.object(drift_detector, "sns_client", mock_sns):
            result = drift_detector.handler({}, None)

        self.assertEqual(result["violations"], [])
        self.assertFalse(result["published"])
        mock_sns.publish.assert_not_called()

    # ------------------------------------------------------------------
    # Error handling: Config API permission / throttle error
    # ------------------------------------------------------------------

    def test_client_error_is_logged_and_skipped(self):
        """ClientError from Config API must be caught; processing continues for all rules."""
        from botocore.exceptions import ClientError

        mock_config = _make_config_client()
        mock_config.get_paginator.return_value.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access Denied"}},
            "GetComplianceDetailsByConfigRule",
        )
        mock_sns = MagicMock()

        with patch.object(drift_detector, "config_client", mock_config), \
                patch.object(drift_detector, "sns_client", mock_sns):
            result = drift_detector.handler({}, None)

        self.assertEqual(result["violations"], [])
        self.assertFalse(result["published"])
        mock_sns.publish.assert_not_called()

    # ------------------------------------------------------------------
    # Return-value contract
    # ------------------------------------------------------------------

    def test_returns_structured_result(self):
        """handler() must always return a dict with 'violations' (list) and 'published' (bool)."""
        mock_config = _make_config_client(pages=[{"EvaluationResults": []}])

        with patch.object(drift_detector, "config_client", mock_config), \
                patch.object(drift_detector, "sns_client", MagicMock()):
            result = drift_detector.handler({}, None)

        self.assertIn("violations", result)
        self.assertIn("published", result)
        self.assertIsInstance(result["violations"], list)
        self.assertIsInstance(result["published"], bool)

    # ------------------------------------------------------------------
    # Violation dict schema
    # ------------------------------------------------------------------

    def test_violation_has_required_fields(self):
        """Every violation dict must contain 'rule', 'resource_type', and 'resource_id'."""
        mock_config = _make_config_client(
            pages=[_one_violation_page("AWS::DynamoDB::Table", "table-without-cmk")]
        )

        with patch.object(drift_detector, "config_client", mock_config), \
                patch.object(drift_detector, "sns_client", MagicMock()):
            result = drift_detector.handler({}, None)

        self.assertGreater(len(result["violations"]), 0)
        for violation in result["violations"]:
            self.assertIn("rule", violation, "violation missing 'rule' key")
            self.assertIn("resource_type", violation, "violation missing 'resource_type' key")
            self.assertIn("resource_id", violation, "violation missing 'resource_id' key")

    # ------------------------------------------------------------------
    # Rule prefix env-var wiring
    # ------------------------------------------------------------------

    def test_hipaa_rules_use_rule_prefix(self):
        """HIPAA_RULES keys must start with the RULE_PREFIX env var."""
        prefix = os.environ.get("RULE_PREFIX", "acme-health-intake")
        for rule_name in drift_detector.HIPAA_RULES:
            self.assertTrue(
                rule_name.startswith(prefix),
                f"Rule '{rule_name}' does not start with prefix '{prefix}'",
            )


if __name__ == "__main__":
    unittest.main()
