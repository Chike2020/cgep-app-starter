"""
Drift Detector — HIPAA Compliance Monitor
HIPAA 164.308(a)(1)(ii)(D) - Information System Activity Review
HIPAA 164.312(b) - Audit Controls

Queries every mapped AWS Config rule for NON_COMPLIANT resources.
If any violations are found, publishes a structured alert to SNS.
Triggered daily via EventBridge and on every Config NON_COMPLIANT state change.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

config_client = boto3.client("config")
sns_client = boto3.client("sns")

ALERT_TOPIC = os.environ["ALERT_TOPIC_ARN"]

# Config rule names map 1:1 to the aws_config_config_rule resources
# in monitoring.tf.  The prefix comes from local.name_prefix in Terraform.
PREFIX = os.environ.get("RULE_PREFIX", "acme-health-intake")

HIPAA_RULES = {
    f"{PREFIX}-s3-kms-encryption": "GAP-01 / HIPAA 164.312(a)(2)(iv)",
    f"{PREFIX}-s3-tls-only": "GAP-03 / HIPAA 164.312(e)(1)",
    f"{PREFIX}-s3-versioning": "GAP-04 / HIPAA 164.308(a)(7)",
    f"{PREFIX}-dynamodb-pitr": "GAP-02 / HIPAA 164.312(a)(2)(iv)",
    f"{PREFIX}-lambda-inside-vpc": "GAP-05 / HIPAA 164.312(e)(1)",
    f"{PREFIX}-iam-no-inline-policy": "GAP-07 / HIPAA 164.312(a)(1)",
    f"{PREFIX}-kms-rotation": "KMS / HIPAA 164.312(a)(2)(iv)",
}


def _get_noncompliant_resources(rule_name: str) -> list[dict]:
    """Return list of NON_COMPLIANT resource identifiers for a Config rule."""
    violations = []
    paginator = config_client.get_paginator("get_compliance_details_by_config_rule")
    pages = paginator.paginate(
        ConfigRuleName=rule_name,
        ComplianceTypes=["NON_COMPLIANT"],
    )
    for page in pages:
        for result in page.get("EvaluationResults", []):
            qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
            violations.append(
                {
                    "rule": rule_name,
                    "resource_type": qualifier.get("ResourceType", "Unknown"),
                    "resource_id": qualifier.get("ResourceId", "Unknown"),
                }
            )
    return violations


def handler(event, context):
    """
    Entry point for EventBridge daily schedule and Config state-change events.

    Returns a dict with:
      - violations: list of {rule, resource_type, resource_id}
      - published: bool — whether an SNS alert was sent
    """
    violations = []

    for rule_name, control_ref in HIPAA_RULES.items():
        try:
            found = _get_noncompliant_resources(rule_name)
            if found:
                logger.warning(
                    "DRIFT: rule=%s control=%s violations=%d",
                    rule_name,
                    control_ref,
                    len(found),
                )
                violations.extend(found)
        except config_client.exceptions.NoSuchConfigRuleException:
            logger.info("Config rule %s not found — skipping", rule_name)
        except ClientError as exc:
            logger.error("Config API error for rule %s: %s", rule_name, exc)

    published = False
    if violations:
        message = {
            "summary": f"HIPAA Drift Detected: {len(violations)} violation(s)",
            "violations": violations,
        }
        sns_client.publish(
            TopicArn=ALERT_TOPIC,
            Subject="HIPAA Drift Detected",
            Message=json.dumps(message, indent=2),
        )
        published = True
        logger.error("DRIFT DETECTED: %d violation(s) — SNS alert sent", len(violations))
    else:
        logger.info("All HIPAA Config rules COMPLIANT")

    return {"violations": violations, "published": published}
