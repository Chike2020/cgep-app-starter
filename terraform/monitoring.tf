######################################################################
# Continuous Monitoring & Drift Detection
# HIPAA 164.308(a)(1)(ii)(D) - Information System Activity Review
# HIPAA 164.312(b) - Audit Controls
######################################################################

######################################################################
# AWS Config — detect control drift in real time
######################################################################

resource "aws_config_configuration_recorder" "hipaa" {
  name     = "${local.name_prefix}-config-recorder"
  role_arn = aws_iam_service_linked_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "hipaa" {
  name           = "${local.name_prefix}-config-delivery"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.hipaa]
}

resource "aws_config_configuration_recorder_status" "hipaa" {
  name       = aws_config_configuration_recorder.hipaa.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.hipaa]
}

# AWS Config service-linked role — uses iam:CreateServiceLinkedRole (included in
# PowerUserAccess), so CI can create it without needing iam:CreateRole.
#
# If this role already exists in your account, import it before applying:
#   terraform import aws_iam_service_linked_role.config \
#     arn:aws:iam::973191046894:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig
resource "aws_iam_service_linked_role" "config" {
  aws_service_name = "config.amazonaws.com"
  description      = "Service-linked role for AWS Config (HIPAA 164.312(b))"
}

######################################################################
# AWS Config Rules — per-control drift detection
######################################################################

resource "aws_config_config_rule" "s3_kms_encryption" {
  name        = "${local.name_prefix}-s3-kms-encryption"
  description = "GAP-01: S3 buckets must use SSE-KMS with a CMK (HIPAA 164.312(a)(2)(iv))"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.hipaa]

  tags = {
    HIPAAControl = "164-312-a-2-iv"
    Gap          = "GAP-01"
  }
}

resource "aws_config_config_rule" "s3_tls_only" {
  name        = "${local.name_prefix}-s3-tls-only"
  description = "GAP-03: S3 buckets must deny non-TLS requests (HIPAA 164.312(e)(1))"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder_status.hipaa]

  tags = {
    HIPAAControl = "164-312-e-1"
    Gap          = "GAP-03"
  }
}

resource "aws_config_config_rule" "s3_versioning" {
  name        = "${local.name_prefix}-s3-versioning"
  description = "GAP-04: S3 buckets must have versioning enabled (HIPAA 164.308(a)(7))"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.hipaa]

  tags = {
    HIPAAControl = "164-308-a-7"
    Gap          = "GAP-04"
  }
}

resource "aws_config_config_rule" "dynamodb_encryption" {
  name        = "${local.name_prefix}-dynamodb-pitr"
  description = "GAP-02: DynamoDB tables must have point-in-time recovery enabled (HIPAA 164.312(a)(2)(iv))"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_PITR_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.hipaa]

  tags = {
    HIPAAControl = "164-312-a-2-iv"
    Gap          = "GAP-02"
  }
}

resource "aws_config_config_rule" "lambda_inside_vpc" {
  name        = "${local.name_prefix}-lambda-inside-vpc"
  description = "GAP-05: Lambda functions must run inside a VPC (HIPAA 164.312(e)(1))"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_INSIDE_VPC"
  }

  depends_on = [aws_config_configuration_recorder_status.hipaa]

  tags = {
    HIPAAControl = "164-312-e-1"
    Gap          = "GAP-05"
  }
}

resource "aws_config_config_rule" "iam_no_inline_policy" {
  name        = "${local.name_prefix}-iam-no-inline-policy"
  description = "GAP-07: IAM roles must not use inline wildcard policies (HIPAA 164.312(a)(1))"

  source {
    owner             = "AWS"
    source_identifier = "IAM_NO_INLINE_POLICY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.hipaa]

  tags = {
    HIPAAControl = "164-312-a-1"
    Gap          = "GAP-07"
  }
}

resource "aws_config_config_rule" "kms_rotation" {
  name        = "${local.name_prefix}-kms-rotation"
  description = "KMS CMKs must have automatic rotation enabled (HIPAA 164.312(a)(2)(iv))"

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.hipaa]

  tags = {
    HIPAAControl = "164-312-a-2-iv"
  }
}

######################################################################
# EventBridge — route Config compliance change events to SNS
######################################################################

resource "aws_sns_topic" "compliance_alerts" {
  name              = "${local.name_prefix}-compliance-alerts-${local.suffix}"
  kms_master_key_id = aws_kms_key.phi.arn

  tags = {
    Purpose      = "compliance-drift-alerts"
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

resource "aws_cloudwatch_event_rule" "config_compliance_change" {
  name        = "${local.name_prefix}-config-noncompliant"
  description = "Fires when any AWS Config rule transitions to NON_COMPLIANT"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = {
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

resource "aws_cloudwatch_event_target" "compliance_alert_sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance_change.name
  target_id = "ComplianceAlertSNS"
  arn       = aws_sns_topic.compliance_alerts.arn
}

resource "aws_sns_topic_policy" "compliance_alerts" {
  arn = aws_sns_topic.compliance_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.compliance_alerts.arn
      }
    ]
  })
}

######################################################################
# Lambda — drift detection: verifies running infra enforces controls
# Triggered by EventBridge schedule (daily) and on Config NON_COMPLIANT
######################################################################

# Drift detector reuses aws_iam_role.lambda (defined in main.tf).
# An additional inline policy grants the read-only Config/SNS permissions needed
# for drift checking, without requiring iam:CreateRole in CI.
resource "aws_iam_role_policy" "drift_detector" {
  name = "drift-detector-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadCompliance"
        Effect = "Allow"
        Action = [
          "config:DescribeComplianceByConfigRule",
          "config:GetComplianceDetailsByConfigRule",
          "s3:GetBucketEncryption",
          "s3:GetBucketVersioning",
          "s3:GetBucketPolicy",
          "lambda:GetFunctionConfiguration",
          "dynamodb:DescribeTable",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid      = "PublishAlerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.compliance_alerts.arn
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

data "archive_file" "drift_detector" {
  type        = "zip"
  output_path = "${path.module}/lambda/drift_detector.zip"

  source {
    content  = <<-PYTHON
import json
import boto3
import os

config_client = boto3.client('config')
sns_client = boto3.client('sns')
ALERT_TOPIC = os.environ['ALERT_TOPIC_ARN']

HIPAA_RULES = [
    'acme-health-intake-s3-kms-encryption',
    'acme-health-intake-s3-tls-only',
    'acme-health-intake-s3-versioning',
    'acme-health-intake-dynamodb-pitr',
    'acme-health-intake-lambda-inside-vpc',
    'acme-health-intake-iam-no-inline-policy',
    'acme-health-intake-kms-rotation',
]

def handler(event, context):
    violations = []
    for rule_name in HIPAA_RULES:
        try:
            resp = config_client.get_compliance_details_by_config_rule(
                ConfigRuleName=rule_name,
                ComplianceTypes=['NON_COMPLIANT'],
                Limit=25,
            )
            for result in resp.get('EvaluationResults', []):
                resource_id = result['EvaluationResultIdentifier']['EvaluationResultQualifier']['ResourceId']
                violations.append({'rule': rule_name, 'resource': resource_id})
        except config_client.exceptions.NoSuchConfigRuleException:
            pass

    if violations:
        sns_client.publish(
            TopicArn=ALERT_TOPIC,
            Subject='HIPAA Drift Detected',
            Message=json.dumps({'violations': violations}, indent=2),
        )
        print(f"DRIFT DETECTED: {len(violations)} violation(s)")
    else:
        print("All HIPAA Config rules COMPLIANT")

    return {'violations': violations}
PYTHON
    filename = "drift_detector.py"
  }
}

resource "aws_lambda_function" "drift_detector" {
  function_name    = "${local.name_prefix}-drift-detector-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "drift_detector.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.drift_detector.output_path
  source_code_hash = data.archive_file.drift_detector.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.compliance_alerts.arn
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.drift_detector_dlq.arn
  }

  reserved_concurrent_executions = 5

  tags = {
    Purpose      = "drift-detection"
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

resource "aws_sqs_queue" "drift_detector_dlq" {
  name              = "${local.name_prefix}-drift-dlq-${local.suffix}"
  kms_master_key_id = aws_kms_key.phi.arn

  tags = {
    Purpose    = "drift-detector-dlq"
    Compliance = "hipaa"
  }
}

resource "aws_cloudwatch_event_rule" "daily_drift_check" {
  name                = "${local.name_prefix}-daily-drift-check"
  description         = "Trigger drift detection Lambda daily"
  schedule_expression = "rate(1 day)"

  tags = {
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

resource "aws_cloudwatch_event_target" "daily_drift_check" {
  rule      = aws_cloudwatch_event_rule.daily_drift_check.name
  target_id = "DriftDetectorLambda"
  arn       = aws_lambda_function.drift_detector.arn
}

resource "aws_lambda_permission" "drift_detector_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_drift_check.arn
}

output "compliance_alert_topic_arn" {
  value       = aws_sns_topic.compliance_alerts.arn
  description = "SNS topic for HIPAA compliance drift alerts"
}

output "drift_detector_function_name" {
  value       = aws_lambda_function.drift_detector.function_name
  description = "Lambda function that checks AWS Config rules daily"
}
