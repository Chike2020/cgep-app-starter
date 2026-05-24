######################################################################
# Drift Detector — Lambda + SNS + EventBridge
# HIPAA 164.308(a)(1)(ii)(D) - Information System Activity Review
# HIPAA 164.312(b) - Audit Controls
#
# Queries every mapped AWS Config rule for NON_COMPLIANT resources.
# If violations are found, publishes a structured alert to SNS.
# Triggered daily via EventBridge and on every Config NON_COMPLIANT
# state change.
######################################################################

######################################################################
# SNS — compliance alert fanout
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
# IAM — drift-detector Lambda execution role
######################################################################

resource "aws_iam_role" "drift_detector" {
  name = "${local.name_prefix}-drift-detector-${local.suffix}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

resource "aws_iam_role_policy" "drift_detector" {
  name = "drift-detector-policy"
  role = aws_iam_role.drift_detector.id

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
        # Lambda needs sqs:SendMessage to write failed invocations to the DLQ
        Sid      = "DLQ"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.drift_detector_dlq.arn
      },
      {
        # DLQ is KMS-encrypted — Lambda needs these to encrypt/decrypt DLQ messages
        Sid      = "KMSForDLQ"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.phi.arn
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

resource "aws_iam_role_policy_attachment" "drift_detector_basic" {
  role       = aws_iam_role.drift_detector.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

######################################################################
# Lambda — queries Config rules, publishes violations to SNS
# Source: terraform/lambda/drift_detector.py (extracted for testability)
######################################################################

data "archive_file" "drift_detector" {
  type        = "zip"
  source_file = "${path.module}/lambda/drift_detector.py"
  output_path = "${path.module}/lambda/drift_detector.zip"
}

resource "aws_lambda_function" "drift_detector" {
  function_name    = "${local.name_prefix}-drift-detector-${local.suffix}"
  role             = aws_iam_role.drift_detector.arn
  handler          = "drift_detector.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.drift_detector.output_path
  source_code_hash = data.archive_file.drift_detector.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.compliance_alerts.arn
      RULE_PREFIX     = local.name_prefix
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

# CloudWatch log group with explicit retention (CKV_AWS_92)
resource "aws_cloudwatch_log_group" "drift_detector" {
  name              = "/aws/lambda/${aws_lambda_function.drift_detector.function_name}"
  retention_in_days = 90

  tags = {
    Compliance   = "hipaa"
    HIPAAControl = "164-312-b"
  }
}

######################################################################
# SQS DLQ — captures failed drift-detector invocations (GAP-06)
######################################################################

resource "aws_sqs_queue" "drift_detector_dlq" {
  name              = "${local.name_prefix}-drift-dlq-${local.suffix}"
  kms_master_key_id = aws_kms_key.phi.arn

  tags = {
    Purpose    = "drift-detector-dlq"
    Compliance = "hipaa"
  }
}

######################################################################
# EventBridge — daily schedule + real-time Config change routing
######################################################################

resource "aws_cloudwatch_event_rule" "daily_drift_check" {
  name                = "${local.name_prefix}-daily-drift-check"
  description         = "Trigger drift detection Lambda daily at 02:00 UTC"
  schedule_expression = "cron(0 2 * * ? *)"

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

######################################################################
# Outputs
######################################################################

output "compliance_alert_topic_arn" {
  value       = aws_sns_topic.compliance_alerts.arn
  description = "SNS topic for HIPAA compliance drift alerts"
}

output "drift_detector_function_name" {
  value       = aws_lambda_function.drift_detector.function_name
  description = "Lambda function that checks AWS Config rules daily"
}
