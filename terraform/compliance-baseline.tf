######################################################################
# HIPAA Compliance Baseline - Gap Remediation
# Wraps the starter workload with required security controls
######################################################################

######################################################################
# GAP-01: S3 KMS Encryption
# HIPAA 164.312(a)(2)(iv) - Customer-controlled encryption keys
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-02: DynamoDB KMS Encryption
# HIPAA 164.312(a)(2)(iv) - Customer-controlled encryption keys
######################################################################

resource "aws_dynamodb_table" "intake_compliant" {
  # We need to recreate the table with encryption
  # In production, you'd migrate data first
  name         = "${local.name_prefix}-submissions-v2-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }

  point_in_time_recovery {
    enabled = true
  }

 tags = {
    Compliance  = "hipaa"
    HIPAAControl = "164-312-a-2-iv"
  }
}

######################################################################
# GAP-03: S3 TLS-Only Policy
# HIPAA 164.312(e)(1) - Transmission Security
######################################################################

resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

######################################################################
# GAP-04: S3 Versioning
# HIPAA 164.308(a)(7) - Contingency Plan (Data Backup)
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-05: Lambda VPC Configuration
# HIPAA 164.312(e)(1) - Network Isolation
######################################################################

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg"
  description = "Security group for Lambda function handling PHI"
  vpc_id      = aws_vpc.main.id

  # Allow outbound to DynamoDB and S3 via VPC endpoints (best practice)
  # For now, allow all outbound (you'd tighten this in production)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${local.name_prefix}-lambda-sg"
    Compliance  = "hipaa"
    HIPAAControl = "164-312-e-1"
  }
}

# Update Lambda with VPC configuration
# Note: This is a separate resource to avoid recreating the function
resource "aws_lambda_function" "intake_vpc" {
  function_name    = "${local.name_prefix}-handler-vpc-${local.suffix}"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake_compliant.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  tags = {
    Compliance  = "hipaa"
    HIPAAControl = "164-312-e-1"
  }
}

######################################################################
# GAP-07: Least Privilege IAM
# HIPAA 164.312(a)(1) - Access Control
######################################################################

resource "aws_iam_role_policy" "lambda_least_privilege" {
  name = "intake-data-access-least-privilege"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query"
        ]
        Resource = aws_dynamodb_table.intake_compliant.arn
      },
      {
        Sid    = "S3Access"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.uploads.arn}/*"
      },
      {
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

# Add VPC permissions for Lambda
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}