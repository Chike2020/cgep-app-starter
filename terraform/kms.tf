######################################################################
# KMS - Customer Managed Key for PHI Encryption
# Addresses GAP-01 and GAP-02
# HIPAA 164.312(a)(2)(iv) - Encryption and Decryption
######################################################################

resource "aws_kms_key" "phi" {
  description             = "Customer-managed key for PHI encryption (HIPAA 164.312(a)(2)(iv))"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name         = "${local.name_prefix}-phi-cmk"
    Purpose      = "phi-encryption"
    Compliance   = "hipaa"
    HIPAAControl = "164-312-a-2-iv"
  }
}
# KMS key policy allowing CloudTrail to use the key
resource "aws_kms_key_policy" "phi" {
  key_id = aws_kms_key.phi.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::973191046894:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:973191046894:trail/*"
          }
        }
      },
      {
        Sid    = "Allow CloudTrail to describe key"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      }
    ]
  })
}
resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi"
  target_key_id = aws_kms_key.phi.key_id
}

# Grant Lambda permission to use the key for encryption/decryption
resource "aws_kms_grant" "lambda_phi" {
  name              = "${local.name_prefix}-lambda-phi-grant"
  key_id            = aws_kms_key.phi.key_id
  grantee_principal = aws_iam_role.lambda.arn

  operations = [
    "Encrypt",
    "Decrypt",
    "GenerateDataKey",
    "DescribeKey"
  ]
}

output "kms_key_id" {
  value       = aws_kms_key.phi.id
  description = "KMS CMK for PHI encryption"
}

output "kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "KMS CMK ARN"
}