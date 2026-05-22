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
    Name        = "${local.name_prefix}-phi-cmk"
    Purpose     = "phi-encryption"
    Compliance  = "hipaa"
    HIPAAControl = "164-312-a-2-iv"
  }
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