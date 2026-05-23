# TEST: This resource VIOLATES GAP-01 policy
# S3 bucket with PHI but no KMS encryption
resource "aws_s3_bucket" "test_violation" {
  bucket = "test-phi-bucket-no-kms-${random_id.suffix.hex}"

  tags = {
    Name      = "test-violation"
    DataClass = "phi"  # PHI tag WITHOUT KMS encryption
    Purpose   = "policy-test"
  }
}