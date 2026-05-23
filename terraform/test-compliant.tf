# TEST: This resource is COMPLIANT with all policies
# Non-PHI bucket (policies don't apply)
resource "aws_s3_bucket" "test_compliant" {
  bucket = "test-public-bucket-${random_id.suffix.hex}"

  tags = {
    Name      = "test-compliant"
    DataClass = "public" # NOT PHI - policies don't apply
    Purpose   = "policy-test"
  }
}