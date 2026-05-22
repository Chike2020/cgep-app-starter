package compliance.hipaa.s3_kms_encryption

import rego.v1

# Test: PASS - PHI bucket with KMS encryption
test_phi_bucket_with_kms_passes if {
    test_input := {
        "resource_changes": [
            {
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "phi-bucket",
                        "tags": {"DataClass": "phi"}
                    }
                }
            },
            {
                "type": "aws_s3_bucket_server_side_encryption_configuration",
                "change": {
                    "after": {
                        "bucket": "phi-bucket",
                        "rule": [{
                            "apply_server_side_encryption_by_default": {
                                "sse_algorithm": "aws:kms",
                                "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc"
                            }
                        }]
                    }
                }
            }
        ]
    }
    
    result := deny with input as test_input
    count(result) == 0
}

# Test: FAIL - PHI bucket without KMS encryption
test_phi_bucket_without_kms_fails if {
    test_input := {
        "resource_changes": [
            {
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "phi-bucket-bad",
                        "tags": {"DataClass": "phi"}
                    }
                }
            }
        ]
    }
    
    result := deny with input as test_input
    count(result) == 1
    some msg in result
    contains(msg, "164.312(a)(2)(iv)")
    contains(msg, "phi-bucket-bad")
}

# Test: PASS - Non-PHI bucket (policy doesn't apply)
test_non_phi_bucket_ignored if {
    test_input := {
        "resource_changes": [
            {
                "type": "aws_s3_bucket",
                "change": {
                    "after": {
                        "bucket": "regular-bucket",
                        "tags": {"DataClass": "public"}
                    }
                }
            }
        ]
    }
    
    result := deny with input as test_input
    count(result) == 0
}