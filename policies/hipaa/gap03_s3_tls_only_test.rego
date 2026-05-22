package compliance.hipaa.s3_tls_only

import rego.v1

# Test: PASS - PHI bucket with TLS policy
test_phi_bucket_with_tls_passes if {
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
                "type": "aws_s3_bucket_policy",
                "change": {
                    "after": {
                        "bucket": "phi-bucket",
                        "policy": "{\"Statement\":[{\"Effect\":\"Deny\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"
                    }
                }
            }
        ]
    }
    
    result := deny with input as test_input
    count(result) == 0
}

# Test: FAIL - PHI bucket without TLS policy
test_phi_bucket_without_tls_fails if {
    test_input := {
        "resource_changes": [{
            "type": "aws_s3_bucket",
            "change": {
                "after": {
                    "bucket": "bad-bucket",
                    "tags": {"DataClass": "phi"}
                }
            }
        }]
    }
    
    result := deny with input as test_input
    count(result) == 1
    some msg in result
    contains(msg, "164.312(e)(1)")
    contains(msg, "bad-bucket")
}