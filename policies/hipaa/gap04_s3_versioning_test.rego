package compliance.hipaa.s3_versioning

import rego.v1

test_phi_bucket_with_versioning_passes if {
    test_input := {
        "resource_changes": [
            {
                "type": "aws_s3_bucket",
                "change": {"after": {"bucket": "phi-bucket", "tags": {"DataClass": "phi"}}}
            },
            {
                "type": "aws_s3_bucket_versioning",
                "change": {"after": {"bucket": "phi-bucket", "versioning_configuration": [{"status": "Enabled"}]}}
            }
        ]
    }
    
    result := deny with input as test_input
    count(result) == 0
}

test_phi_bucket_without_versioning_fails if {
    test_input := {
        "resource_changes": [{
            "type": "aws_s3_bucket",
            "change": {"after": {"bucket": "bad-bucket", "tags": {"DataClass": "phi"}}}
        }]
    }
    
    result := deny with input as test_input
    count(result) == 1
}