# METADATA
# title: HIPAA 164.308(a)(7) - S3 Versioning for Data Backup
# description: Ensures S3 buckets with PHI have versioning enabled
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   severity: high
#   gap: GAP-04
package compliance.hipaa.s3_versioning

import rego.v1

is_phi_bucket(resource) if {
    resource.type == "aws_s3_bucket"
    resource.change.after.tags.DataClass == "phi"
}

has_versioning(bucket_name) if {
    some resource in input.resource_changes
    resource.type == "aws_s3_bucket_versioning"
    resource.change.after.bucket == bucket_name
    resource.change.after.versioning_configuration[_].status == "Enabled"
}

deny contains msg if {
    some resource in input.resource_changes
    is_phi_bucket(resource)
    bucket_name := resource.change.after.bucket
    not has_versioning(bucket_name)
    
    msg := sprintf(
        "HIPAA 164.308(a)(7) VIOLATION: S3 bucket '%s' contains PHI but does not have versioning enabled. Add aws_s3_bucket_versioning with status='Enabled' for data backup and recovery",
        [bucket_name]
    )
}