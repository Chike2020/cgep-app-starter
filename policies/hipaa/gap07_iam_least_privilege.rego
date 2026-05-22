# METADATA
# title: HIPAA 164.312(a)(1) - IAM Least Privilege
# description: Prevents wildcard permissions on PHI resources
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#   severity: critical
#   gap: GAP-07
package compliance.hipaa.iam_least_privilege

import rego.v1

is_iam_policy(resource) if {
    resource.type == "aws_iam_role_policy"
}

has_wildcard_actions(resource) if {
    policy := json.unmarshal(resource.change.after.policy)
    some statement in policy.Statement
    some action in statement.Action
    contains(action, "*")
}

deny contains msg if {
    some resource in input.resource_changes
    is_iam_policy(resource)
    has_wildcard_actions(resource)
    policy_name := resource.change.after.name
    
    msg := sprintf(
        "HIPAA 164.312(a)(1) VIOLATION: IAM policy '%s' contains wildcard actions (e.g., s3:*, dynamodb:*). Specify exact actions needed (e.g., s3:GetObject, dynamodb:PutItem) for least privilege access control",
        [policy_name]
    )
}