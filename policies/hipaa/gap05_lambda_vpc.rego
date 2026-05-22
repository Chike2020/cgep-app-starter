# METADATA
# title: HIPAA 164.312(e)(1) - Lambda Network Isolation
# description: Ensures Lambda functions handling PHI run inside VPC
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   gap: GAP-05
package compliance.hipaa.lambda_vpc

import rego.v1

is_phi_lambda(resource) if {
    resource.type == "aws_lambda_function"
    resource.change.after.tags.DataClass == "phi"
}

has_vpc_config(resource) if {
    resource.change.after.vpc_config != null
    count(resource.change.after.vpc_config) > 0
    count(resource.change.after.vpc_config[_].subnet_ids) > 0
}

deny contains msg if {
    some resource in input.resource_changes
    is_phi_lambda(resource)
    not has_vpc_config(resource)
    function_name := resource.change.after.function_name
    
    msg := sprintf(
        "HIPAA 164.312(e)(1) VIOLATION: Lambda function '%s' handles PHI but is not deployed in a VPC. Add vpc_config block with subnet_ids and security_group_ids for network isolation",
        [function_name]
    )
}