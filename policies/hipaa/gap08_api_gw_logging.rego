# METADATA
# title: HIPAA 164.312(b) - API Gateway Access Logging and Throttling
# description: API Gateway HTTP stages must have access logging enabled and throttling configured
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(b)"
#   severity: high
#   gap: GAP-08
package compliance.hipaa.api_gw_logging

import rego.v1

is_apigw_stage(resource) if {
	resource.type == "aws_apigatewayv2_stage"
}

has_access_logging(resource) if {
	al := resource.change.after.access_log_settings
	al != null
	count(al) > 0
}

has_throttling(resource) if {
	drs := resource.change.after.default_route_settings
	drs != null
	count(drs) > 0
	drs[_].throttling_burst_limit > 0
	drs[_].throttling_rate_limit > 0
}

deny contains msg if {
	some resource in input.resource_changes
	is_apigw_stage(resource)
	not has_access_logging(resource)
	stage_name := resource.change.after.name

	msg := sprintf(
		"HIPAA 164.312(b) VIOLATION: API Gateway stage '%s' has no access_log_settings. Add a CloudWatch log group destination to capture request audit records.",
		[stage_name],
	)
}

deny contains msg if {
	some resource in input.resource_changes
	is_apigw_stage(resource)
	not has_throttling(resource)
	stage_name := resource.change.after.name

	msg := sprintf(
		"HIPAA 164.312(b) VIOLATION: API Gateway stage '%s' has no throttling configured. Set throttling_burst_limit and throttling_rate_limit in default_route_settings.",
		[stage_name],
	)
}
