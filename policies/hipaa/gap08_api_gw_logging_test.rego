package compliance.hipaa.api_gw_logging

import rego.v1

# Stage with access logging AND throttling — must pass
stage_compliant := {"resource_changes": [{
	"type": "aws_apigatewayv2_stage",
	"change": {"after": {
		"name": "$default",
		"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/test"}],
		"default_route_settings": [{"throttling_burst_limit": 100, "throttling_rate_limit": 50}],
	}},
}]}

# Stage with no access_log_settings — must fail
stage_no_logging := {"resource_changes": [{
	"type": "aws_apigatewayv2_stage",
	"change": {"after": {
		"name": "$default",
		"access_log_settings": [],
		"default_route_settings": [{"throttling_burst_limit": 100, "throttling_rate_limit": 50}],
	}},
}]}

# Stage with no throttling (burst=0) — must fail
stage_no_throttling := {"resource_changes": [{
	"type": "aws_apigatewayv2_stage",
	"change": {"after": {
		"name": "$default",
		"access_log_settings": [{"destination_arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/test"}],
		"default_route_settings": [{"throttling_burst_limit": 0, "throttling_rate_limit": 0}],
	}},
}]}

test_compliant_stage_passes if {
	result := deny with input as stage_compliant
	count(result) == 0
}

test_stage_without_logging_fails if {
	result := deny with input as stage_no_logging
	count(result) == 1
}

test_stage_without_throttling_fails if {
	result := deny with input as stage_no_throttling
	count(result) == 1
}
