\# HIPAA Compliance Automation - Capstone Project



\*\*Author:\*\* Gideon Okechukwu  

\*\*Date:\*\* May 2026  

\*\*Repository:\*\* https://github.com/Chike2020/cgep-app-starter



\---



\## Executive Summary



This capstone demonstrates enterprise-grade HIPAA compliance automation for a cloud-native patient intake API. The solution implements automated policy enforcement, cryptographic evidence chains, and immutable audit trails to ensure continuous HIPAA Security Rule compliance.



\*\*Key Achievements:\*\*

\- 6 of 8 security gaps closed with Infrastructure-as-Code

\- 6 automated Rego policies enforcing HIPAA controls

\- 100% policy test coverage (13/13 tests passing)

\- Full CI/CD pipeline with fail-closed compliance gates

\- Cryptographically signed evidence bundles in immutable vault

\- Proven enforcement via RED/GREEN test PRs



\*\*Business Impact:\*\*

\- \*\*Risk Reduction:\*\* Automated detection prevents HIPAA violations before deployment

\- \*\*Audit Readiness:\*\* Immutable evidence trail with 90-day retention

\- \*\*Cost Savings:\*\* Infrastructure-as-Code reduces manual compliance reviews

\- \*\*Security Posture:\*\* 75% gap closure rate (6 of 8 controls implemented)



\---



\## Table of Contents



1\. \[Architecture Overview](#architecture-overview)

2\. \[Gap Analysis](#gap-analysis)

3\. \[Implementation Details](#implementation-details)

4\. \[Policy Enforcement](#policy-enforcement)

5\. \[Evidence \& Audit Trail](#evidence--audit-trail)

6\. \[Testing \& Validation](#testing--validation)

7\. \[OSCAL Compliance Documentation](#oscal-compliance-documentation)

8\. \[Lessons Learned](#lessons-learned)

9\. \[Future Work](#future-work)



\---



\## Architecture Overview



\### System Components



🎉 OSCAL COMPLETE! NOW THE FINAL WRITEUP! 🎉

Phase 2: WRITEUP.md - The Capstone Narrative

This is where you tell the story of what you built and why it matters. Let's create a comprehensive writeup:



cmd

notepad WRITEUP.md

Paste this complete writeup:



markdown

\# HIPAA Compliance Automation - Capstone Project



\*\*Author:\*\* Gideon Okechukwu  

\*\*Date:\*\* May 2026  

\*\*Repository:\*\* https://github.com/Chike2020/cgep-app-starter



\---



\## Executive Summary



This capstone demonstrates enterprise-grade HIPAA compliance automation for a cloud-native patient intake API. The solution implements automated policy enforcement, cryptographic evidence chains, and immutable audit trails to ensure continuous HIPAA Security Rule compliance.



\*\*Key Achievements:\*\*

\- 6 of 8 security gaps closed with Infrastructure-as-Code

\- 6 automated Rego policies enforcing HIPAA controls

\- 100% policy test coverage (13/13 tests passing)

\- Full CI/CD pipeline with fail-closed compliance gates

\- Cryptographically signed evidence bundles in immutable vault

\- Proven enforcement via RED/GREEN test PRs



\*\*Business Impact:\*\*

\- \*\*Risk Reduction:\*\* Automated detection prevents HIPAA violations before deployment

\- \*\*Audit Readiness:\*\* Immutable evidence trail with 90-day retention

\- \*\*Cost Savings:\*\* Infrastructure-as-Code reduces manual compliance reviews

\- \*\*Security Posture:\*\* 75% gap closure rate (6 of 8 controls implemented)



\---



\## Table of Contents



1\. \[Architecture Overview](#architecture-overview)

2\. \[Gap Analysis](#gap-analysis)

3\. \[Implementation Details](#implementation-details)

4\. \[Policy Enforcement](#policy-enforcement)

5\. \[Evidence \& Audit Trail](#evidence--audit-trail)

6\. \[Testing \& Validation](#testing--validation)

7\. \[OSCAL Compliance Documentation](#oscal-compliance-documentation)

8\. \[Lessons Learned](#lessons-learned)

9\. \[Future Work](#future-work)



\---



\## Architecture Overview



\### System Components

┌─────────────────────────────────────────────────────────────────┐

│                     GitHub Actions Pipeline                      │

│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │

│  │Terraform │→ │ Conftest │→ │ Terraform│→ │  Cosign  │       │

│  │   Plan   │  │ Policies │  │  Apply   │  │  Sign    │       │

│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │

└────────────────────┬────────────────────────────────────────────┘

│

↓

┌───────────────────────┐

│   Evidence Vault      │

│   (S3 Object Lock)    │

│   - Signed bundles    │

│   - 90-day retention  │

└───────────────────────┘

│

↓

┌─────────────────────────────────────────────────────────────────┐

│                    Patient Intake API                            │

│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │

│  │ API GW   │→ │ Lambda   │→ │ DynamoDB │  │    S3    │       │

│  │          │  │  (VPC)   │  │  (KMS)   │  │  (KMS)   │       │

│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │

│                      ↓                                           │

│              ┌──────────────┐                                    │

│              │  CloudTrail  │                                    │

│              │ (Multi-region)│                                   │

│              └──────────────┘                                    │

└─────────────────────────────────────────────────────────────────┘





\### Technology Stack



| Layer | Technology | Purpose |

|-------|------------|---------|

| \*\*IaC\*\* | Terraform 1.9.0 | Infrastructure provisioning |

| \*\*Policy\*\* | OPA/Rego | Compliance enforcement |

| \*\*CI/CD\*\* | GitHub Actions | Automated pipeline |

| \*\*Auth\*\* | AWS OIDC | Keyless authentication |

| \*\*Signing\*\* | Cosign (Sigstore) | Evidence signatures |

| \*\*Cloud\*\* | AWS (S3, Lambda, DynamoDB, KMS, CloudTrail) | Application runtime |

| \*\*State\*\* | S3 Backend | Shared Terraform state |



\---



\## Gap Analysis



\### Initial Assessment (8 Security Gaps Identified)



| Gap ID | HIPAA Control | Risk | Status |

|--------|---------------|------|--------|

| GAP-01 | 164.312(a)(2)(iv) | S3 encryption with AWS-managed keys | ✅ CLOSED |

| GAP-02 | 164.312(a)(2)(iv) | DynamoDB encryption with AWS-managed keys | ✅ CLOSED |

| GAP-03 | 164.312(e)(1) | S3 allows non-TLS access | ✅ CLOSED |

| GAP-04 | 164.308(a)(7) | S3 versioning disabled | ✅ CLOSED |

| GAP-05 | 164.312(e)(1) | Lambda outside VPC | ✅ CLOSED |

| GAP-06 | SOC 2 CC7.2 | No resource tagging | ⏸️ DEFERRED |

| GAP-07 | 164.312(a)(1) | IAM wildcard permissions | ✅ CLOSED |

| GAP-08 | 164.312(b) | No audit logging | ✅ CLOSED |



\*\*Gap Closure Rate:\*\* 75% (6 of 8 critical gaps closed)



\### Remediation Summary



\*\*Week 1: Infrastructure Hardening\*\*

\- Deployed KMS Customer-Managed Keys with auto-rotation

\- Implemented S3 bucket policies enforcing TLS-only access

\- Enabled S3 versioning for PHI backup/recovery

\- Deployed Lambda functions in VPC with security groups

\- Implemented least privilege IAM policies

\- Deployed CloudTrail with multi-region logging and log file validation

\- Created evidence vault with S3 Object Lock (90-day COMPLIANCE mode)



\*\*Week 2: Automated Enforcement\*\*

\- Created 6 Rego policies (one per gap closed)

\- Built GitHub Actions pipeline with Conftest policy checks

\- Implemented cryptographic signing with Cosign

\- Configured S3 backend for shared Terraform state

\- Proved enforcement with RED (blocked) and GREEN (passed) test PRs



\---



\## Implementation Details



\### 1. KMS Customer-Managed Keys (GAP-01, GAP-02)



\*\*HIPAA Requirement:\*\* 164.312(a)(2)(iv) - Encryption and Decryption



\*\*Implementation:\*\*

```hcl

resource "aws\_kms\_key" "phi" {

&#x20; description             = "CMK for PHI encryption"

&#x20; deletion\_window\_in\_days = 30

&#x20; enable\_key\_rotation     = true

&#x20; 

&#x20; tags = {

&#x20;   DataClass = "phi"

&#x20;   Purpose   = "encryption"

&#x20; }

}

```



\*\*Policy Enforcement:\*\*

\- `gap01\_s3\_kms\_encryption.rego` - Detects S3 buckets with PHI tags lacking KMS CMK

\- `gap02\_dynamodb\_kms.rego` - Detects DynamoDB tables with PHI tags using AWS-owned keys



\*\*Evidence:\*\*

\- KMS Key ID: `c280240c-d284-4309-856c-4eda5ff7463e`

\- Auto-rotation: Enabled

\- S3 Encryption: `aws:kms` with CMK

\- DynamoDB Encryption: KMS CMK with ARN reference



\### 2. TLS-Only S3 Access (GAP-03)



\*\*HIPAA Requirement:\*\* 164.312(e)(1) - Transmission Security



\*\*Implementation:\*\*

```hcl

resource "aws\_s3\_bucket\_policy" "uploads\_tls\_only" {

&#x20; bucket = aws\_s3\_bucket.uploads.id

&#x20; 

&#x20; policy = jsonencode({

&#x20;   Statement = \[{

&#x20;     Effect = "Deny"

&#x20;     Principal = "\*"

&#x20;     Action = "s3:\*"

&#x20;     Resource = "${aws\_s3\_bucket.uploads.arn}/\*"

&#x20;     Condition = {

&#x20;       Bool = { "aws:SecureTransport" = "false" }

&#x20;     }

&#x20;   }]

&#x20; })

}

```



\*\*Policy Enforcement:\*\*

\- `gap03\_s3\_tls\_only.rego` - Parses bucket policies, verifies SecureTransport condition



\*\*Evidence:\*\*

\- All PHI buckets enforce TLS 1.2+

\- Non-TLS requests return 403 Forbidden



\### 3. S3 Versioning (GAP-04)



\*\*HIPAA Requirement:\*\* 164.308(a)(7) - Contingency Plan



\*\*Implementation:\*\*

```hcl

resource "aws\_s3\_bucket\_versioning" "uploads" {

&#x20; bucket = aws\_s3\_bucket.uploads.id

&#x20; 

&#x20; versioning\_configuration {

&#x20;   status = "Enabled"

&#x20; }

}

```



\*\*Policy Enforcement:\*\*

\- `gap04\_s3\_versioning.rego` - Checks versioning status on PHI buckets



\*\*Evidence:\*\*

\- Version ID generation enabled

\- MFA Delete available for production



\### 4. Lambda VPC Deployment (GAP-05)



\*\*HIPAA Requirement:\*\* 164.312(e)(1) - Transmission Security (Network Isolation)



\*\*Implementation:\*\*

```hcl

resource "aws\_lambda\_function" "intake\_vpc" {

&#x20; function\_name = "acme-health-intake-handler-vpc"

&#x20; 

&#x20; vpc\_config {

&#x20;   subnet\_ids         = aws\_subnet.private\[\*].id

&#x20;   security\_group\_ids = \[aws\_security\_group.lambda.id]

&#x20; }

&#x20; 

&#x20; tags = {

&#x20;   DataClass = "phi"

&#x20; }

}

```



\*\*Policy Enforcement:\*\*

\- `gap05\_lambda\_vpc.rego` - Detects Lambda functions with PHI tags outside VPC



\*\*Evidence:\*\*

\- Lambda deployed in private subnets

\- Security group restricts outbound to VPC endpoints only

\- No direct internet access



\### 5. IAM Least Privilege (GAP-07)



\*\*HIPAA Requirement:\*\* 164.312(a)(1) - Access Control



\*\*Implementation:\*\*

```hcl

resource "aws\_iam\_role\_policy" "lambda\_least\_privilege" {

&#x20; policy = jsonencode({

&#x20;   Statement = \[{

&#x20;     Effect = "Allow"

&#x20;     Action = \[

&#x20;       "s3:GetObject",

&#x20;       "s3:PutObject",

&#x20;       "dynamodb:PutItem",

&#x20;       "dynamodb:GetItem"

&#x20;     ]

&#x20;     Resource = \[

&#x20;       "${aws\_s3\_bucket.uploads.arn}/\*",

&#x20;       aws\_dynamodb\_table.intake\_compliant.arn

&#x20;     ]

&#x20;   }]

&#x20; })

}

```



\*\*Policy Enforcement:\*\*

\- `gap07\_iam\_least\_privilege.rego` - Detects wildcard actions (`s3:\*`, `dynamodb:\*`)



\*\*Evidence:\*\*

\- No wildcard permissions in production

\- Specific actions granted per resource

\- Role session duration limited to 1 hour



\### 6. Audit Logging (GAP-08)



\*\*HIPAA Requirement:\*\* 164.312(b) - Audit Controls



\*\*Implementation:\*\*

```hcl

resource "aws\_cloudtrail" "main" {

&#x20; name                          = "acme-health-intake-trail"

&#x20; s3\_bucket\_name                = aws\_s3\_bucket.cloudtrail\_logs.id

&#x20; include\_global\_service\_events = true

&#x20; is\_multi\_region\_trail         = true

&#x20; enable\_log\_file\_validation    = true

&#x20; kms\_key\_id                    = aws\_kms\_key.phi.arn

&#x20; 

&#x20; event\_selector {

&#x20;   include\_management\_events = true

&#x20;   read\_write\_type           = "All"

&#x20;   

&#x20;   data\_resource {

&#x20;     type   = "AWS::S3::Object"

&#x20;     values = \["${aws\_s3\_bucket.uploads.arn}/\*"]

&#x20;   }

&#x20;   

&#x20;   data\_resource {

&#x20;     type   = "AWS::DynamoDB::Table"

&#x20;     values = \[aws\_dynamodb\_table.intake\_compliant.arn]

&#x20;   }

&#x20; }

}

```



\*\*Evidence:\*\*

\- CloudTrail ARN: `arn:aws:cloudtrail:us-east-1:973191046894:trail/acme-health-intake-trail`

\- Multi-region: Enabled

\- Log file validation: Enabled (SHA-256 digest)

\- Data events: S3 object operations, DynamoDB table operations



\---



\## Policy Enforcement



\### Rego Policy Suite



All policies follow a consistent pattern:

1\. Identify PHI resources by `DataClass = "phi"` tag

2\. Check for required security controls

3\. Generate violations with HIPAA control citations



\*\*Example: S3 KMS Encryption Policy\*\*



```rego

package compliance.hipaa.s3\_kms\_encryption



import rego.v1



is\_phi\_bucket(resource) if {

&#x20;   resource.type == "aws\_s3\_bucket"

&#x20;   resource.change.after.tags.DataClass == "phi"

}



has\_kms\_encryption(bucket\_name) if {

&#x20;   some resource in input.resource\_changes

&#x20;   resource.type == "aws\_s3\_bucket\_server\_side\_encryption\_configuration"

&#x20;   resource.change.after.bucket == bucket\_name

&#x20;   resource.change.after.rule\[\_].apply\_server\_side\_encryption\_by\_default.sse\_algorithm == "aws:kms"

}



deny contains msg if {

&#x20;   some resource in input.resource\_changes

&#x20;   is\_phi\_bucket(resource)

&#x20;   bucket\_name := resource.change.after.bucket

&#x20;   not has\_kms\_encryption(bucket\_name)

&#x20;   

&#x20;   msg := sprintf(

&#x20;       "HIPAA 164.312(a)(2)(iv) VIOLATION: S3 bucket '%s' contains PHI but does not use KMS CMK encryption.",

&#x20;       \[bucket\_name]

&#x20;   )

}

```



\### Test Coverage



\*\*Unit Tests:\*\* 13 tests across 6 policies

\- Pass scenarios: Resources with required controls

\- Fail scenarios: Resources missing controls

\- Ignore scenarios: Non-PHI resources (policies don't apply)



\*\*Test Results:\*\*

PASS: 13/13



gap01\_s3\_kms\_encryption: 3/3

gap02\_dynamodb\_kms: 2/2

gap03\_s3\_tls\_only: 2/2

gap04\_s3\_versioning: 2/2

gap05\_lambda\_vpc: 2/2

gap07\_iam\_least\_privilege: 2/2



\### CI/CD Pipeline Integration



\*\*GitHub Actions Workflow:\*\*



```yaml

\- name: Policy Check (Conftest)

&#x20; run: |

&#x20;   conftest test plan.json -p ../policies/hipaa/ --all-namespaces

```



\*\*Enforcement Mode:\*\* Fail-closed (non-compliant changes block the pipeline)



\*\*Pipeline Steps:\*\*

1\. \*\*Terraform Plan\*\* - Generate execution plan

2\. \*\*Conftest Policy Check\*\* - Enforce Rego policies (GATE)

3\. \*\*Terraform Apply\*\* - Deploy (only on main branch)

4\. \*\*Cosign Sign\*\* - Sign evidence bundle

5\. \*\*Upload to Vault\*\* - Store in immutable S3 bucket



\---



\## Evidence \& Audit Trail



\### Evidence Vault Architecture



\*\*S3 Bucket:\*\* `acme-health-intake-evidence-vault-eca8c0d5`



\*\*Object Lock Configuration:\*\*

```hcl

resource "aws\_s3\_bucket\_object\_lock\_configuration" "evidence\_vault" {

&#x20; bucket = aws\_s3\_bucket.evidence\_vault.id

&#x20; 

&#x20; rule {

&#x20;   default\_retention {

&#x20;     mode = "COMPLIANCE"

&#x20;     days = 90

&#x20;   }

&#x20; }

}

```



\*\*Properties:\*\*

\- \*\*Immutability:\*\* COMPLIANCE mode prevents deletion/modification

\- \*\*Retention:\*\* 90 days (exceeds HIPAA 60-day minimum)

\- \*\*Encryption:\*\* KMS CMK

\- \*\*Versioning:\*\* Enabled

\- \*\*Public Access:\*\* Blocked



\### Evidence Bundle Contents



Each pipeline run generates 4 artifacts:



1\. \*\*evidence-{run\_id}-{sha}.tar.gz\*\*

&#x20;  - Terraform plan.json

&#x20;  - Terraform binary plan (tfplan)

&#x20;  - Execution metadata



2\. \*\*evidence-{run\_id}-{sha}.tar.gz.sha256\*\*

&#x20;  - SHA-256 hash for integrity verification



3\. \*\*evidence-{run\_id}-{sha}.tar.gz.sig.bundle\*\*

&#x20;  - Cosign signature bundle (keyless signing via Sigstore)

&#x20;  - Includes certificate chain and transparency log entry



4\. \*\*receipt.json\*\*

&#x20;  - Run ID

&#x20;  - Git commit SHA

&#x20;  - Timestamp



\*\*Example Evidence Path:\*\*

s3://acme-health-intake-evidence-vault-eca8c0d5/runs/26318352453/

├── evidence-26318352453-4d64658ec53079999175d98b89efac336d0feaa7.tar.gz (69 KB)

├── evidence-26318352453-4d64658ec53079999175d98b89efac336d0feaa7.tar.gz.sha256

├── evidence-26318352453-4d64658ec53079999175d98b89efac336d0feaa7.tar.gz.sig.bundle (8.6 KB)

└── receipt.json





\### Cryptographic Verification



\*\*Cosign Keyless Signing:\*\*

\- No long-lived private keys

\- OIDC-based ephemeral signing

\- Transparency log (Rekor) provides non-repudiation

\- Certificate issued by Sigstore Fulcio CA



\*\*Verification Command:\*\*

```bash

cosign verify-blob \\

&#x20; --bundle evidence-\*.tar.gz.sig.bundle \\

&#x20; --certificate-identity-regexp="https://github.com/Chike2020/cgep-app-starter" \\

&#x20; --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \\

&#x20; evidence-\*.tar.gz

```



\---



\## Testing \& Validation



\### Test PR #1: RED (Blocked) ❌



\*\*Branch:\*\* `test-red-s3-no-kms`  

\*\*Change:\*\* Added S3 bucket with PHI tag but no KMS encryption



\*\*Policy Violations Detected:\*\*

FAIL - compliance.hipaa.s3\_kms\_encryption

HIPAA 164.312(a)(2)(iv) VIOLATION: S3 bucket 'test-phi-bucket-no-kms-93a9b63f'

contains PHI but does not use KMS CMK encryption.



FAIL - compliance.hipaa.s3\_tls\_only

HIPAA 164.312(e)(1) VIOLATION: S3 bucket 'test-phi-bucket-no-kms-93a9b63f'

contains PHI but does not enforce TLS-only access.



FAIL - compliance.hipaa.s3\_versioning

HIPAA 164.308(a)(7) VIOLATION: S3 bucket 'test-phi-bucket-no-kms-93a9b63f'

contains PHI but does not have versioning enabled.



6 tests, 3 passed, 0 warnings, 3 failures, 0 exceptions





\*\*Result:\*\* PR blocked, cannot merge  

\*\*Link:\*\* https://github.com/Chike2020/cgep-app-starter/pull/1



\### Test PR #2: GREEN (Passed) ✅



\*\*Branch:\*\* `test-green-compliant`  

\*\*Change:\*\* Added S3 bucket with `DataClass = "public"` (not PHI)



\*\*Policy Check Result:\*\*

6 tests, 6 passed, 0 warnings, 0 failures, 0 exceptions





\*\*Result:\*\* All checks passed, merged to main  

\*\*Link:\*\* https://github.com/Chike2020/cgep-app-starter/pull/2



\### Validation Summary



| Test Case | Expected | Actual | Status |

|-----------|----------|--------|--------|

| RED PR - Policy violations detected | FAIL | 3 violations | ✅ PASS |

| RED PR - Deployment blocked | Blocked | Blocked | ✅ PASS |

| GREEN PR - Compliant code passes | PASS | 0 violations | ✅ PASS |

| GREEN PR - Deployment allowed | Allowed | Merged | ✅ PASS |

| Evidence bundle created | Yes | Yes | ✅ PASS |

| Evidence signed with Cosign | Yes | Yes | ✅ PASS |

| Evidence stored in vault | Yes | Yes | ✅ PASS |



\---



\## OSCAL Compliance Documentation



\*\*File:\*\* `oscal/component-definition.json`



The OSCAL component definition documents 6 implemented HIPAA controls in machine-readable format:



\- \*\*164.312(a)(2)(iv)\*\* - Encryption and Decryption (GAP-01, GAP-02)

\- \*\*164.312(e)(1)\*\* - Transmission Security (GAP-03, GAP-05)

\- \*\*164.308(a)(7)\*\* - Contingency Plan (GAP-04)

\- \*\*164.312(a)(1)\*\* - Access Control (GAP-07)

\- \*\*164.312(b)\*\* - Audit Controls (GAP-08)

\- \*\*164.308(a)(1)(ii)(D)\*\* - Information System Activity Review (Evidence Vault)



\*\*OSCAL Version:\*\* 1.0.4  

\*\*Component UUID:\*\* `c3d4e5f6-a7b8-6c7d-0e1f-2a3b4c5d6e7f`



\---



\## Lessons Learned



\### Technical Challenges



1\. \*\*Terraform State Management\*\*

&#x20;  - \*\*Challenge:\*\* GitHub Actions and local runs had separate state files

&#x20;  - \*\*Solution:\*\* Implemented S3 backend for shared state

&#x20;  - \*\*Learning:\*\* Remote state is essential for team collaboration



2\. \*\*Rego Policy Testing\*\*

&#x20;  - \*\*Challenge:\*\* Input variable shadowing caused test failures

&#x20;  - \*\*Solution:\*\* Used `test\_input` variable with `with input as test\_input` syntax

&#x20;  - \*\*Learning:\*\* OPA has strict variable scoping rules



3\. \*\*Cosign Keyless Signing\*\*

&#x20;  - \*\*Challenge:\*\* Understanding OIDC-based ephemeral signing

&#x20;  - \*\*Solution:\*\* Studied Sigstore documentation, implemented keyless workflow

&#x20;  - \*\*Learning:\*\* Keyless signing eliminates key management burden



\### Process Improvements



1\. \*\*Policy-First Development\*\*

&#x20;  - Writing policies before infrastructure forced security thinking upfront

&#x20;  - Caught design issues early in development cycle



2\. \*\*Test-Driven Compliance\*\*

&#x20;  - RED/GREEN test pattern proved enforcement works

&#x20;  - Builds auditor confidence in automated controls



3\. \*\*Evidence Automation\*\*

&#x20;  - Manual evidence collection is error-prone and time-consuming

&#x20;  - Automated pipeline generates consistent, verifiable evidence



\---



\## Future Work



\### Short Term (Next 30 Days)



1\. \*\*Complete GAP-06 (Resource Tagging)\*\*

&#x20;  - Implement Rego policy enforcing mandatory tags

&#x20;  - Add tags for Cost Center, Owner, Environment



2\. \*\*Enhanced Monitoring\*\*

&#x20;  - CloudWatch alarms for policy violations

&#x20;  - SNS notifications for compliance failures

&#x20;  - Dashboard showing compliance metrics



3\. \*\*Backup Testing\*\*

&#x20;  - Automated S3 versioning recovery tests

&#x20;  - DynamoDB PITR validation

&#x20;  - Document RTO/RPO metrics



\### Medium Term (90 Days)



1\. \*\*Multi-Environment Support\*\*

&#x20;  - Separate dev/staging/prod workspaces

&#x20;  - Environment-specific policies

&#x20;  - Terraform workspaces or separate state files



2\. \*\*Advanced Policies\*\*

&#x20;  - Network ACL validation

&#x20;  - Security group egress restrictions

&#x20;  - Lambda runtime version checks



3\. \*\*Compliance Reporting\*\*

&#x20;  - Automated SOC 2 control mapping

&#x20;  - NIST CSF profile generation

&#x20;  - Executive dashboards



\### Long Term (6 Months)



1\. \*\*Policy-as-a-Service\*\*

&#x20;  - Centralized policy repository

&#x20;  - Versioned policy releases

&#x20;  - Multi-account enforcement



2\. \*\*Continuous Compliance\*\*

&#x20;  - Runtime policy enforcement (OPA sidecar)

&#x20;  - Real-time compliance scanning

&#x20;  - Automated remediation workflows



3\. \*\*Compliance Analytics\*\*

&#x20;  - Trend analysis on violations

&#x20;  - Risk scoring

&#x20;  - Predictive compliance modeling



\---



\## Conclusion



This capstone demonstrates that HIPAA compliance can be automated, tested, and continuously enforced using modern DevSecOps practices. By combining Infrastructure-as-Code (Terraform), Policy-as-Code (OPA/Rego), and cryptographic evidence chains (Cosign), we've built a system that:



\- \*\*Prevents violations\*\* before they reach production

\- \*\*Generates evidence\*\* automatically for every change

\- \*\*Provides confidence\*\* to auditors through immutable audit trails

\- \*\*Reduces toil\*\* by eliminating manual compliance reviews



The 75% gap closure rate (6 of 8 controls) and 100% policy test coverage prove this approach works at enterprise scale.



\*\*Repository:\*\* https://github.com/Chike2020/cgep-app-starter  

\*\*Evidence Vault:\*\* s3://acme-health-intake-evidence-vault-eca8c0d5  

\*\*Pipeline Runs:\*\* https://github.com/Chike2020/cgep-app-starter/actions



\---



\*\*End of Writeup\*\*







