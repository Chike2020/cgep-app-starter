\# Acme Health HIPAA Compliance Capstone - Implementation Plan



\## Executive Summary



\*\*Primary Framework\*\*: HIPAA Security Rule  

\*\*Justification\*\*: Acme Health is a telehealth company processing Protected Health Information (PHI). HIPAA compliance is legally required, not optional. While SOC 2 and CMMC would add value, HIPAA is the foundation that enables the company to legally operate.



\*\*Target\*\*: Close 6 of 8 gaps (exceed minimum of 5)  

\*\*Timeline\*\*: 21 days (3 weeks)  

\*\*Repository\*\*: https://github.com/Chike2020/cgep-app-starter



\---



\## The 8 Gaps - Remediation Strategy



\### HIGH PRIORITY (Will Fix in Terraform + Enforce in Policy)



\*\*GAP-01: S3 Encryption (SSE-KMS)\*\*

\- \*\*HIPAA\*\*: 164.312(a)(2)(iv) - Encryption and Decryption

\- \*\*Fix\*\*: Add `aws\_s3\_bucket\_server\_side\_encryption\_configuration` with CMK

\- \*\*Policy\*\*: Detect missing KMS encryption on PHI buckets

\- \*\*Layer\*\*: Terraform override + Rego policy



\*\*GAP-02: DynamoDB Encryption (CMK)\*\*

\- \*\*HIPAA\*\*: 164.312(a)(2)(iv) - Encryption and Decryption  

\- \*\*Fix\*\*: Add `server\_side\_encryption` block with CMK to DynamoDB table

\- \*\*Policy\*\*: Detect AWS-managed keys on PHI data stores

\- \*\*Layer\*\*: Terraform override + Rego policy



\*\*GAP-03: S3 TLS Enforcement\*\*

\- \*\*HIPAA\*\*: 164.312(e)(1) - Transmission Security

\- \*\*Fix\*\*: Add bucket policy denying `aws:SecureTransport = false`

\- \*\*Policy\*\*: Detect missing SecureTransport deny statement

\- \*\*Layer\*\*: Terraform override + Rego policy



\*\*GAP-04: S3 Versioning\*\*

\- \*\*HIPAA\*\*: 164.308(a)(7) - Contingency Plan (Data Backup)

\- \*\*Fix\*\*: Add `aws\_s3\_bucket\_versioning` resource

\- \*\*Policy\*\*: Detect unversioned PHI buckets

\- \*\*Layer\*\*: Terraform override + Rego policy



\*\*GAP-05: Lambda VPC Deployment\*\*

\- \*\*HIPAA\*\*: 164.312(e)(1) - Transmission Security (Network Isolation)

\- \*\*Fix\*\*: Add `vpc\_config` block to Lambda, create security group

\- \*\*Policy\*\*: Detect Lambda functions outside VPC

\- \*\*Layer\*\*: Terraform override + Rego policy



\*\*GAP-07: Lambda IAM Over-Permissions\*\*

\- \*\*HIPAA\*\*: 164.312(a)(1) - Access Control (Least Privilege)

\- \*\*Fix\*\*: Replace `dynamodb:\*` and `s3:\*` with specific actions

\- \*\*Policy\*\*: Detect wildcard permissions on PHI resources

\- \*\*Layer\*\*: Terraform override + Rego policy



\### MEDIUM PRIORITY (May address if time permits)



\*\*GAP-06: Lambda Observability\*\*

\- \*\*SOC 2\*\*: CC7.2 - System Monitoring

\- \*\*Fix\*\*: Add reserved concurrency, DLQ, X-Ray tracing

\- \*\*Layer\*\*: Terraform only (not critical for HIPAA)



\*\*GAP-08: API Gateway Logging\*\*

\- \*\*HIPAA\*\*: 164.312(b) - Audit Controls

\- \*\*Fix\*\*: Add CloudWatch Logs access logging

\- \*\*Layer\*\*: Terraform + CloudTrail covers audit requirement



\---



\## Week-by-Week Plan



\### Week 1: Infrastructure + Baseline (Days 1-7)



\*\*Days 1-2: Environment Setup\*\*

\- ✅ Fork repo

\- ✅ Deploy starter (`make deploy`)

\- ✅ Verify working (`make test`)

\- Create KMS key for PHI encryption

\- Create evidence vault with Object Lock (reuse Lab 2.5)

\- Deploy CloudTrail for audit logging



\*\*Days 3-5: Gap Remediation (Terraform)\*\*

\- Create `terraform/compliance-baseline.tf`

\- Fix GAP-01: S3 KMS encryption

\- Fix GAP-02: DynamoDB KMS encryption  

\- Fix GAP-03: S3 TLS-only policy

\- Fix GAP-04: S3 versioning

\- Fix GAP-05: Lambda VPC + security group

\- Fix GAP-07: Tighten IAM permissions

\- Test full deployment



\*\*Days 6-7: Verification\*\*

\- Plan and apply complete baseline

\- Verify all gaps closed

\- Document Terraform changes



\### Week 2: Policy + Pipeline (Days 8-14)



\*\*Days 8-10: OPA/Rego Policies\*\*

\- Create `policies/hipaa/` directory

\- Write 6 policies (one per gap)

\- Write test fixtures for each

\- Test with `opa test`

\- Run Conftest against plan



\*\*Days 11-13: GitHub Actions Pipeline\*\*

\- Create `.github/workflows/hipaa-compliance-gate.yml`

\- Implement 5 steps:

&#x20; 1. Terraform Plan

&#x20; 2. Conftest Policy Check

&#x20; 3. Terraform Apply (on merge)

&#x20; 4. Cosign Sign Evidence

&#x20; 5. Upload to Vault

\- Wire AWS OIDC (reuse Lab 4.3)

\- Wire Cosign (reuse Lab 4.4)



\*\*Day 14: PR Testing\*\*

\- Create GREEN PR (passes all checks)

\- Create RED PR (violates a policy)

\- Verify pipeline blocks non-compliant code



\### Week 3: OSCAL + Documentation (Days 15-21)



\*\*Days 15-17: OSCAL Component\*\*

\- Create `oscal/components/acme-health-intake.json`

\- Map 6 controls to HIPAA Security Rule

\- Link evidence to vault URIs

\- Create profile selecting HIPAA controls

\- Validate with trestle



\*\*Days 18-20: WRITEUP.md\*\*

\- Framework justification

\- Gap remediation details

\- Design trade-offs

\- What we didn't get to

\- Architecture diagrams



\*\*Day 21: Final Review\*\*

\- Test complete end-to-end flow

\- Verify evidence chain

\- Polish README

\- Submit



\---



\## Control Mapping (HIPAA → Gaps)



| HIPAA Control | Title | Gaps Addressed | Evidence |

|---------------|-------|----------------|----------|

| 164.312(a)(1) | Access Control | GAP-07 (IAM) | IAM policy JSON, Rego policy |

| 164.312(a)(2)(iv) | Encryption | GAP-01, GAP-02 | KMS key, encryption configs |

| 164.308(a)(7) | Contingency Plan | GAP-04 (Versioning) | S3 versioning config |

| 164.312(b) | Audit Controls | CloudTrail | Trail logs, evidence vault |

| 164.312(e)(1) | Transmission Security | GAP-03, GAP-05 | TLS policy, VPC config |



\---



\## Files to Create



cgep-app-starter/ (forked)

├── terraform/

│   ├── main.tf (existing starter)

│   ├── compliance-baseline.tf (NEW - our additions)

│   ├── kms.tf (NEW)

│   ├── cloudtrail.tf (NEW)

│   ├── evidence-vault.tf (NEW)

│   └── variables.tf (update)

│

├── policies/

│   └── hipaa/

│       ├── gap01\_s3\_kms\_encryption.rego

│       ├── gap01\_s3\_kms\_encryption\_test.rego

│       ├── gap02\_dynamodb\_kms.rego

│       ├── gap02\_dynamodb\_kms\_test.rego

│       ├── gap03\_s3\_tls\_only.rego

│       ├── gap03\_s3\_tls\_only\_test.rego

│       ├── gap04\_s3\_versioning.rego

│       ├── gap04\_s3\_versioning\_test.rego

│       ├── gap05\_lambda\_vpc.rego

│       ├── gap05\_lambda\_vpc\_test.rego

│       ├── gap07\_iam\_least\_privilege.rego

│       └── gap07\_iam\_least\_privilege\_test.rego

│

├── .github/workflows/

│   └── hipaa-compliance-gate.yml

│

├── oscal/

│   ├── components/

│   │   └── acme-health-intake.json

│   └── profiles/

│       └── hipaa-minimum.json

│

├── WRITEUP.md (NEW - capstone deliverable)

├── CAPSTONE-PLAN.md (this file)

└── README.md (update with verification instructions)

\---



\## Success Criteria



\- \[ ] All 8 starter resources still present and functional

\- \[ ] 6 gaps closed in Terraform

\- \[ ] 6 Rego policies with tests (all passing)

\- \[ ] GitHub Actions pipeline working end-to-end

\- \[ ] 1 GREEN PR merged

\- \[ ] 1 RED PR blocked

\- \[ ] Signed evidence in vault (Cosign verified)

\- \[ ] OSCAL component validated by trestle

\- \[ ] WRITEUP.md complete and honest

\- \[ ] README.md with grader instructions



\---



\## Next Steps



1\. Deploy starter to verify it works

2\. Create compliance-baseline.tf

3\. Start closing gaps one by one



Let's build this! 🚀

---

## WEEK 2 COMPLETION - ACHIEVED 2026-05-23

### Deliverables ✅
- [x] 6 Rego policies with comprehensive tests (13/13 passing)
- [x] GitHub Actions CI/CD pipeline (5 steps)
- [x] S3 backend for shared Terraform state
- [x] AWS OIDC authentication
- [x] Cosign cryptographic signing
- [x] Evidence vault with Object Lock
- [x] RED test PR (blocked - 3 violations)
- [x] GREEN test PR (passed - 0 violations)

### Evidence
- Pipeline runs: https://github.com/Chike2020/cgep-app-starter/actions
- Evidence vault: s3://acme-health-intake-evidence-vault-eca8c0d5/runs/
- Test PRs: #1 (RED), #2 (GREEN)

### Status
Week 2: 100% COMPLETE ✅
Overall Capstone Progress: 67% (2 weeks ahead of schedule)

