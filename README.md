# cgep-app-starter

> Patient Intake API for "Acme Health". The deliberately-flawed workload your **CGE-P capstone** wraps with GRC controls.

## What this is

A minimal AWS workload: VPC, Lambda, API Gateway, DynamoDB, S3. It ingests patient intake submissions over HTTPS. Think of it as a system you have just inherited from an engineering team and been asked to make audit-defensible.

This repository ships **non-compliant on purpose**. Your job in the capstone is not to rewrite this app. Your job is to wrap it with the four CGE-P layers (Terraform GRC baseline, Rego policies, GitHub Actions evidence pipeline, OSCAL component) so the same workload becomes audit-defensible against HIPAA, SOC 2, and CMMC L2.

## The deploy gate

If you cannot deploy this starter, you cannot pass the capstone. Real GRC engineers inherit working systems. Step zero is making the system run.

```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter

# Confirm you're authenticated to the right account:
make creds AWS_PROFILE=<your-sandbox-profile>

make deploy AWS_PROFILE=<your-sandbox-profile>
make test    AWS_PROFILE=<your-sandbox-profile>
```

> **AWS SSO note:** if your profile is SSO-based, Terraform's AWS provider can fail to read it directly with `failed to find SSO session section`. The Makefile's `eval $(aws configure export-credentials)` pattern handles this. If you're running `terraform` commands by hand, do the same export first.

Expected output of `make test`:

```json
{
    "submission_id": "f1e3...",
    "status": "received"
}
```

When you're done exploring: `make destroy`.

## What you build on top

Fork the repo into your own `cgep-capstone` and add:

1. **Layer 1 — GRC baseline (Terraform).** KMS keys, an S3 evidence vault with Object Lock, a CloudTrail trail. Bring this starter's data stores under your CMK.
2. **Layer 2 — OPA policy suite (Rego).** Five or more policies that catch the named gaps in [GAPS.md](GAPS.md). Each policy maps to at least one control from the framework you choose.
3. **Layer 3 — GitHub Actions pipeline.** Plan → Conftest gate → apply → Cosign sign → upload to vault.
4. **Layer 4 — OSCAL component.** A `component-definition.json` describing how your governed system implements its controls.

Full brief: `docs/labs/07_01_capstone_brief.md` in the course content repo.

## Framework mapping is required

Your capstone must declare a primary framework: **HIPAA Security Rule**, **SOC 2 Trust Services Criteria**, or **CMMC Level 2**. Every policy carries at least one control ID from your chosen framework. Your OSCAL component's `control-implementations` reference your framework's catalog.

A starter mapping is in [FRAMEWORKS.md](FRAMEWORKS.md). It is not the only valid mapping. You're expected to defend yours.

## Cost

Roughly $0 if destroyed within an hour. Lambda + API Gateway + DynamoDB + S3 are all pay-per-use, and an empty deployment generates no traffic. CloudTrail (which you add) costs cents.

## Layout

```
cgep-app-starter/
├── README.md            # this file
├── WORKLOAD.md          # what the API does
├── GAPS.md              # the named flaws your policies must catch
├── FRAMEWORKS.md        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile             # make deploy | test | destroy
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── lambda/handler.py
└── test/
    └── intake.sh
```

## License

MIT. Fork freely. Submissions remain learners' own work.

# HIPAA Compliance Automation - Patient Intake API

[![HIPAA Compliance Gate](https://github.com/Chike2020/cgep-app-starter/actions/workflows/hipaa-compliance-gate.yml/badge.svg)](https://github.com/Chike2020/cgep-app-starter/actions/workflows/hipaa-compliance-gate.yml)

Enterprise-grade HIPAA compliance automation demonstrating Infrastructure-as-Code, Policy-as-Code, and cryptographic evidence chains.

**Capstone Project** | **May 2026** | **Gideon Okechukwu**

---

## 🎯 Project Overview

Automated compliance enforcement for a cloud-native patient intake API handling Protected Health Information (PHI). The system implements the HIPAA Security Rule through automated policy checks, preventing non-compliant infrastructure from reaching production.

### Key Features

- ✅ **6 Automated Policies** - Rego policies enforcing HIPAA controls
- ✅ **100% Test Coverage** - 13/13 unit tests passing
- ✅ **Fail-Closed Enforcement** - Non-compliant changes blocked at CI/CD
- ✅ **Cryptographic Signatures** - Cosign keyless signing for evidence
- ✅ **Immutable Audit Trail** - S3 Object Lock with 90-day retention
- ✅ **75% Gap Closure** - 6 of 8 security gaps remediated

---

## 🏗️ Architecture

GitHub Actions Pipeline → Policy Check (Conftest) → Deploy → Sign → Evidence Vault
↓ FAIL = BLOCK
↓ PASS = CONTINUE
Patient Intake API
├── API Gateway
├── Lambda (VPC)
├── DynamoDB (KMS)
├── S3 (KMS, Versioning, TLS-only)
└── CloudTrail (Multi-region)

**Tech Stack:** Terraform | OPA/Rego | GitHub Actions | AWS | Cosign

---

## 📋 HIPAA Controls Implemented

| Control | Requirement | Implementation | Policy |
|---------|-------------|----------------|--------|
| 164.312(a)(2)(iv) | Encryption/Decryption | KMS CMK for S3 + DynamoDB | `gap01`, `gap02` |
| 164.312(e)(1) | Transmission Security | TLS-only S3, Lambda in VPC | `gap03`, `gap05` |
| 164.308(a)(7) | Contingency Plan | S3 versioning | `gap04` |
| 164.312(a)(1) | Access Control | Least privilege IAM | `gap07` |
| 164.312(b) | Audit Controls | CloudTrail data events | - |
| 164.308(a)(1)(ii)(D) | Activity Review | Evidence vault | - |

---

## 🚀 Quick Start

### Prerequisites

- AWS Account with credentials configured
- Terraform 1.9.0+
- OPA 0.55.0+
- GitHub repository

### Local Development

```bash
# Clone repository
git clone https://github.com/Chike2020/cgep-app-starter
cd cgep-app-starter

# Initialize Terraform
cd terraform
terraform init

# Run policy tests
cd ../policies/hipaa
opa test . -v

# Deploy infrastructure
cd ../../terraform
terraform plan
terraform apply
```

### CI/CD Pipeline

The GitHub Actions pipeline runs automatically on:
- **Pull Requests** - Policy check only (no deployment)
- **Push to main** - Full pipeline including deployment, signing, evidence upload

**Workflow:** `.github/workflows/hipaa-compliance-gate.yml`

---

## 🧪 Testing

### Policy Tests

```bash
cd policies/hipaa
opa test . -v
```

**Result:** `13/13 tests passing`

### Integration Tests

- **RED PR** - [#1](https://github.com/Chike2020/cgep-app-starter/pull/1) - BLOCKED (3 violations)
- **GREEN PR** - [#2](https://github.com/Chike2020/cgep-app-starter/pull/2) - PASSED (merged)

---

## 📊 Project Metrics

| Metric | Value |
|--------|-------|
| **Security Gaps Closed** | 6 of 8 (75%) |
| **Policy Tests** | 13/13 passing |
| **Infrastructure Resources** | 50+ AWS resources |
| **Pipeline Steps** | 5 automated stages |
| **Evidence Bundles** | Cryptographically signed |
| **Lines of Code** | 6,000+ (Terraform + Rego) |

---

## 📁 Repository Structure
cgep-app-starter/
├── .github/
│   └── workflows/
│       └── hipaa-compliance-gate.yml    # CI/CD pipeline
├── policies/
│   └── hipaa/
│       ├── gap01_s3_kms_encryption.rego
│       ├── gap02_dynamodb_kms.rego
│       ├── gap03_s3_tls_only.rego
│       ├── gap04_s3_versioning.rego
│       ├── gap05_lambda_vpc.rego
│       ├── gap07_iam_least_privilege.rego
│       └── *_test.rego                  # Unit tests
├── terraform/
│   ├── main.tf                          # Core infrastructure
│   ├── kms.tf                           # Encryption keys
│   ├── cloudtrail.tf                    # Audit logging
│   ├── evidence-vault.tf                # Immutable storage
│   ├── github-oidc.tf                   # CI/CD authentication
│   └── backend.tf                       # S3 state backend
├── oscal/
│   └── component-definition.json        # Compliance documentation
├── WRITEUP.md                           # Detailed project writeup
├── CAPSTONE-PLAN.md                     # Implementation plan
└── README.md                            # This file

---

## 🔐 Evidence Vault

**Bucket:** `s3://acme-health-intake-evidence-vault-eca8c0d5`

Each pipeline run stores:
- Terraform plan (JSON + binary)
- SHA-256 hash
- Cosign signature bundle
- Execution metadata

**Retention:** 90 days (COMPLIANCE mode - immutable)

**Example:**
runs/26318352453/
├── evidence-26318352453-{sha}.tar.gz
├── evidence-26318352453-{sha}.tar.gz.sha256
├── evidence-26318352453-{sha}.tar.gz.sig.bundle
└── receipt.json

---

## 📚 Documentation

- **[WRITEUP.md](WRITEUP.md)** - Comprehensive project documentation
- **[CAPSTONE-PLAN.md](CAPSTONE-PLAN.md)** - Implementation timeline
- **[OSCAL Component](oscal/component-definition.json)** - Machine-readable compliance

---

## 🎓 Capstone Completion

**Status:** ✅ COMPLETE (May 2026)

- [x] Week 1: Infrastructure deployment (6 gaps closed)
- [x] Week 2: Policy automation & CI/CD pipeline
- [x] Week 3: OSCAL documentation & writeup

**Timeline:** 3 weeks (1 week ahead of schedule)

---

## 🤝 Contributing

This is a capstone project and not accepting external contributions. However, feel free to fork and adapt for your own HIPAA compliance needs.

---

## 📄 License

Educational project - See institution guidelines for usage rights.

---

## 👤 Author

**Gideon Okechukwu**

- GitHub: [@Chike2020](https://github.com/Chike2020)
- Certifications: CISSP, PMP, Security+, NY Bar (2020)
- LinkedIn: [Connect with me](https://linkedin.com)

---

## 🙏 Acknowledgments

- HIPAA Security Rule guidance from HHS.gov
- OPA/Rego documentation from Open Policy Agent
- Cosign documentation from Sigstore
- CGE-P program curriculum and labs

---

**Built with ❤️ for compliance automation**
