# Secure Multi-Tier Architecture with GuardDuty, KMS & Security Hub

An AWS Security Specialty–style design and infrastructure-as-code portfolio project for a secure, multi-tier application architecture with defense-in-depth controls (GuardDuty, KMS, Security Hub, Config, CloudTrail, WAF, SCPs).

## Table of Contents

- [Solution Overview](#solution-overview)
- [Scope & Deployment Status](#️-scope--deployment-status)
- [Architecture Diagram](#architecture-diagram)
- [How It's Built](#how-its-built)
- [Repository Structure](#repository-structure)
- [Deploying (Reference Only, Not Executed)](#deploying-reference-only-not-executed)
- [Compliance Mapping](#compliance-mapping)


## Solution Overview

## Scope & Deployment Status

This repository contains architecture design and infrastructure-as-code authored for review purposes. **It was not deployed to a live AWS account.** All Terraform in this repository is validated with `terraform validate` and linted with `tflint`, but it has never been run through `terraform apply`, and no resources described here have ever existed in AWS. No screenshots, logs, or metrics in this repository (if any are added later) should be read as evidence of a live deployment. 

## Architecture Diagram

## How It's Built

## Repository Structure

```
secure-multi-tier-architecture-aws/
├── README.md
├── .gitignore
├── architecture/
│   ├── solution-architecture.png    # placeholder
│   ├── incident-response-flow.png   # placeholder
│   └── architecture-diagram.drawio  # placeholder
├── infrastructure/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── network/
│   │   └── main.tf
│   ├── security/
│   │   ├── kms.tf
│   │   ├── secrets-manager.tf
│   │   ├── guardduty.tf
│   │   ├── security-hub.tf
│   │   ├── config-rules.tf
│   │   ├── cloudtrail.tf
│   │   ├── waf.tf
│   │   └── scp.tf
│   └── compute/
│       └── main.tf
├── lambda/
│   ├── rds-rotation/
│   │   └── README.md
│   └── incident-response/
│       └── README.md
├── docs/
│   ├── threat-model.md
│   ├── compliance-mapping.md
│   └── runbook.md
└── demo/                            
```

## Deploying (Reference Only, Not Executed)

## Compliance Mapping
