# Secure Multi-Tier Architecture with GuardDuty, KMS & Security Hub

An AWS Security Specialty–style design and documentation project: a secure, multi-tier application architecture defended with layered detective and preventive controls — KMS, Secrets Manager, GuardDuty, Security Hub, Config, CloudTrail, WAF/Shield, and IAM/SCPs.

## Table of Contents

- [Overview](#overview)
- [Scope & Approach](#scope--approach)
- [Architecture Diagram](#architecture-diagram)
- [Security Controls Deep Dive](#security-controls-deep-dive)
- [Incident Response Walkthrough](#incident-response-walkthrough)
- [Compliance Mapping](#compliance-mapping)
- [What I'd Do Differently at Scale](#what-id-do-differently-at-scale)

## Overview


 This architecture defends a three-tier web application's data and control plane against unauthorized access, data exfiltration, and configuration drift, using layered detective and preventive controls rather than a single perimeter. It maps directly to the AWS Well-Architected Framework's Security Pillar (identity foundations, defense in depth, automated response, data protection) and to the SAA-C03 exam's Security domain (encryption at rest/in transit, IAM least privilege, threat detection, and compliance monitoring).

## Scope & Approach

This is a design and documentation exercise. The architecture described here was designed and documented in detail, but it was **not deployed to a live AWS account**.


## Architecture Diagram

![Solution architecture diagram](architecture/solution-architecture.png)

*Solution architecture: the multi-tier VPC layout: public-facing ALB, private application tier (ASG/ECS), private data tier (RDS), and the security-service overlay (KMS, GuardDuty, Security Hub, Config, CloudTrail) that observes and protects all three.*

![Incident response flow diagram](architecture/incident-response-flow.png)

*Incident response flow: the automated detection-to-notification path: a GuardDuty finding triggers an EventBridge rule, which invokes a Lambda function that enriches and routes the finding, ending in a human-facing notification and an entry in the runbook's escalation path.*

## Security Controls Deep Dive

### KMS

**Decision:** four separate customer-managed keys — one each for S3 (assets/logs), RDS (database storage), EBS (compute-tier volumes), and SSM Parameter Store (SecureString config), instead of one shared CMK. Each key protects a different data category with a different owner, access pattern, and blast radius: a compromised compute-tier instance profile can only exercise EBS-decrypt rights, never database or config-secret decrypt rights, and CloudTrail's `kms:Decrypt` history for each key stays specific to that data category instead of being polluted by unrelated activity.

Each key's policy grants the account root full administrative access, and grants exactly one narrowly-scoped role `kms:Decrypt` / `kms:GenerateDataKey` / `kms:DescribeKey`, never `kms:*` restricted with a `kms:ViaService` condition so the role can only use the key through the one AWS service that legitimately needs it, not via a direct API call against arbitrary ciphertext.

```json
// Illustrative — RDS CMK policy statement, not deployed
{
  "Sid": "AllowAppTierUseViaRDS",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<account-id>:role/app-tier-role" },
  "Action": [
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:DescribeKey"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:ViaService": "rds.us-east-1.amazonaws.com"
    }
  }
}
```

### Secrets Manager

**Decision:** the RDS master credential lives in one secret, encrypted with the RDS CMK above, rotated automatically on a 30-day schedule via the AWS-provided single-user RDS rotation Lambda pattern. The application tier fetches the credential at **runtime** on each new connection (with short-TTL client-side caching) rather than injecting it as a boot-time environment variable, a boot-time env var would keep using the old password until every instance/task is restarted, silently defeating rotation, and would leave the plaintext value sitting in the task definition, launch template, and any crash dump or debug log for the life of the instance.

A resource policy on the secret (not just IAM) denies plaintext `GetSecretValue` to everything except the app-tier role and the rotation Lambda's role, and denies access entirely from outside the account.

### GuardDuty

**Decision:** enabled account-wide with S3 protection turned on (the log/asset bucket is a realistic exfiltration target), and findings are routed to Security Hub for consolidation and to EventBridge for automated response rather than left sitting in the GuardDuty console. EKS protection is left off, since this architecture has no EKS workload, enabling it would just add unreviewed findings noise.

### Security Hub

**Decision:** acts as the single aggregation point for GuardDuty, Config, and Inspector findings, with the CIS AWS Foundations Benchmark and the AWS Foundational Security Best Practices standards both enabled. Two standards rather than one deliberately: CIS gives an industry-recognized baseline reviewers will already know how to read, while the AWS-native standard catches service-specific misconfigurations CIS doesn't cover.

### Config

**Decision:** continuous evaluation rather than a point-in-time check, using a targeted set of managed rules chosen to match the controls that matter most in this architecture `rds-storage-encrypted`, `encrypted-volumes`, `s3-bucket-public-read-prohibited`, and `iam-user-mfa-enabled` among them (full list in [Compliance Mapping](#compliance-mapping)). Config's job here is to catch drift *after* deployment — a resource created correctly today but changed out-of-band six weeks later — which a one-time `terraform validate` pass structurally cannot.

### CloudTrail

**Decision:** a single multi-region trail with log file validation enabled, delivering to the same S3 bucket protected by the S3 CMK above. Multi-region is non-negotiable for an account-level audit trail, a single-region trail would silently miss any action taken through a different region's endpoint (including many IAM and STS calls, which are global but can still be invoked regionally). CloudTrail is also the evidentiary backbone GuardDuty and the incident-response Lambda both depend on.

### WAF + Shield

**Decision:** AWS WAF attached to the ALB with the AWS Managed Core rule group, the SQL injection managed rule group, and one custom rate-based rule for basic L7 flood/brute-force protection. Shield Standard (included at no extra cost) is judged sufficient here rather than Shield Advanced. Advanced's cost and its DDoS Response Team engagement make sense for a business-critical, high-traffic production workload, not for a single-account portfolio architecture with no real traffic.

```json
// Illustrative — WAF rate-based rule sketch, not deployed
{
  "Name": "RateLimitPerIP",
  "Priority": 1,
  "Action": { "Block": {} },
  "Statement": {
    "RateBasedStatement": {
      "Limit": 2000,
      "AggregateKeyType": "IP"
    }
  }
}
```

### IAM / SCPs

**Decision:** every tier runs under its own narrowly-scoped role (no shared "app role" spanning compute and database access), and Service Control Policies at the AWS Organizations level provide a preventive backstop on top of those roles, for example, denying anyone (including an account admin) from disabling GuardDuty or Config, or from creating unencrypted EBS volumes or RDS instances, account-wide. The SCP layer exists specifically so that a single over-permissioned IAM policy elsewhere can't quietly disable the detective controls this whole design depends on.

## Incident Response Walkthrough

Full detection-to-resolution steps live in [`docs/runbook.md`](docs/runbook.md); this section summarizes the automated path shown in the incident-response-flow diagram above.

A GuardDuty finding (for example, an EC2 instance querying a known command-and-control domain) is published to Security Hub for consolidation and simultaneously matched by an EventBridge rule filtering on finding severity. That rule invokes the incident-response Lambda, which enriches the finding with resource context, takes an automated first action appropriate to the finding type (e.g. isolating the instance's security group), and publishes a notification for human review. A human responder then follows the escalation steps in the runbook to confirm root cause, decide on further containment, and close out the finding, the automation handles speed of first response, not the full investigation.

## Compliance Mapping

The full control-by-control mapping, which CIS AWS Foundations Benchmark control ID each service/config decision above satisfies, and its current status (lives in [`docs/compliance-mapping.md`](docs/compliance-mapping.md)).

## What I'd Do Differently at Scale

