Automated CVE Remediation Platform - Phase 1

Overview

This project aims to build an automated CVE remediation platform for containerized applications using Trivy vulnerability scanning and deterministic remediation rules.

The primary objective is to reduce the time required to remediate known vulnerabilities by automatically identifying, validating, and proposing fixes through GitHub Pull Requests.

Phase 1 intentionally excludes AI-based decision-making and focuses on rule-driven, auditable remediation workflows.

⸻

Goals

* Detect vulnerabilities in Docker images and Dockerfiles.
* Continuously scan repositories through GitHub Actions.
* Automatically identify remediation opportunities.
* Apply deterministic remediation strategies.
* Validate fixes through rebuild and rescanning.
* Generate Pull Requests containing proposed fixes.
* Maintain full auditability and developer control.

⸻

Scope

Included

* Docker image scanning using Trivy
* Dockerfile analysis
* Base image remediation
* OS package remediation
* GitHub Actions integration
* Pull Request creation
* Daily scans on the main branch
* Pull Request scans on feature branches

Excluded (Phase 1)

* AI-generated code changes
* Automatic merge to main branch
* Major version upgrades
* Application dependency remediation (Maven, npm, pip, NuGet)
* Runtime remediation

⸻

High-Level Architecture

                    GitHub Repository
                           |
                           |
            +--------------+--------------+
            |                             |
            |                             |
      Pull Request                 Daily Main Scan
            |                             |
            v                             v
       GitHub Actions               GitHub Actions
            |                             |
            +-------------+---------------+
                          |
                          v
                     Build Image
                          |
                          v
                     Trivy Scan
                          |
                          v
                 Remediation Service
                          |
                          v
                     Rules Engine
                          |
                          v
                  Remediation Decision
                          |
                          v
                 Dockerfile Updater
                          |
                          v
                   Build Validation
                          |
                          v
                    Trivy Re-Scan
                          |
                          v
                    GitHub Update

⸻

Workflow Types

1. Pull Request Workflow

When a developer opens a Pull Request:

Developer PR
      |
      v
Build Image
      |
      v
Trivy Scan
      |
      v
Rules Engine
      |
      v
Auto Remediation
      |
      v
Commit to Same Branch
      |
      v
PR Updated

Design Decision

The remediation engine updates the existing Pull Request branch.

No additional Pull Request is created.

Benefits:

* Single review experience
* Reduced PR clutter
* Easier ownership
* Faster remediation cycle

⸻

2. Main Branch Daily Workflow

Nightly scheduled scans run against the main branch.

Main Branch
      |
      v
Nightly Trivy Scan
      |
      v
Rules Engine
      |
      v
Generate Fix
      |
      v
Create Remediation Branch
      |
      v
Create New Pull Request

Design Decision

A separate remediation Pull Request is created.

Benefits:

* Full audit trail
* Security review process
* No direct modification of main

⸻

Core Components

Trivy

Responsibilities:

* Scan Docker images
* Identify CVEs
* Report severity levels
* Provide fixed version information

Example:

{
  "PkgName": "openssl",
  "InstalledVersion": "3.0.2",
  "FixedVersion": "3.0.15",
  "Severity": "CRITICAL"
}

⸻

Remediation Service

Acts as the orchestration layer.

Responsibilities:

* Receive Trivy results
* Normalize vulnerability data
* Invoke Rules Engine
* Coordinate remediation process
* Trigger validation workflows
* Create GitHub commits and PRs

Suggested Technology:

* Python FastAPI

⸻

Rules Engine

The Rules Engine is the decision-making component.

Responsibilities:

* Determine eligibility for remediation
* Select remediation strategy
* Prevent unsafe modifications
* Generate explainable decisions

The Rules Engine does not modify code.

It only determines what action should be taken.

⸻

Rules Engine Layers

Layer 1 - Severity Filter

Only process:

HIGH
CRITICAL

Ignore:

LOW
MEDIUM

⸻

Layer 2 - Fixed Version Availability

Rule:

If FixedVersion exists
    Continue
Else
    Escalate

⸻

Layer 3 - Package Classification

Supported package types:

Base Images

Examples:

FROM ubuntu:22.04
FROM python:3.11.2
FROM node:18

OS Packages

Examples:

RUN apt-get install openssl
RUN apk add curl

⸻

Layer 4 - Remediation Strategy Selection

Apt Packages

Example:

RUN apt-get install openssl

Strategy:

APT_UPGRADE

⸻

Alpine Packages

Example:

RUN apk add openssl

Strategy:

APK_UPGRADE

⸻

Base Images

Example:

FROM python:3.11.2

Strategy:

UPDATE_BASE_IMAGE_TAG

⸻

Layer 5 - Risk Rules

Allowed

Patch upgrades:

3.0.2 -> 3.0.15

Escalated

Minor upgrades:

2.4.1 -> 2.8.0

Major upgrades:

2.x -> 3.x

⸻

Validation Pipeline

Every remediation must pass validation before a commit or Pull Request is generated.

Validation steps:

Docker Build
      |
      v
Unit Tests (optional)
      |
      v
Trivy Re-Scan

Requirements:

Build = PASS
Critical CVEs = 0
High CVEs = 0

Failure results in remediation abandonment.

⸻

GitHub Integration

Pull Request Branches

Auto-remediation commits are pushed directly to the developer branch.

Example:

feature/customer-api

Commit:

[AutoRemediation] Fix OpenSSL CVE

⸻

Main Branch Remediation

Branch created:

fix/cve-openssl-20260614

Pull Request:

Auto Remediation - OpenSSL CVE
Build: PASS
Trivy: PASS
Severity: CRITICAL
Package: openssl
Fixed Version: 3.0.15

⸻

Repository Structure

cve-remediation-engine/
├── app.py
├── parser.py
├── rules_engine.py
├── dockerfile_updater.py
├── validator.py
├── github_pr.py
│
├── rules/
│   ├── apt.yaml
│   ├── alpine.yaml
│   ├── base-image.yaml
│
└── tests/

⸻

Future Enhancements (Phase 2)

Phase 2 introduces AI-assisted remediation.

Additional Components:

Trivy
  |
  v
Remediation Service
  |
  +------------+
  |            |
  v            v
Rules Engine   LLM Advisor
  |            |
  +------------+
       |
       v
Validation
       |
       v
GitHub PR

AI responsibilities:

* Breaking change analysis
* Multiple remediation option selection
* Dependency conflict analysis
* Upgrade risk assessment
* Pull Request summarization

AI will never directly modify code without deterministic validation.

⸻

Success Criteria

The platform is considered successful when:

* Daily scans continuously monitor main branch vulnerabilities.
* Pull Requests are automatically remediated when safe fixes exist.
* Developers receive validated remediation commits.
* Security teams maintain full auditability.
* Critical and High vulnerabilities are remediated without manual intervention where safe and deterministic.

:::
This README is suitable as an architecture/design document for a GitHub repository, internal RFC, or architecture review board discussion.
