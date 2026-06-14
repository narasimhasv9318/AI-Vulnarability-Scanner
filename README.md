# Automated CVE Remediation Platform

## Overview

The Automated CVE Remediation Platform is a DevSecOps solution that continuously scans container images for vulnerabilities and automatically proposes remediation through GitHub Pull Requests.

The platform leverages Trivy for vulnerability detection and a deterministic Rules Engine to safely remediate known vulnerabilities without requiring AI-generated code modifications.

Phase 1 focuses on Docker images and Dockerfiles, ensuring security improvements are auditable, repeatable, and governed.

---

## Objectives

- Detect container vulnerabilities using Trivy
- Continuously scan GitHub repositories
- Automatically remediate High and Critical vulnerabilities
- Validate fixes through rebuild and re-scan
- Generate Pull Requests with remediation changes
- Maintain developer ownership and governance
- Reduce Mean Time To Remediate (MTTR)

---

## Architecture

```text
                          GitHub Repository
                                  |
                                  |
                +-----------------+-----------------+
                |                                   |
                |                                   |
          Pull Request                       Daily Main Scan
                |                                   |
                v                                   v
          GitHub Actions                     GitHub Actions
                |                                   |
                +-----------------+-----------------+
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
```

---

## Solution Components

### Trivy

Responsible for vulnerability detection.

Example output:

```json
{
  "PkgName": "openssl",
  "InstalledVersion": "3.0.2",
  "FixedVersion": "3.0.15",
  "Severity": "CRITICAL"
}
```

Responsibilities:

- Scan Docker images
- Detect vulnerabilities
- Provide fixed version recommendations
- Generate machine-readable reports

---

### Remediation Service

Acts as the orchestration layer.

Responsibilities:

- Parse Trivy reports
- Normalize vulnerability information
- Invoke Rules Engine
- Trigger remediation workflows
- Coordinate validation
- Create commits and Pull Requests

Suggested implementation:

```text
Python FastAPI
```

---

### Rules Engine

The Rules Engine determines whether a vulnerability can be automatically remediated.

Responsibilities:

- Evaluate remediation eligibility
- Select remediation strategy
- Prevent unsafe upgrades
- Generate explainable decisions

The Rules Engine does not modify code.

It only determines what action should be taken.

---

### Dockerfile Updater

Responsible for applying remediation actions to source code.

Examples:

#### Base Image Upgrade

Before:

```dockerfile
FROM python:3.11.2
```

After:

```dockerfile
FROM python:3.11.9
```

#### Package Upgrade

Before:

```dockerfile
RUN apt-get install -y openssl
```

After:

```dockerfile
RUN apt-get update && apt-get upgrade -y
```

---

## Workflow Design

### Pull Request Workflow

When a developer creates a Pull Request:

```text
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
```

### Design Decision

The remediation engine updates the same feature branch.

No additional Pull Request is created.

Benefits:

- Single review experience
- Reduced Pull Request clutter
- Maintains developer ownership
- Easier audit trail

---

### Main Branch Workflow

A scheduled scan runs daily against the main branch.

```text
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
Create Pull Request
```

### Design Decision

A new remediation Pull Request is created.

Benefits:

- Security review process
- Full auditability
- No direct modification of main branch

---

## Rules Engine Design

### Layer 1 - Severity Filtering

Process only:

```text
HIGH
CRITICAL
```

Ignore:

```text
LOW
MEDIUM
```

---

### Layer 2 - Fixed Version Availability

Rule:

```text
IF FixedVersion Exists
    Continue
ELSE
    Escalate
```

---

### Layer 3 - Package Classification

#### Base Images

Examples:

```dockerfile
FROM ubuntu:22.04
FROM python:3.11.2
FROM node:18
```

#### OS Packages

Examples:

```dockerfile
RUN apt-get install openssl
RUN apk add curl
```

---

### Layer 4 - Strategy Selection

#### Apt Packages

```text
Strategy: APT_UPGRADE
```

#### Alpine Packages

```text
Strategy: APK_UPGRADE
```

#### Base Images

```text
Strategy: UPDATE_BASE_IMAGE_TAG
```

---

### Layer 5 - Risk Evaluation

#### Allowed

Patch upgrades:

```text
3.0.2 -> 3.0.15
```

#### Escalated

Minor upgrades:

```text
2.4.1 -> 2.8.0
```

Major upgrades:

```text
2.x -> 3.x
```

---

## Validation Pipeline

Every remediation must pass validation before being committed.

```text
Build Image
    |
    v
Execute Tests
    |
    v
Trivy Re-Scan
    |
    v
Create Commit / PR
```

### Validation Requirements

```text
Docker Build = PASS
Critical CVEs = 0
High CVEs = 0
```

If validation fails:

```text
Remediation Abandoned
Manual Review Required
```

---

## Repository Structure

```text
cve-remediation-engine/
│
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
├── tests/
│
└── README.md
```

---

## Example End-to-End Flow

### Input

Dockerfile:

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y openssl
```

Trivy Result:

```json
{
  "PkgName": "openssl",
  "InstalledVersion": "3.0.2",
  "FixedVersion": "3.0.15",
  "Severity": "CRITICAL"
}
```

### Decision

```json
{
  "action": "UPDATE_PACKAGE",
  "strategy": "APT_UPGRADE",
  "confidence": "HIGH"
}
```

### Remediation

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y openssl
```

### Validation

```text
Build: PASS
Trivy Scan: PASS
Critical CVEs: 0
High CVEs: 0
```

### Outcome

```text
Pull Request Updated
```

or

```text
New Remediation Pull Request Created
```

---

## Future Roadmap (Phase 2)

Introduce AI-assisted decision making.

```text
Trivy
  |
  v
Remediation Service
  |
  +----------------+
  |                |
  v                v
Rules Engine    LLM Advisor
  |                |
  +----------------+
          |
          v
Validation
          |
          v
GitHub PR
```

AI Responsibilities:

- Breaking change analysis
- Upgrade risk assessment
- Dependency conflict analysis
- Multiple remediation option evaluation
- Pull Request summarization

AI will never directly merge code without validation.

---

## Success Criteria

- Daily vulnerability scans on main branch
- Vulnerability scanning on every Pull Request
- Automated remediation for eligible vulnerabilities
- Validation before code changes
- Pull Request generation for review
- Full auditability and governance
- Reduced security remediation effort
