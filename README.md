# HealthBridge Patient Portal

A HIPAA-compliant patient portal API built with FastAPI, demonstrating real-world healthcare application security patterns. Used as a demo project for the [thr8 PASTA Threat Model Generator](https://github.com/cybrking/thr8) GitHub Action.

## What This Demonstrates

This project is intentionally designed with a rich attack surface to showcase what `thr8` produces when run against a realistic healthcare application:

- **PHI handling** — Patient records, prescriptions, and visit notes stored with field-level encryption
- **Role-based access control** — patient / doctor / nurse / admin roles with enforcement at every endpoint
- **External integrations** — SureScripts pharmacy network, Twilio SMS, SendGrid email, DrugBank API, telehealth video
- **Infrastructure** — Terraform-provisioned AWS (RDS PostgreSQL, ElastiCache Redis, S3 with KMS, ECS Fargate)
- **Kubernetes deployment** — Network policies, pod security contexts, secrets management
- **HIPAA audit logging** — Immutable audit trail for all PHI access

## Stack

| Layer | Technology |
|---|---|
| API | FastAPI (Python 3.11) |
| Database | PostgreSQL 15 (RDS Multi-AZ) |
| Cache / Sessions | Redis 7 (ElastiCache) |
| File Storage | S3 + KMS encryption |
| Container | Docker / ECS Fargate |
| Orchestration | Kubernetes |
| IaC | Terraform |
| Auth | JWT + TOTP MFA |

## Running Locally

```bash
docker compose up
```

API available at `http://localhost:8000`  
Docs at `http://localhost:8000/docs`

## Threat Model

This repo uses `thr8` to auto-generate a PASTA threat model on every push to `main`.

See `.github/workflows/threat-model.yml` — the action scans this codebase and produces:
- `THREAT_MODEL.md` — full PASTA analysis with Mermaid data flow diagrams
- `threat-model.json` — machine-readable output
- `THREAT_MODEL.html` — stakeholder-ready report with executive summary

### Sample Output (what thr8 finds in this repo)

Running thr8 against this project surfaces threats including:
- PHI exfiltration via insecure S3 presigned URL scope
- JWT secret exposure through environment variable injection
- Drug interaction API key leakage in logs
- Telehealth room token reuse after session expiry
- RBAC bypass via role claim manipulation in JWT payload
- Redis session store poisoning for privilege escalation

## License

MIT
