# ADR-007: SLSA L3 Release Pipeline with Cosign Keyless Signing

**Status:** Accepted | **Date:** 2025-01

## Context
The original release workflow had no artifact signing, no provenance, and no consumer verification path. This creates supply-chain risk (SLSA L0).

## Decision
- Python wheel signed via `slsa-github-generator` (SLSA L3 trusted builder).
- Container image signed with Cosign keyless (GitHub OIDC → Rekor transparency log).
- GitHub artifact attestations API used for container provenance.
- SBOM attached to every release as `sbom.json`.
- Release notes include copy-paste verification commands.

## Consequences
- Consumers can verify artifact authenticity before installation.
- No long-lived signing keys required (OIDC-based — ephemeral certificates).
- Rekor provides non-repudiation: signatures are publicly auditable.
- CI runtime increases ~3 minutes for release jobs.

## Rollback
- Remove `slsa-provenance` and signing steps from `release.yml`.
- Existing releases remain valid (no retroactive revocation).
