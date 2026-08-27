# Security policy

## Current status

App Isolation Workbench is pre-alpha, free and open-source research software under the [Apache License 2.0](LICENSE). It must not be treated as a production security boundary, application allowlisting system, packaging authority, or evidence attestation service. The initial target is Windows 11 24H2 x64; live provider support is not present in the current release.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's private vulnerability reporting feature. If that feature is unavailable, contact the repository owner privately before disclosure. Do not open a public issue containing exploit details, credentials, customer evidence, installer payloads, or signing material.

## Non-negotiable boundaries

- Never commit signing keys, certificates containing private keys, customer installers, ETL/EVTX captures, secrets, or unredacted evidence bundles.
- Never add an arbitrary command, script, path, registry, URL, or query execution verb to a privileged helper.
- Treat project files, installer metadata, evidence fields, model output, and knowledge-pack content as untrusted input.
- Do not make an AI provider part of an authorization, assertion, signing, installation, or deployment decision.
- Security claims require an effective-backend record, target-token evidence, canary assertions, evidence completeness, and cleanup evidence.
- Unsupported, degraded, incomplete, or ambiguous behavior must remain `insufficientEvidence`; it must not be promoted to a successful isolation recommendation.
- Do not add telemetry, a persistent privileged service, automatic Windows feature/provider installation, or automation of Master Packager.

## Supported versions

There are no supported releases yet. Security fixes are applied to the latest development branch. Hosted CI checks contracts and code, not live containment; provider claims require separately documented Windows 11 24H2 x64 evidence.

## Scope and disclosure

The Workbench milestone covers assessment and on-demand replay of validated profiles. The Studio milestone adds MSIX authoring, remediation, signing, and final-package validation. Neither milestone authorizes arbitrary commands or claims that packaging alone creates an isolation boundary. See [the threat model](docs/THREAT-MODEL.md) for required controls and [CONTRIBUTING.md](CONTRIBUTING.md) for safe contribution practices.
