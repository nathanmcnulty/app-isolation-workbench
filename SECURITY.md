# Security policy

## Current status

App Isolation Workbench is pre-alpha research software. It must not be treated as a production security boundary, application allowlisting system, packaging authority, or evidence attestation service.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the repository owner through GitHub's private vulnerability reporting feature once it is enabled. Do not open a public issue containing exploit details, credentials, customer evidence, installer payloads, or signing material.

## Non-negotiable boundaries

- Never commit signing keys, certificates containing private keys, customer installers, ETL/EVTX captures, secrets, or unredacted evidence bundles.
- Never add an arbitrary command, script, path, registry, URL, or query execution verb to a privileged helper.
- Treat project files, installer metadata, evidence fields, model output, and knowledge-pack content as untrusted input.
- Do not make an AI provider part of an authorization, assertion, signing, installation, or deployment decision.
- Security claims require an effective-backend record, target-token evidence, canary assertions, evidence completeness, and cleanup evidence.

## Supported versions

There are no supported releases yet. Security fixes are applied only to the latest private development branch.
