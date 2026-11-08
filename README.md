# App Isolation Workbench

App Isolation Workbench (AIW) is a free, open-source project for evaluating Windows applications for readiness to be packaged using application isolation technologies. The goal is to assess any administrator-selected application, then help with adaptation, packaging, and testing where practical. It is intended to be application-agnostic, without a fixed catalog of supported products.

## Who it is for

AIW is intended for IT administrators, application packagers, and security practitioners evaluating applications they manage. The current builds are experimental and best suited to lab testing and contributors comfortable with early software.

## Goals

- Observe installation and real application use, including requirements and failures.
- Compare the same workflow with and without selected isolation restrictions.
- Keep results understandable, backed by inspectable evidence, and clear about what was not tested.
- Over time, help administrators adapt applications and create reusable launch profiles or packages, then validate them.

## Current state

AIW is in alpha development, with a Windows desktop app and an experimental CLI.

- The signed public alpha uses Notepad++ editing and Bambu Studio export as reference test cases for Windows Sandbox workflows.
- Recent development builds add a 7-Zip archive test case comparing ordinary-user and AppContainer execution inside Sandbox. Results can be reopened and exported for review.
- Automated coverage is limited to these implemented test cases today. They are development fixtures, not a supported-application catalog.
- Testing targets Windows 11 24H2 or later on x64, with Windows Sandbox enabled. End-to-end evidence remains specific to the tested versions and workflows.

General application assessment, broader isolation measurements, and general-purpose packaging remain unfinished. A passing workflow does not establish that an application is safe or that every isolation boundary is effective. Treat the current builds as research software, not a production-ready application isolation solution.

Execution requires explicit approval. There is no automatic telemetry.

## Learn more

- [Public alpha download](https://github.com/nathanmcnulty/app-isolation-workbench/releases/tag/desktop-alpha-4e39c787e63a): follow the included `START-HERE.md` for verification and setup. This release predates the newer development work described above.
- [Roadmap](docs/ROADMAP.md): direction and remaining work.
- [Architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT-MODEL.md): design and security boundaries.
- [Development guide](docs/DEVELOPMENT-WORKFLOW.md) and [contributing](CONTRIBUTING.md): working on the project.
- [Security policy](SECURITY.md): reporting vulnerabilities privately.

Licensed under the [Apache License 2.0](LICENSE).
