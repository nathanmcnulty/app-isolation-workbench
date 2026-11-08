# App Isolation Workbench

App Isolation Workbench (AIW) is a free, open-source project for assessing Windows applications and exploring how they behave under isolation. It aims to help administrators understand what an application needs, which everyday tasks still work with restrictions, and where testing leaves unanswered questions.

## Who it is for

AIW is intended for IT administrators, application packagers, and security practitioners evaluating applications they manage. The current builds are experimental and best suited to lab testing and contributors comfortable with early software.

## Goals

- Observe installation and real application use, including requirements and failures.
- Compare the same workflow with and without selected isolation restrictions.
- Keep results understandable, backed by inspectable evidence, and clear about what was not tested.
- Over time, help administrators adapt applications and create reusable launch profiles or packages, then validate them.

## Current state

AIW is in alpha development, with a Windows desktop app and an experimental CLI.

- The signed public alpha supports a small set of fixed Windows Sandbox workflows, including Notepad++ editing and Bambu Studio export.
- Recent development builds also compare a fixed 7-Zip archive workflow as an ordinary user and in AppContainer, both inside Sandbox. Results can be reopened and exported for review.
- Testing targets Windows 11 24H2 or later on x64, with Windows Sandbox enabled. Support remains specific to the tested application versions and workflows.

Broader application coverage, isolation measurements, and general-purpose packaging remain unfinished. A passing workflow does not establish that an application is safe or that every isolation boundary is effective. Treat the current builds as research software, not a production-ready application isolation solution.

Execution requires explicit approval. There is no automatic telemetry.

## Learn more

- [Public alpha download](https://github.com/nathanmcnulty/app-isolation-workbench/releases/tag/desktop-alpha-4e39c787e63a): follow the included `START-HERE.md` for verification and setup. This release predates the newer development work described above.
- [Roadmap](docs/ROADMAP.md): direction and remaining work.
- [Architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT-MODEL.md): design and security boundaries.
- [Development guide](docs/DEVELOPMENT-WORKFLOW.md) and [contributing](CONTRIBUTING.md): working on the project.
- [Security policy](SECURITY.md): reporting vulnerabilities privately.

Licensed under the [Apache License 2.0](LICENSE).
