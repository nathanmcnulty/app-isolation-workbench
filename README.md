# App Isolation Workbench

App Isolation Workbench (AIW) is a free, open-source testing workbench for Windows applications. Its goal is to help administrators evaluate an application they supply, compare ordinary and isolated behavior, and understand what would be needed to adapt, package, and validate it.

The workbench is intended to be application-agnostic. It is not an application store or a collection of repackaged third-party applications.

## Goals

- Observe installation and real application use, including requirements and failures.
- Compare the same workflow with and without selected isolation restrictions.
- Keep results understandable, backed by inspectable evidence, and explicit about what was not tested.
- Provide useful assessment before optional adaptation, launch profiles, or packaging.

Users obtain applications from their publishers and keep installers, application files, and generated packages outside this repository. AIW does not grant redistribution rights for those applications.

## Current state

AIW is experimental alpha software with a Windows desktop app and CLI. General-purpose assessment and packaging are unfinished: the existing implementation still relies on fixed application-specific adapters. The [recovery roadmap](docs/ROADMAP.md) replaces them with one capability-based workflow, then retires their execution paths. Unknown application names must not become gates, and exact payloads still bind each approved run. This migration is not yet implemented; [repository scope](docs/REPOSITORY-SCOPE.md) records the distribution boundary.

Testing has included Notepad++, Bambu Studio, and 7-Zip. These are historical test subjects, not products distributed or endorsed by this project and not a supported-application catalog. Previous results apply only to their recorded versions, inputs, and workflows.

Testing targets Windows 11 24H2 or later on x64. Execution requires explicit approval and disposable Windows workers. There is no automatic telemetry. A passing workflow is not proof that an application is safe or that every isolation boundary is effective.

## Learn more

- [Roadmap](docs/ROADMAP.md): intended administrator journey, staged recovery, and acceptance criteria.
- [Documentation guide](docs/README.md): current plans and historical evidence.
- [Architecture](docs/ARCHITECTURE.md) and [threat model](docs/THREAT-MODEL.md): design and security boundaries.
- [Development guide](docs/DEVELOPMENT-WORKFLOW.md) and [contributing](CONTRIBUTING.md): working on the project.
- [Security policy](SECURITY.md): reporting vulnerabilities privately.

## License

Project-owned code and assets are released under the [Unlicense](LICENSE). Third-party dependencies retain their own licenses. This does not relicense external applications, their content, or earlier releases; see the [license scope](docs/REPOSITORY-SCOPE.md#license-scope).
