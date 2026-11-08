# Documentation guide

Current direction was reconciled on 2026-11-08. Use these documents together:

- [Roadmap](ROADMAP.md): product decision, intended administrator journey,
  R0-R6 milestones, coverage and provider priorities.
- [Architecture](ARCHITECTURE.md): implemented components versus target contracts,
  authority, evidence, execution and recovery boundaries.
- [Application-neutral migration audit](APPLICATION-AGNOSTIC-MIGRATION.md):
  concrete source coupling, replacement/deletion checklist and validation.
- [Release gates](RELEASE-GATES.md): generic-engine, operator and AIW-only
  distribution acceptance. Optional packaging is a separate gate.
- [Repository scope](REPOSITORY-SCOPE.md): first-party distribution and license limits.
- [Working state](WORKING-STATE.md) and [execution plan](EXECUTION-PLAN.md):
  current source pointers and next bounded implementation slice.
- [Installer corpus](INSTALLER-CORPUS.md): representative generic regression inputs,
  not a supported-app catalog; acquisition stays outside source distribution.
- [Development workflow](DEVELOPMENT-WORKFLOW.md) and [threat model](THREAT-MODEL.md):
  required working practices and preserved safety constraints.

## Contract and evidence documents

Detailed intake, approval, reports, Results, package, cleanup and provider records
remain useful for their explicitly recorded source/schema/workflow. Read their
status and exact evidence scope before using them. Schema availability does not
imply generic execution support; an old success does not establish a new claim.

Documents named for Notepad++, Bambu, 7-Zip, fixed paired controls, earlier preview
finish lines, dated reviews and VM handoffs are scoped implementation/evidence
records. Their fixed product choices, copied operator commands and future-tense
plans do not supersede the roadmap or grant execution authorization. Retained
product-specific APIs may still exist while migration is unfinished.

The [previous roadmap](ROADMAP-HISTORY-2026-11-06.md),
[preview release gates](RELEASE-GATES-HISTORY-2026-11-08.md) and
[preview execution packets](EXECUTION-PLAN-HISTORY-2026-11-08.md) preserve old
milestones and evidence links. They are not current supported-product promises,
publication instructions or prerequisites for generic assessment.
