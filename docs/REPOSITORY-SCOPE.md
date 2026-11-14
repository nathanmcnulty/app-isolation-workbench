# Repository and distribution scope

AIW is a testing workbench for administrator-selected Windows applications. It
should publish its own tools, generic contracts, project-owned controls, and
text describing what was tested. It is not a source for third-party installers,
application packages, extracted vendor files, configuration, or product-specific
bundles. Users acquire applications from their publishers, supply local inputs,
and keep those inputs and generated packages outside the repository.

## Distribution cleanup

- The retained application-configuration archive and its vendor license file are
  removed from the current tree. Synthetic project-owned receipts exercise the
  shared verifier; tests that require exact historical native bytes are explicit
  external-fixture tests. Synthetic data is not native acceptance evidence.
- The hosted workflow that downloaded, assembled, signed, and uploaded a
  third-party application MSIX is removed, along with its assembly builder/test.
- The desktop builder that embedded a third-party installer is removed.
- The existing desktop candidate workflow is paused at every job. Its release
  layout still contains fixed application assets and must be replaced and
  reviewed before publication resumes. No old release, remote artifact, or Git
  history is deleted or relabeled by this change.
- `scripts/verify-repository-content.ps1` rejects installers and opaque archives
  in tracked/non-ignored source, including common payload signatures hidden by a
  renamed extension. Ignore rules are an aid, not the enforcement mechanism.
  This source check does not audit historical commits, remote releases, or every
  possible encoded payload. Review remains necessary.

## Implementation gap

The current desktop and CLI still contain fixed application-specific adapters,
recipes, package creation, and report readers. They are not a generic assessment
engine, and retaining them is not completion of this scope change. No new fixed
application adapters or product bundles should be added.

The decision is to build one generic replacement on the existing intake,
source/scenario, approval, execution and evidence mechanisms, then retire
product-specific execution after its reusable safety behavior and regression
coverage transfer. See the [staged roadmap](ROADMAP.md) and
[source/deletion inventory](APPLICATION-AGNOSTIC-MIGRATION.md). Assessment comes
before optional packaging; unknown application names are not admission gates,
while exact input hashes and capability checks remain mandatory.

Existing fixed paths remain legacy migration code, not the general engine. Keep
historical evidence readers and narrowly authorized recovery separate from new
execution/publication. Do not erase original receipts or reinterpret absent
observations as new proof. Removal must not strand retained evidence or weaken
held-file, approval/session, receipt-last or exact-cleanup safeguards.

Older application-specific documents remain text records, not current product
promises or permission to redistribute their inputs. Earlier test results are
unchanged; the cleanup adds no live compatibility or isolation result.

## License scope

The root [Unlicense](../LICENSE) applies to project-owned original code, scripts,
documentation, and assets from this change onward. Rust metadata in the main and
GUI workspaces and contribution terms use the same license. Contributors must
have the right to make that dedication; commit authorship alone does not prove
ownership of employer, contractor, copied, or third-party material.

Third-party dependencies keep their own licenses, notices, and applicable
source-distribution obligations. Tested applications and their data are not
relicensed. Before distributing compiled AIW binaries, review the resolved
licenses and notices for the actual target/features in both workspaces; a
vulnerability scan and a lockfile are not a complete license audit.

Existing Apache-2.0 grants and historical third-party terms are not revoked or
erased. Prior releases are not retroactively offered solely under the Unlicense.
The Unlicense does not reproduce Apache-2.0's express patent license and
termination provisions.
