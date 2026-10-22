# Reviewed MSIX lifecycle evidence fixture

`worker107-r5.zip` is the exact read-only archive exported from disposable VM107
on 2026-10-22 after the completed signed Notepad++ research lifecycle. SHA-256:
`768e9ade771bbc3345067c82745c15f2d7c0ed31c4c8e281d437d14a27c321b3`;
285340 bytes, 118 entries. It was independently reviewed before being admitted by
the compiled `worker107NotepadR5` reader. See
[the lifecycle record](../../docs/NOTEPAD-MSIX-LIFECYCLE.md).

The archive contains project-owned receipts/scripts and retained Notepad++ XML
configuration data; it contains no MSIX, executable binary, private key, saved
credential, or account password. Lab account SIDs, VM identity, observed paths,
process metadata and public signing identity are intentionally retained as evidence.
The repository's project license applies to project-owned material. Notepad++
configuration material retains its upstream license, copied unchanged from the
signed package as `NOTEPAD-LICENSE.txt`. Upstream source/release:
https://github.com/notepad-plus-plus/notepad-plus-plus/releases/tag/v8.9.8.

Tests read entries in memory. They do not extract or execute scripts, install the
application, contact a hypervisor, or recreate the lab account. The archive is a
historical research observation, not a portable production assessment approval.
Do not replace it or update its checksum to make a failed/changed trial pass.
A new profile requires an independently reviewed source/input/run/cleanup record.
