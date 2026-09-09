# Scoped application registry observations

The fixed Notepad++ MSI v5 profile adds read-only registry snapshots before installation, after installation, and after the application closes. The profile version binds this capture requirement to preparation and approval. Older v1–v4 runs retain their original semantics and do not acquire registry evidence retroactively.

## Scope and identity

Capture is limited to `HKLM\Software\Notepad++` and `HKU\<runtime SID>\Software\Notepad++`, in explicit 64-bit and 32-bit registry views. The runtime SID must match the verified standard-user context and launched root-process token. The collector does not assume that its own `HKCU` belongs to the application user. Settings written only to the elevated installer account's user hive are outside this runtime-user scope. The views can share underlying keys on Windows; report both views without interpreting duplicate observations as separate dependencies.

This does not include Windows Installer product registration. MSI uninstall registration is keyed by ProductCode; the EXE installer's `Uninstall\Notepad++` location is not interchangeable. Capturing MSI registration requires binding the product identity to the approved installer first. Other registry roots, services, drivers, COM registrations, dependencies and runtime access tracing remain outside this slice.

## Evidence and limits

Snapshots record key presence, including empty keys; explicitly absent roots; and value names, numeric registry types, byte lengths and SHA-256 hashes of the original bytes. Raw value contents are neither serialized nor rendered. A hash is not anonymization: predictable values can be guessed, and names themselves may contain sensitive information. There is no automatic upload or telemetry.

Each phase is limited to 256 keys, 1,024 values, 64 KiB per value, 4 MiB of value bytes, depth 16 and ten seconds. Relative key paths are limited to 1,024 ASCII bytes and names to 256 printable ASCII bytes; unsupported names mark the scope incomplete rather than being normalized. The unnamed default value is represented by an empty name. Capture is bounded and read-only. Registry symbolic links, unreadable data, observed changes during enumeration and exhausted limits make the affected root/view incomplete. Registry snapshots are not atomic transactions; before/after checks detect some concurrent changes and do not prove that an adversarial process could not change and restore state. A snapshot difference is an observed state change, not proof that a registry entry is a required application dependency.

The separate `importedMsiRegistry` event binds all three phases and the runtime SID to the run, Sandbox session, request and scenario. Successful v5 execution requires the event, including explicit incompleteness where applicable. Missing, duplicate, foreign or malformed evidence is rejected. A passed capture stage means collection completed, not that all scopes were readable.

The completed report includes raw metadata snapshots and installation/use diffs. Diffs suppress scopes incomplete in either compared phase and list those scopes separately. Historical reports omit these fields; absence means unmeasured. Function results remain separate from the overall isolation verdict, which still requires independent boundary evidence and an eligible baseline/candidate comparison.

## Native API basis

The collector uses [RegOpenKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw) with explicit registry views and link handling. Microsoft describes [registry symbolic links](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/d5ce9dcc-1f90-4f5a-b076-cc1d2c9b4195) and the [Windows Installer uninstall registration contract](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key). Live fixture results, rather than API availability alone, establish what this implementation measured.
