# MSI product-registration evidence

The approved Notepad++ MSI profile v6 adds a receipt-bound `importedMsiProductRegistration` event. The collector reads the `ProductCode` from the exact staged MSI, then queries that product's machine registration before and after installation. The request, scenario and installer hashes remain bound to the event. A ProductCode identifies a product; it does not independently identify an installed package revision or establish a required dependency.

The fixed collector runs only in the disposable guest. It opens `C:\AIW\Tools\application.msi` with [MsiOpenDatabaseW in read-only mode](https://learn.microsoft.com/en-us/windows/win32/api/msiquery/nf-msiquery-msiopendatabasew), executes one compiled-in Property-table query, and requires exactly one complete GUID. Database, view and record handles are closed before starting the installer. There is no caller-supplied SQL, property name, product enumeration, repair operation or host-side installer inspection through this collector. The guest's existing held-file verification binds the staged bytes before and after execution.

Registration uses [MsiGetProductInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msigetproductinfoexw), with `MSIINSTALLCONTEXT_MACHINE`, a null SID, and the fixed `State` property. This explicitly queries the machine context rather than inferring it from the collector's current user. Only fixed-size buffers and numeric error codes are retained.

| State | Interpretation |
|---|---|
| `notRegistered` | Windows Installer returned `ERROR_UNKNOWN_PRODUCT` for this machine-context query. Per-user registration is outside the query. |
| `advertised` | The machine product state is advertised. |
| `installed` | The machine product state is installed. |
| `unavailable` | The query failed or returned an unsupported value; `errorCode` records the Windows error or invalid-data result. This is unmeasured, not absence or installation. |

No state transition is required by the evidence contract: an already registered product or an unavailable query must remain visible. Malformed or unreadable MSI identity fails the before-install capture stage; it is not an application incompatibility verdict. Observations are not an atomic system snapshot. PackageCode comparison, package-cache verification, MSI feature/component dependencies, other uninstall metadata, per-user registration, and registration after application exercise remain outside this slice.

Successful v6 runs require exactly one correctly bound event, even if its query state is unavailable. A missing, duplicate, foreign or malformed event rejects the successful report after cleanup. Successful execution uses schema v0alpha6; the assessment uses v0alpha7. Report sets include the registration only when verified. Older v1-v5 profiles reject an unexpected product event and preserve absent fields and their original JSON report versions. Failed runs still retain completed file/registry captures; product-registration observations on failure remain unmeasured.

Use `aiw schema msi-product-registration` to export the contract. The [fixture record](FIXTURE-NOTEPAD-PLUS-PLUS-8.9.8.md#machine-product-registration-benchmark--2026-09-09) records the live transition and retained-report checks.
