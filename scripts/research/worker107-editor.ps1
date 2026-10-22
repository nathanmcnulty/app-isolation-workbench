#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$uuid='e5cecc90-35c2-4831-bf9c-424be23f7d4e'
if((Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $uuid -or $env:USERNAME -cne 'AiwStandardUser'){throw 'Worker107 interactive trial user required'}
$prepared=Get-Content -LiteralPath 'C:\AIW-Msix-Lifecycle-Preparation.json' -Raw|ConvertFrom-Json
$context=Get-Content -LiteralPath 'C:\AIW-Msix-Lifecycle-Output\standard-user-lifecycle\primary-context.json' -Raw|ConvertFrom-Json
if($prepared.vmId -cne $uuid -or $prepared.runNonce -cne $context.runNonce -or $prepared.userSid -cne $context.prepared.userSid){throw 'Prepared primary binding differs'}
$native=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'research_msix_native.cs') -Raw
$interactive=@(Get-Content -LiteralPath (Join-Path $PSScriptRoot 'research_msix_interactive.cs') | Where-Object {!$_.StartsWith('using ')}) -join "`n"
Add-Type -TypeDefinition ("using System.Diagnostics;`nusing System.Security.Principal;`n"+$native+"`n"+$interactive)
Add-Type -Path (Join-Path $PSScriptRoot 'worker107-editor-input.cs')
$observation=[AiwInteractiveNative]::ObserveCurrent()
[AiwInteractiveNative]::RequireOwnedStandardSession($observation,$prepared.userSid,$prepared.notBeforeFileTime,$prepared.notAfterFileTime)
if($observation.AuthenticationId -cne $context.authenticationId -or $observation.SessionId -ne $prepared.sessionId){throw 'Actual editor-control session differs'}
$evidence='C:\Users\AiwStandardUser\AppData\Local\AIW\msix-lifecycle'
$receipt=Join-Path $evidence 'ui-edit-started.json'
$f=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$f.Dispose()
$process=$null
try {
    $activated=Get-Content -LiteralPath (Join-Path $evidence 'activated.json') -Raw|ConvertFrom-Json
    $window=Get-Content -LiteralPath (Join-Path $evidence 'application-window.json') -Raw|ConvertFrom-Json
    $awaiting=Get-Content -LiteralPath (Join-Path $evidence 'awaiting-edit.json') -Raw|ConvertFrom-Json
    if($awaiting.document -ine (Join-Path $evidence 'document.txt') -or $window.processId -ne $activated.processId -or !$activated.identityVerifiedBeforeResume){throw 'Observed editor/document differs'}
    $process=[Diagnostics.Process]::GetProcessById($activated.processId);$null=$process.Handle
    if($process.StartTime.ToUniversalTime().ToString('o') -cne $activated.startTime -or $process.SessionId -ne $prepared.sessionId -or $process.MainModule.FileName -ine $activated.imagePath){throw 'Held editor generation differs'}
    $token=[AiwMsixNative]::Observe($process.Handle)
    if($token.UserSid -cne $prepared.userSid -or $token.PackageFullName -cne 'AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6' -or $token.IsElevated -or $token.AdministratorsEnabled -or $token.IsAppContainer -or $token.IntegritySid -cne 'S-1-16-8192'){throw 'Actual packaged editor token differs'}
    if((Get-FileHash -LiteralPath $activated.imagePath).Hash.ToLowerInvariant() -cne $activated.imageSha256){throw 'Editor image bytes differ'}
    [AiwOwnedEditorInput]::Edit([uint32]$process.Id,[IntPtr]([long]$window.window))
    if(!$process.WaitForExit(15000) -or $process.ExitCode -ne 0){throw 'Owned editor exit unconfirmed'}
    @{completed=$true;workflow='ownedForegroundKeyboardOpenAppendSaveClose';processId=$process.Id;applicationDataWrittenByHelper=$false;runNonce=$context.runNonce}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'ui-edit-result.json')
} catch {
    @{error=$_.Exception.Message;automaticRetry=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $evidence 'ui-edit-failure.json')
    throw
} finally {if($process){$process.Dispose()}}
