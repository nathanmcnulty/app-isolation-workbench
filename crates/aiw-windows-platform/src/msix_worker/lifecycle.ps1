#Requires -Version 7.6
#Requires -PSEdition Core
$SignedSha256='2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437'
$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Fixed approved disposable-VM MSIX workflow.
if($env:USERNAME -cne 'AiwStandardUser'){throw 'Fixed Sandbox standard user required'}
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
if($session -eq 0 -or $identity.Name -notmatch '\\AiwStandardUser$'){throw 'Interactive standard-user session required'}
$root=Join-Path $PSScriptRoot 'input'
$request=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'request.json') -Raw|ConvertFrom-Json
Assert-AiwWorkerRuntimeIdentity $AiwPowerShellRuntime $request.powerShellRuntime
$account=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'account.json') -Raw|ConvertFrom-Json
if($request.workerUuid -cne 'e5cecc90-35c2-4831-bf9c-424be23f7d4e' -or (Get-CimInstance Win32_ComputerSystemProduct).UUID -ine $request.workerUuid -or $identity.User.Value -cne $account.userSid -or $account.runNonce -cne $request.nonce -or [DateTime]::UtcNow.ToFileTimeUtc() -ge $request.notAfterFileTime){throw 'Approved worker/account/request interval differs'}
$evidence=Join-Path $env:LOCALAPPDATA ('AIW\msix-'+$request.nonce+'\msix-lifecycle')
if(Test-Path -LiteralPath $evidence){throw 'Fresh lifecycle evidence required; diagnose retained attempt before retry'}
New-Item -ItemType Directory -Path $evidence|Out-Null
function Record([string]$Name,$Value){$bytes=[Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Value -Depth 12));$file=[IO.File]::Open((Join-Path $evidence ($Name+'.json')),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}}
function Hash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function ConfigSnapshot([string]$Family){
 $paths=@((Join-Path $env:APPDATA 'Notepad++'),(Join-Path $env:LOCALAPPDATA 'Notepad++'))
 if($Family){$paths+=@((Join-Path $env:LOCALAPPDATA ('Packages\'+$Family+'\LocalCache\Roaming\Notepad++')),(Join-Path $env:LOCALAPPDATA ('Packages\'+$Family+'\LocalCache\Local\Notepad++')))}
 $values=@()
 foreach($path in $paths){
  if(!(Test-Path -LiteralPath $path)){continue}
  $files=@(Get-ChildItem -LiteralPath $path -Filter '*.xml' -File)
  if($files.Count -gt 32){throw 'Configuration inventory exceeds research bound'}
  foreach($file in $files){if($file.Length -gt 4MB -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Configuration file refused'};$values += [pscustomobject]@{path=$file.FullName;sizeBytes=$file.Length;sha256=(Hash $file.FullName)}}
 }
 $totalBytes=0L
 foreach($value in $values){$totalBytes += $value.sizeBytes}
 if($values.Count -gt 16 -or $totalBytes -gt 16MB){throw 'Combined configuration snapshot bound exceeded'}
 return $values
}
$held=$null;$ownedProcess=$null;$suspended=$null;$activatedPid=$null;$installedFullName=$null;$stage='preflight'
try {


 $current=[Diagnostics.Process]::GetCurrentProcess()
 try {$operatorToken=[AiwMsixNative]::Observe($current.Handle);$supervisorInJob=[AiwMsixNative]::InJob($current.Handle);$supervisorImage=$current.MainModule.FileName;$supervisorStart=$current.StartTime.ToUniversalTime().ToString('o')}finally{$current.Dispose()}
 if(!$supervisorInJob -or $supervisorImage -ine 'C:\Program Files\PowerShell\7\pwsh.exe'){throw 'Fixed PowerShell supervisor job/image mismatch'}
 if($operatorToken.IsElevated -or $operatorToken.AdministratorsEnabled -or $operatorToken.IsAppContainer -or $operatorToken.TokenSessionId -ne $session -or $operatorToken.IntegritySid -cne 'S-1-16-8192' -or $operatorToken.UserSid -cne $identity.User.Value -or $env:USERPROFILE -cne 'C:\Users\AiwStandardUser'){throw 'Non-elevated standard-user context required'}
 Record 'worker' ([ordered]@{computer=$env:COMPUTERNAME;powerShellRuntime=$AiwPowerShellRuntime;supervisorPid=$PID;supervisorImage=$supervisorImage;supervisorStart=$supervisorStart;inInheritedJob=$supervisorInJob;sessionId=$session;operator=$identity.Name;operatorSid=$identity.User.Value;operatorToken=$operatorToken;windowsBuild=[Environment]::OSVersion.Version.ToString();time=[DateTime]::UtcNow.ToString('o');researchOnly=$false})
 $preexistingPackages=@(Get-AppxPackage -Name AIWResearch.NotepadPP|Select-Object Name,PackageFullName,PackageFamilyName,Version,Publisher,InstallLocation,PackageUserInformation)
 $preexistingProcesses=@(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue|ForEach-Object {
  $imagePath=$null;$startTime=$null;$queryError=$null
  try{$imagePath=$_.MainModule.FileName;$startTime=$_.StartTime.ToUniversalTime().ToString('o')}catch{$queryError=$_.Exception.Message}
  [pscustomobject]@{pid=$_.Id;sessionId=$_.SessionId;imagePath=$imagePath;startTime=$startTime;queryError=$queryError}
 })
 Record 'preflight-inventory' @{packages=$preexistingPackages;processes=$preexistingProcesses}
 if($preexistingPackages.Count -ne 0 -or $preexistingProcesses.Count -ne 0){throw 'Preexisting application registration or process refused'}
 $packageProcesses=Get-AiwPackageProcessInventory
 $packageProcesses|Add-Member -NotePropertyName queryAuthority -NotePropertyValue 'applicationUserDiagnostic'
 $packageProcesses|Add-Member -NotePropertyName globalAbsenceVerified -NotePropertyValue $false
 Record 'package-processes-before' $packageProcesses
 if($packageProcesses.matches.Count -ne 0 -or @($packageProcesses.queryErrors|Where-Object name -ieq 'notepad++').Count -ne 0){throw 'Preflight application candidate refused'}
 Invoke-AiwDriverControl -EvidenceDirectory (Join-Path $evidence 'driver-control')|Out-Null
 $control=Get-Content (Join-Path $evidence 'driver-control\control.json') -Raw|ConvertFrom-Json
 if(!$control.passed){throw 'Driver control failed'}
 Record 'driver-controls-completed' @{controlsPassed=$true;applicationTrialStarted=$false}
 $package=Join-Path $root 'application.msix'
 $held=[IO.File]::Open($package,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $sha=[Security.Cryptography.SHA256]::Create()
 try {$actual=([BitConverter]::ToString($sha.ComputeHash($held))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose();$held.Position=0}
 if($actual -cne $SignedSha256){throw 'Signed package bytes differ'}
 $signature=Get-AuthenticodeSignature -LiteralPath $package
 $publisher='CN=Nathan McNulty, O=Nathan McNulty, L=Soldotna, S=Alaska, C=US'
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -cne $publisher -or $null -eq $signature.TimeStamperCertificate){throw 'Package publisher/signature/timestamp refused'}
 $assembly=Get-Content (Join-Path $root 'assembly.json') -Raw|ConvertFrom-Json
 $signing=Get-Content (Join-Path $root 'signing.json') -Raw|ConvertFrom-Json
 if($signing.signedSha256 -cne $SignedSha256 -or $assembly.source.sha256 -cne 'b269383239464a945d17cfabfccf53935b83d80d907922310fdfd50d80274c66' -or $assembly.publisher -cne $publisher){throw 'Assembly/signing binding differs'}
 $beforeConfig=@(ConfigSnapshot '')
 Record 'config-before' $beforeConfig
 if($beforeConfig.Count -ne 0){throw 'Fresh worker configuration required'}
 Record 'package-input' ([ordered]@{signedSha256=$actual;sizeBytes=$held.Length;publisher=$publisher;sourceRevision=$signing.sourceRevision;sourceSha256=$assembly.source.sha256;driverSource='approved fixed VM MSIX worker';signatureStatus=$signature.Status.ToString();signerThumbprint=$signature.SignerCertificate.Thumbprint;timestampThumbprint=$signature.TimeStamperCertificate.Thumbprint})
 $stage='install'
 Record 'install-started' @{time=[DateTime]::UtcNow.ToString('o')}
 Add-AppxPackage -Path $package -ErrorAction Stop
 $packages=@(Get-AppxPackage -Name AIWResearch.NotepadPP)
 Record 'post-install-inventory' @($packages|Select-Object Name,PackageFullName,PackageFamilyName,Version,Publisher,Architecture,InstallLocation,Status)
 if($packages.Count -ne 1){throw 'Exact installed registration absent'}
 $installed=$packages[0]
 $installedFullName=$installed.PackageFullName
 $location=$installed.InstallLocation
 if(!$location){throw 'Installed path absent'}
 if($installed.Version.ToString() -cne '8.9.8.0' -or $installed.Publisher -cne $publisher -or $installed.Architecture.ToString() -ine 'X64'){throw 'Installed package identity differs'}
 $manifest=Get-AppxPackageManifest -Package $installedFullName
 $manifest.Save((Join-Path $evidence 'installed-manifest.xml'))
 $manifestBeforeHash=Hash (Join-Path $location 'AppxManifest.xml')
 Record 'manifest-before' @{sha256=$manifestBeforeHash}
 Record 'installed' ([ordered]@{packageFullName=$installedFullName;packageFamilyName=$installed.PackageFamilyName;installLocation=$location;version=$installed.Version.ToString();publisher=$installed.Publisher;status=$installed.Status.ToString()})
 $family=$installed.PackageFamilyName
 $fullBefore=@(ConfigSnapshot $family)
 Record 'config-installed-before-launch' $fullBefore
 if($fullBefore.Count -ne 0){throw 'Preexisting package configuration refused'}
 $payloadBefore=@()
 foreach($file in $assembly.payloadInventory){$path=Join-Path $location $file.path;if((Hash $path) -cne $file.sha256){throw ('Installed payload differs: '+$file.path)};$payloadBefore += [pscustomobject]@{path=$file.path;sha256=$file.sha256}}
 Record 'payload-before' $payloadBefore
 $document=Join-Path $evidence 'document.txt'
 $initial="AIW MSIX package lifecycle`r`n"
 $expected=$initial+"AIW packaged validation`r`n"
 [IO.File]::WriteAllText($document,$initial,(New-Object Text.UTF8Encoding($false)))
 Record 'document-input' @{path=$document;sha256=(Hash $document);sizeBytes=(Get-Item $document).Length}
 $stage='activation'
 $activationStarted=[DateTime]::UtcNow
 $suspended=[AiwSuspendedNotepad]::Create()
 $activatedPid=$suspended.Pid
 $ownedProcess=[Diagnostics.Process]::GetProcessById([int]$activatedPid)
 $null=$ownedProcess.Handle
 $heldProcessHandle=$suspended.Handle
 $observation=[AiwMsixNative]::Observe($heldProcessHandle)
 $applicationId=[AiwMsixNative]::ApplicationId($heldProcessHandle)
 $applicationInJob=[AiwMsixNative]::InJob($heldProcessHandle)
 if($applicationInJob -isnot [bool] -or !$applicationInJob){throw 'Application must inherit the owned worker job'}
 $image=[AiwMsixNative]::ImagePath($heldProcessHandle)
 $actualImageHash=Hash $image
 $expectedImage=@($assembly.payloadInventory|Where-Object {$_.path -ceq 'Application/notepad++.exe'})
 if($expectedImage.Count -ne 1){throw 'Unique fixed executable inventory required'}
 Record 'activation-suspended' ([ordered]@{processId=$activatedPid;sessionId=$ownedProcess.SessionId;startTime=$ownedProcess.StartTime.ToUniversalTime().ToString('o');imagePath=$image;imageSha256=$actualImageHash;packageObservation=$observation;applicationUserModelId=$applicationId;inAnyJob=$applicationInJob;launchMethod='fixedInstalledExecutableSuspended'})
 if($applicationId -cne 'AIWResearch.NotepadPP_q1fhfzcjv9wt6!Notepad'){throw 'Suspended application identity differs'}
 if($actualImageHash -cne $expectedImage[0].sha256 -or $observation.PackageFullName -cne 'AIWResearch.NotepadPP_8.9.8.0_x64__q1fhfzcjv9wt6' -or $observation.PackageFullName -cne $installedFullName -or $observation.UserSid -cne $identity.User.Value -or $observation.IsElevated -or $observation.AdministratorsEnabled -or $observation.IsAppContainer -or $observation.TokenSessionId -ne $session -or $observation.TokenSessionId -ne $ownedProcess.SessionId -or $observation.IntegritySid -cne 'S-1-16-8192' -or $ownedProcess.SessionId -ne $session -or $ownedProcess.StartTime.ToUniversalTime() -lt $activationStarted -or $image -ine (Join-Path $location 'Application\notepad++.exe')){throw 'Actual package identity, image path or medium non-elevated token differs'}
 Record 'activated' ([ordered]@{processId=$activatedPid;sessionId=$ownedProcess.SessionId;startTime=$ownedProcess.StartTime.ToUniversalTime().ToString('o');imagePath=$image;imageSha256=$actualImageHash;packageObservation=$observation;applicationUserModelId=$applicationId;inAnyJob=$applicationInJob;identityVerifiedBeforeResume=$true;launchMethod='fixedInstalledExecutableSuspended'})
 $suspended.Resume()
 Record 'activation-returned' @{processId=$activatedPid;packageFamilyName=$family;launchMethod='fixedInstalledExecutableSuspended';resumed=$true}
 $windowDeadline=[DateTime]::UtcNow.AddSeconds(20)
 do{$ownedProcess.Refresh();$window=$ownedProcess.MainWindowHandle;if([AiwMsixNative]::VisibleOwnedWindow($window,$activatedPid)){break};if($ownedProcess.HasExited){throw 'Owned application exited before window'};Start-Sleep -Milliseconds 100}while([DateTime]::UtcNow -lt $windowDeadline)
 if(![AiwMsixNative]::VisibleOwnedWindow($window,$activatedPid)){throw 'Visible owned application window absent'}
 if(@(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue).Count -ne 1){throw 'Unexpected additional application process'}
 Record 'application-window' @{processId=$activatedPid;window=$window.ToInt64();visible=$true;ownedProcessHandle=$true}
 $stage='document-workflow'
 Record 'awaiting-edit' @{document=$document;task='Open document.txt in the observed packaged Notepad++, append AIW packaged validation followed by Enter, save and close Notepad++';deadlineSeconds=900}
 Write-Host ('Open '+$document+' in the packaged Notepad++. Append AIW packaged validation, press Enter, save and close the editor.')
 if(!$ownedProcess.WaitForExit(900000)){throw 'Owned editor deadline reached; inspect retained stage before recovery'}
 $code=$ownedProcess.get_ExitCode()
 if($code -isnot [int]){throw 'Held editor exit code absent'}
 Record 'editor-exit' @{processId=$activatedPid;exitCode=$code;closed=$ownedProcess.HasExited}
 if($code -ne 0){throw 'Packaged editor exited unsuccessfully'}
 $packageProcesses=Get-AiwPackageProcessInventory
 $packageProcesses|Add-Member -NotePropertyName queryAuthority -NotePropertyValue 'applicationUserDiagnostic'
 $packageProcesses|Add-Member -NotePropertyName globalAbsenceVerified -NotePropertyValue $false
 Record 'package-processes-after-close' $packageProcesses
 if($packageProcesses.matches.Count -ne 0 -or @($packageProcesses.queryErrors|Where-Object name -ieq 'notepad++').Count -ne 0){throw 'Application candidate remains after editor close'}
 $bytes=[IO.File]::ReadAllBytes($document)
 $expectedBytes=[Text.Encoding]::UTF8.GetBytes($expected)
 if([Convert]::ToBase64String($bytes) -cne [Convert]::ToBase64String($expectedBytes)){throw 'Saved document bytes differ'}
 Record 'document-output' @{path=$document;sha256=(Hash $document);sizeBytes=$bytes.Length;exactExpectedBytes=$true}
 $stage='configuration'
 $afterConfig=@(ConfigSnapshot $family)
 $configurationDirectory=Join-Path $evidence 'configuration'
 New-Item -ItemType Directory -Path $configurationDirectory|Out-Null
 for($index=0;$index -lt $afterConfig.Count;$index++){$retained='configuration/'+$index+'-'+[IO.Path]::GetFileName($afterConfig[$index].path);Copy-Item -LiteralPath $afterConfig[$index].path -Destination (Join-Path $evidence $retained);$afterConfig[$index]|Add-Member -NotePropertyName retainedFile -NotePropertyValue $retained}
 Record 'config-after' $afterConfig
 if(@($afterConfig|Where-Object {[IO.Path]::GetFileName($_.path) -ceq 'config.xml'}).Count -eq 0){throw 'Per-user configuration location not observed'}
 foreach($file in $assembly.payloadInventory){if((Hash (Join-Path $location $file.path)) -cne $file.sha256){throw ('Immutable payload changed: '+$file.path)}}
 if((Hash (Join-Path $location 'AppxManifest.xml')) -cne $manifestBeforeHash){throw 'Installed manifest changed'}
 Record 'manifest-after' @{sha256=(Hash (Join-Path $location 'AppxManifest.xml'))}
 Record 'payload-after' @{matchesOriginalInventory=$true;filesChecked=$assembly.payloadInventory.Count}
 $stage='uninstall'
 Record 'uninstall-started' @{packageFullName=$installedFullName;time=[DateTime]::UtcNow.ToString('o')}
 Remove-AppxPackage -Package $installedFullName -ErrorAction Stop
 $remaining=@(Get-AppxPackage -Name AIWResearch.NotepadPP)
 $processes=@(Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue)
 $configAfterUninstall=@(ConfigSnapshot $family)
 $packageProcesses=Get-AiwPackageProcessInventory
 $packageProcesses|Add-Member -NotePropertyName queryAuthority -NotePropertyValue 'applicationUserDiagnostic'
 $packageProcesses|Add-Member -NotePropertyName globalAbsenceVerified -NotePropertyValue $false
 Record 'package-processes-after-uninstall' $packageProcesses
 if($packageProcesses.matches.Count -ne 0 -or @($packageProcesses.queryErrors|Where-Object name -ieq 'notepad++').Count -ne 0){throw 'Application candidate remains after uninstall'}
 Record 'cleanup' @{registrationAbsent=($remaining.Count -eq 0);applicationProcessesAbsent=($processes.Count -eq 0);installLocationPresent=(Test-Path -LiteralPath $location);configurationAfterUninstall=$configAfterUninstall;userDataDeletionClaim='notInferredFromUninstall'}
 if($remaining.Count -ne 0 -or $processes.Count -ne 0){throw 'Exact registration/process cleanup not verified'}
 Record 'result' ([ordered]@{completed=$true;researchOnly=$false;signedSha256=$SignedSha256;packageFullName=$installedFullName;packageIdentity='observed';runtime='mediumIlFullTrust';documentWorkflow='exactBytesVerified';configuration='perUserLocationObserved';payloadUnchanged=$true;registrationCleanup='verified';isolation='notMeasured';evidenceRoot=$evidence})
 Write-Host ('Lifecycle completed. Evidence: '+$evidence)
} catch {
 $primaryError=$_
 Record 'failure' ([ordered]@{stage=$stage;summary=$_.Exception.Message;exception=$_.Exception.ToString();errorRecord=($_|Out-String);packageFullName=$installedFullName;processId=$activatedPid;automaticRetry=$false;automaticUninstall=$false;time=[DateTime]::UtcNow.ToString('o')})
 try{Record 'failure-state' @{packages=@(Get-AppxPackage -Name AIWResearch.NotepadPP|Select-Object PackageFullName,InstallLocation,PackageUserInformation);processes=Get-AiwPackageProcessInventory;configuration=@(ConfigSnapshot 'AIWResearch.NotepadPP_q1fhfzcjv9wt6');applicationCleanupVerified=$false}}catch{Record 'failure-state-error' @{error=$_.Exception.Message;primaryError=$primaryError.Exception.Message}}
 throw $primaryError
} finally {try{if($suspended){$suspended.Dispose()}}finally{if($ownedProcess){$ownedProcess.Dispose()};if($held){$held.Dispose()}}}
