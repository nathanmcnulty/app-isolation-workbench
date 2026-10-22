#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if(Test-Path -LiteralPath $Destination){throw 'Fresh payload destination required'}
$status=@(& git -C $repo status --porcelain=v1)
if($LASTEXITCODE -ne 0 -or $status.Count -ne 0){throw 'Commit and review the exact clean sources before sealing a payload'}
$commit=(& git -C $repo rev-parse HEAD).Trim();if($LASTEXITCODE){throw 'Cannot identify source'}
$driver='C:\AIW-Build\msix-worker107-r1\x86_64-pc-windows-msvc\release\examples\msix_standard_user_lifecycle.exe'
$driverSha='c551938fb6c6f8f8d6a5311850e8713d020f4c888f0b3f67b88babc1d6a0dad5'
if((Get-FileHash -LiteralPath $driver).Hash.ToLowerInvariant() -cne $driverSha){throw 'Reviewed native image differs'}
New-Item -ItemType Directory -Path $Destination|Out-Null
foreach($file in @('worker107-msix.ps1','worker107-msix-templates.ps1','worker107-scheduler-controller.ps1.in','worker107-scheduler-worker.ps1.in','msix-primary-preparation.ps1','worker107-editor.ps1','worker107-editor-input.cs')){
    $source=Join-Path $PSScriptRoot $file
    [IO.File]::WriteAllText((Join-Path $Destination $file),[IO.File]::ReadAllText($source).Replace("`r`n","`n"),[Text.UTF8Encoding]::new($false))
}
foreach($name in @('research_msix_native.cs','research_msix_interactive.cs')){
    $source=Join-Path $repo ('crates\aiw-windows-platform\src\'+$name)
    [IO.File]::WriteAllText((Join-Path $Destination $name),[IO.File]::ReadAllText($source).Replace("`r`n","`n"),[Text.UTF8Encoding]::new($false))
}
Copy-Item -LiteralPath $driver -Destination (Join-Path $Destination 'msix_standard_user_lifecycle.exe')
$inputs=@{'application.msix'='2ae3a7c685e811eb34479980bff41d1442b023578074e19f4dca8fc676070437';'assembly.json'='d7eca3af76598534d29e411b4d4775d61e6ffe11174aa5a171b44bfe2a080c38';'signing.json'='670e6f9e44211848c305c61261aa2ed6e2c94fac229214ec843cd4c9afab9e80'}
foreach($name in $inputs.Keys){$source=Join-Path 'C:\AIW-Resume-20261021\assets\inputs' $name;if((Get-FileHash -LiteralPath $source).Hash.ToLowerInvariant() -cne $inputs[$name]){throw 'Frozen signed input differs'};Copy-Item -LiteralPath $source -Destination (Join-Path $Destination $name)}
$manifest=[ordered]@{schemaVersion='aiw.dev/worker107-msix-bundle/v1';workerUuid='e5cecc90-35c2-4831-bf9c-424be23f7d4e';sourceCommit=$commit;driverSha256=$driverSha;files=@(Get-ChildItem -LiteralPath $Destination -File|Sort-Object Name|ForEach-Object{[ordered]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant();bytes=$_.Length}})}
[IO.File]::WriteAllText((Join-Path $Destination 'bundle.json'),($manifest|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
[ordered]@{sourceCommit=$commit;driverSha256=$driverSha;manifestSha256=(Get-FileHash -LiteralPath (Join-Path $Destination 'bundle.json')).Hash.ToLowerInvariant();files=$manifest.files.Count;applicationTrialExecuted=$false}|ConvertTo-Json
