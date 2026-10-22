# Pure guard and fixed transport checks; never invokes the preparation body.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Prepare-Worker106Offline.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw 'Payload parse failed'}
$guard=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-OfflineIdentity'},$true))
if ($guard.Count -ne 1){throw 'Unique guard required'}
Invoke-Expression $guard[0].Extent.Text
$valid=[pscustomobject]@{Uuid='7e686bee-8c05-43c7-9603-a9562ece224c';Sid='S-1-5-18';Is64Bit=$true;Adapters=@([pscustomobject]@{MacAddress='CC-34-21-7E-FE-59';Status='Disconnected'});DomainJoined=$false;AzureAdJoined='NO';EnterpriseJoined='NO';ServiceCount=0;TailscalePathsPresent=$false}
Assert-OfflineIdentity $valid
$cases=@(
    {param($o) $o.Uuid='wrong'}, {param($o) $o.Sid='S-1-5-21-1001'},
    {param($o) $o.Is64Bit=$false}, {param($o) $o.Adapters=@()},
    {param($o) $o.Adapters=@($o.Adapters[0],$o.Adapters[0])},
    {param($o) $o.Adapters[0].MacAddress='00-00-00-00-00-00'},
    {param($o) $o.Adapters[0].Status='Up'}, {param($o) $o.DomainJoined=$true},
    {param($o) $o.AzureAdJoined='YES'}, {param($o) $o.EnterpriseJoined='YES'},
    {param($o) $o.ServiceCount=1}, {param($o) $o.TailscalePathsPresent=$true}
)
foreach($case in $cases){
    $o=$valid | ConvertTo-Json -Depth 4 | ConvertFrom-Json
    & $case $o
    $rejected=$false
    try {Assert-OfflineIdentity $o} catch {$rejected=$true}
    if(-not $rejected){throw 'Unsafe worker identity accepted'}
}
# Verify Windows PowerShell 5.1 receives a large fixed script through QGA-style
# stdin and the tiny encoded bootstrap, without executing the actual payload.
$bootstrap='$text=[Console]::In.ReadToEnd(); & ([scriptblock]::Create($text)) -Operation Verify'
$info=[Diagnostics.ProcessStartInfo]::new()
$info.FileName="$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$info.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
$info.UseShellExecute=$false;$info.CreateNoWindow=$true
$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
$process=[Diagnostics.Process]::Start($info)
try {
    $control='param([string]$Operation)'+"`n"+('# padding' + "`n")*6000+'[Console]::Out.Write($Operation)'
    $process.StandardInput.Write($control);$process.StandardInput.Close()
    $output=$process.StandardOutput.ReadToEnd();$errorText=$process.StandardError.ReadToEnd()
    if(-not $process.WaitForExit(30000) -or $process.ExitCode -ne 0 -or $output -cne 'Verify' -or $errorText){throw 'Fixed stdin control failed'}
} finally {$process.Dispose()}
[ordered]@{Accepted=1;Rejected=$cases.Count;WindowsPowerShell51LargeStdinControl='passed';WorkerMutationsExecuted=$false} | ConvertTo-Json
