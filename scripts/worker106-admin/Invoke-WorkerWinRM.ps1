param([Parameter(Mandatory=$true)][string]$ScriptPath)
$ErrorActionPreference='Stop'
$credential=Import-Clixml -LiteralPath 'C:\passkeys\worker106-tools\worker-admin-recovery\worker-admin.credential.clixml'
$request=@{username=$credential.UserName;password=$credential.GetNetworkCredential().Password;script=[IO.File]::ReadAllText((Resolve-Path -LiteralPath $ScriptPath).Path)}|ConvertTo-Json -Compress
$info=[Diagnostics.ProcessStartInfo]::new()
$info.FileName='C:\Users\labadmin\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$info.Arguments='"'+(Join-Path $PSScriptRoot 'winrm-client.py')+'"'
$info.UseShellExecute=$false;$info.CreateNoWindow=$true
$info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
$info.StandardInputEncoding=[Text.UTF8Encoding]::new($false)
$process=[Diagnostics.Process]::Start($info)
try {
    $process.StandardInput.Write($request);$process.StandardInput.Close();$request=$null
    $output=$process.StandardOutput.ReadToEnd();$errorText=$process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if($errorText){Write-Warning $errorText}
    $output
} finally {$process.Dispose();$credential=$null;$request=$null}
