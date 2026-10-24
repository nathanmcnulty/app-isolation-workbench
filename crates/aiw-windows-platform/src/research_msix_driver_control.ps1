#Requires -Version 7.6
#Requires -PSEdition Core
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(Test-Path -LiteralPath $EvidenceDirectory){throw 'Fresh control evidence required'}
New-Item -ItemType Directory -Path $EvidenceDirectory|Out-Null
$controls=@()
foreach($mode in @('success','failure','deadline')) {
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName='C:\Program Files\PowerShell\7\pwsh.exe'
 $fixed= switch($mode){
  success {"[Console]::Out.WriteLine('aiw-owned-control-out'); [Console]::Error.WriteLine('aiw-owned-control-error'); exit 0"}
  failure {"[Console]::Out.WriteLine('aiw-owned-control-out'); [Console]::Error.WriteLine('aiw-owned-control-error'); exit 42"}
  deadline {"[Console]::Out.WriteLine('aiw-owned-control-out'); [Console]::Error.WriteLine('aiw-owned-control-error'); Start-Sleep -Seconds 30; exit 0"}
 }
 $fixed = 'if($PSVersionTable.PSEdition -cne ''Core'' -or $PSVersionTable.PSVersion -lt [version]''7.6'' -or $PSVersionTable.PSVersion.ToString() -match ''-''){throw ''Stable Core 7.6+ required''}; $ProgressPreference=''SilentlyContinue''; ' + $fixed
 $info.Arguments='-NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($fixed))
 $info.UseShellExecute=$false; $info.CreateNoWindow=$true
 $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
 $process=New-Object Diagnostics.Process
 $process.StartInfo=$info
 $started=$false
 $timer=[Diagnostics.Stopwatch]::StartNew()
 try {
  if(!$process.Start()){throw 'Control did not start'}
  $started=$true
  $heldHandle=$process.Handle
  $ownedPid=$process.Id
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  $startTime=$process.StartTime.ToUniversalTime().ToString('o')
  $image=[AiwMsixNative]::ImagePath($heldHandle)
  $inJob=[AiwMsixNative]::InJob($heldHandle)
  if(!$inJob -or $image -ine $info.FileName){throw 'Owned control image/job mismatch'}
  $deadline=if($mode -eq 'deadline'){5000}else{15000}
  $finished=$process.WaitForExit($deadline)
  if(!$finished){$process.Kill();if(!$process.WaitForExit(5000)){throw 'Owned deadline control did not terminate'}}
  if(!$stdout.Wait(5000) -or !$stderr.Wait(5000)){throw 'Control streams did not drain'}
  $out=$stdout.Result;$err=$stderr.Result
  if($out.Length -gt 1024 -or $err.Length -gt 1024){throw 'Closed control stream bound exceeded'}
  [IO.File]::WriteAllText((Join-Path $EvidenceDirectory ($mode+'.stdout.log')),$out)
  [IO.File]::WriteAllText((Join-Path $EvidenceDirectory ($mode+'.stderr.log')),$err)
  if($out.Trim() -cne 'aiw-owned-control-out' -or $err.Trim() -cne 'aiw-owned-control-error'){throw 'Owned control capture differs'}
  if($mode -eq 'success' -and (!$finished -or $process.ExitCode -ne 0)){throw 'Success control failed'}
  if($mode -eq 'failure' -and (!$finished -or $process.ExitCode -ne 42)){throw 'Failure control differs'}
  if($mode -eq 'deadline' -and $finished){throw 'Deadline control did not hit deadline'}
  $controls += [pscustomobject]@{mode=$mode;pid=$ownedPid;heldHandle=($heldHandle -ne [IntPtr]::Zero);startTime=$startTime;imagePath=$image;inInheritedJob=$inJob;stdoutCharacters=$out.Length;stderrCharacters=$err.Length;exitCode=$process.ExitCode;deadlineHit=(!$finished);exited=$process.HasExited;elapsedMs=$timer.ElapsedMilliseconds}
 }finally{if($started -and !$process.HasExited){$process.Kill();if(!$process.WaitForExit(5000)){throw 'Control cleanup failed'}};$timer.Stop();$process.Dispose()}
}
$result=[pscustomobject]@{computer=$env:COMPUTERNAME;identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;sessionId=[Diagnostics.Process]::GetCurrentProcess().SessionId;controls=$controls;passed=$true}
$result|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'control.json') -Encoding UTF8
$result|ConvertTo-Json -Depth 4 -Compress
