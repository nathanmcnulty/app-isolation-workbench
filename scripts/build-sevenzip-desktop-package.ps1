#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$DesktopExe,[Parameter(Mandatory)][string]$CliExe,
 [Parameter(Mandatory)][string]$GuestAgent,[Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$GuestAgentSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$WorkflowSourceSha256,
 [Parameter(Mandatory)][string]$Installer,[Parameter(Mandatory)][string]$OutputDirectory,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceRevision
)
# Assembly only. No compilation, installer/application run, provider call, download or cleanup.

$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
if($PSVersionTable.PSVersion.PreReleaseLabel -or [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -cne 'X64'){throw 'Stable x64 PowerShell Core 7.6+ required'}
foreach($module in @('Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security')){Import-Module (Join-Path $PSHOME "Modules\$module\$module.psd1") -SkipEditionCheck -ErrorAction Stop}
$PSModuleAutoLoadingPreference='None';$PSNativeCommandUseErrorActionPreference=$false
if(@(Get-PSSession|Where-Object Name -eq 'WinPSCompatSession').Count){throw 'Windows PowerShell compatibility sessions are prohibited'}
if(-not ('AiwSevenZipPackageFiles' -as [type])){Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class AiwSevenZipPackageFiles {
 [StructLayout(LayoutKind.Sequential, Pack=4)] struct Info {public uint Attr;public long C,A,W;public uint Vol,Hi,Lo,Links,IndexHi,IndexLo;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr x,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string p,IntPtr s);
 public static SafeFileHandle Hold(string p,bool directory) {
  var h=CreateFileW(p,directory?0x80u:0x80000000u,directory?3u:1u,IntPtr.Zero,3,0x02200000,IntPtr.Zero);Info i;
  if(h.IsInvalid){h.Dispose();throw new Win32Exception(Marshal.GetLastWin32Error());}
  if(!GetFileInformationByHandle(h,out i)||(i.Attr&0x440)!=0||((i.Attr&16)!=0)!=directory||i.Vol==0||(i.IndexHi==0&&i.IndexLo==0)||(!directory&&i.Links!=1)){h.Dispose();throw new IOException("Unsupported, linked or reparse package object");}
  return h;
 }
 public static void CreateDirectoryNew(string p){if(!CreateDirectoryW(p,IntPtr.Zero))throw new Win32Exception(Marshal.GetLastWin32Error());}
}
'@}
$held=[Collections.Generic.List[IDisposable]]::new()
function Full-LocalPath([string]$Path){
 if($Path -cnotmatch '\A[A-Za-z]:\\' -or $Path.Substring(3).Contains(':') -or $Path.Contains('/') -or @($Path.Split('\')|Select-Object -Skip 1|Where-Object{$_ -in @('.','..') -or $_.EndsWith(' ') -or $_.EndsWith('.')}).Count){throw 'Canonical local drive path required'}
 $full=[IO.Path]::GetFullPath($Path);if([IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)).DriveType -ne 'Fixed'){throw 'Local fixed drive required'};return $(if($full.Length -eq 3){$full}else{$full.TrimEnd('\')})
}
function Hold-Directory([string]$Path){
 $full=Full-LocalPath $Path;$current=[IO.Path]::GetPathRoot($full);$held.Add([AiwSevenZipPackageFiles]::Hold($current,$true))
 foreach($part in $full.Substring(3).Split('\',[StringSplitOptions]::RemoveEmptyEntries)){$current=Join-Path $current $part;$held.Add([AiwSevenZipPackageFiles]::Hold($current,$true))}
 return $full
}
function Hold-File([string]$Path,[long]$Limit=134217728){
 $full=Full-LocalPath $Path;$null=Hold-Directory ([IO.Path]::GetDirectoryName($full));$h=[AiwSevenZipPackageFiles]::Hold($full,$false)
 $stream=[IO.FileStream]::new($h,[IO.FileAccess]::Read);$held.Add($stream);if($stream.Length -gt $Limit){throw 'Package file exceeds bounded contract'};return ,$stream
}
function Hash-Stream([IO.FileStream]$Stream){$Stream.Position=0;try{return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Stream)).ToLowerInvariant()}finally{$Stream.Position=0}}
function New-Bytes([string]$Path,[byte[]]$Bytes){$file=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);try{$file.Write($Bytes);$file.Flush($true)}finally{$file.Dispose()}}
function Json-Bytes([object]$Value){return ,([Text.UTF8Encoding]::new($false,$true).GetBytes(($Value|ConvertTo-Json -Depth 16 -Compress)))}
function Read-Json([IO.FileStream]$Stream){$bytes=[byte[]]::new([int]$Stream.Length);$Stream.Position=0;$Stream.ReadExactly($bytes);$Stream.Position=0;return ([Text.UTF8Encoding]::new($false,$true).GetString($bytes)|ConvertFrom-Json -AsHashtable -Depth 16)}
function Assert-Keys($Value,[string[]]$Expected){$a=[string[]]@($Value.Keys);$b=[string[]]@($Expected);[Array]::Sort($a,[StringComparer]::Ordinal);[Array]::Sort($b,[StringComparer]::Ordinal);if(($a -join '|') -cne ($b -join '|')){throw 'Unknown or missing package fields'}}
$installerHash='fd99e86f57d8f429ef5ed045bf98315af962e2309b0f1ba87a147a44c71647d0';$installerSize=1663506L
$payloadPaths=@('LICENSE','README.txt','aiw-desktop.exe','aiw.exe','product/sevenzip/7z2605-x64.exe','product/sevenzip/aiw-guest-agent.exe','product/sevenzip/manifest.json')

$repo=[IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
function Assert-Source {
 $head=& git -C $repo rev-parse HEAD;if($LASTEXITCODE -ne 0 -or $head.Trim() -cne $SourceRevision){throw 'Exact supplied source HEAD required'}
 $status=@(& git -C $repo status --porcelain=v1 --untracked-files=all);if($LASTEXITCODE -ne 0 -or $status.Count){throw 'Clean source checkout required for assembly'}
}
try{
 Assert-Source
 $output=Full-LocalPath $OutputDirectory
 if($output -ieq $repo -or $output.StartsWith($repo+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Output must be outside checkout'}
 $null=Hold-Directory ([IO.Path]::GetDirectoryName($output));if(Test-Path -LiteralPath $output){throw 'Fresh package destination required'}
 $sources=[ordered]@{'aiw-desktop.exe'=Hold-File $DesktopExe;'aiw.exe'=Hold-File $CliExe;'product/sevenzip/aiw-guest-agent.exe'=Hold-File $GuestAgent;'product/sevenzip/7z2605-x64.exe'=Hold-File $Installer}
 if((Hash-Stream $sources['product/sevenzip/aiw-guest-agent.exe']) -cne $GuestAgentSha256){throw 'Guest agent differs from independently supplied hash'}
 if((Hash-Stream $sources['product/sevenzip/7z2605-x64.exe']) -cne $installerHash -or $sources['product/sevenzip/7z2605-x64.exe'].Length -ne $installerSize){throw 'Official 7-Zip 26.05 installer identity differs'}
 $identityText=& (Full-LocalPath $CliExe) provider sevenzip-identity;if($LASTEXITCODE -ne 0 -or ($identityText -join '').Length -gt 4096){throw 'Read-only CLI source identity failed'}
 $identity=$identityText|ConvertFrom-Json -AsHashtable;Assert-Keys $identity @('schemaVersion','sourceSha256','installerSha256','installerSizeBytes')
 if($identity.schemaVersion -cne 'aiw.dev/sevenzip-source-identity/v0alpha1' -or $identity.sourceSha256 -cne $WorkflowSourceSha256 -or $identity.installerSha256 -cne $installerHash -or $identity.installerSizeBytes -ne $installerSize){throw 'CLI workflow/installer identity differs'}
 $license=Hold-File (Join-Path $repo 'LICENSE') 1048576
 [AiwSevenZipPackageFiles]::CreateDirectoryNew($output);$null=Hold-Directory $output
 foreach($directory in @('product','product\sevenzip')){$path=Join-Path $output $directory;[AiwSevenZipPackageFiles]::CreateDirectoryNew($path);$null=Hold-Directory $path}
 foreach($name in $sources.Keys){
  $source=$sources[$name];$source.Position=0;$destination=Join-Path $output $name.Replace('/','\')
  $file=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$source.CopyTo($file);$file.Flush($true)}finally{$file.Dispose()}
  $copied=Hold-File $destination;if($copied.Length -ne $source.Length -or (Hash-Stream $copied) -cne (Hash-Stream $source)){throw 'Held source/copy identity mismatch; preserve failed package'}
 }
 $licenseBytes=[byte[]]::new([int]$license.Length);$license.ReadExactly($licenseBytes);New-Bytes (Join-Path $output 'LICENSE') $licenseBytes
 $manifest=[ordered]@{schemaVersion='aiw.dev/sevenzip-product-assets/v0alpha1';guestAgentSha256=$GuestAgentSha256;workflowSourceSha256=$WorkflowSourceSha256;installerSha256=$installerHash;installerSizeBytes=$installerSize}
 New-Bytes (Join-Path $output 'product\sevenzip\manifest.json') (Json-Bytes $manifest)
 $readme="7-Zip 26.05 assessment development package. Open aiw-desktop.exe, choose 7-Zip archive assessment, select a new evidence folder, enter the operator identity and exact guest Windows version. Review the complete plan, approve its exact hash, then Start separately. Installation and archive use run only inside an offline disposable Windows Sandbox. Results opens retained selections without replay and exports sanitized JSON/Markdown. Keep retained evidence; cancellation/recovery concern only the original owned session. GUI/shell, uninstall, registry/system changes, network/IPC/UI, all descendant tokens and endpoint equivalence remain unmeasured. General compatibility, isolation and production acceptance are not certified. Source revision: $SourceRevision."
 New-Bytes (Join-Path $output 'README.txt') ([Text.UTF8Encoding]::new($false).GetBytes($readme))
 $records=@();$checksums=''
 foreach($name in $payloadPaths){$file=Hold-File (Join-Path $output $name.Replace('/','\'));$hash=Hash-Stream $file;$records+=,[ordered]@{path=$name;sizeBytes=$file.Length;sha256=$hash};$checksums+=("$hash  $name"+[char]10)}
 New-Bytes (Join-Path $output 'checksums.txt') ([Text.UTF8Encoding]::new($false).GetBytes($checksums))
 $checksum=Hold-File (Join-Path $output 'checksums.txt') 1048576
 $records=@($records|Where-Object path -in @('LICENSE','README.txt','aiw-desktop.exe','aiw.exe'))+@([ordered]@{path='checksums.txt';sizeBytes=$checksum.Length;sha256=Hash-Stream $checksum})+@($records|Where-Object path -like 'product/*')
 Assert-Source
 $receipt=[ordered]@{schemaVersion='aiw.dev/sevenzip-desktop-package/v0alpha1';sourceRevision=$SourceRevision;guestAgentSha256=$GuestAgentSha256;workflowSourceSha256=$WorkflowSourceSha256;installerSha256=$installerHash;installerSizeBytes=$installerSize;files=$records;receiptLast=$true}
 New-Bytes (Join-Path $output 'receipt.json') (Json-Bytes $receipt)
 $receiptHash=Hash-Stream (Hold-File (Join-Path $output 'receipt.json') 1048576)
 & (Join-Path $PSScriptRoot 'verify-sevenzip-desktop-package.ps1') -PackageRoot $output -ReceiptSha256 $receiptHash -SourceRevision $SourceRevision -CliExe $CliExe -GuestAgentSha256 $GuestAgentSha256 -WorkflowSourceSha256 $WorkflowSourceSha256
}finally{for($i=$held.Count-1;$i -ge 0;$i--){$held[$i].Dispose()}}

