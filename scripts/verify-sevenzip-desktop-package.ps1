#Requires -Version 7.6
#Requires -PSEdition Core
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$PackageRoot,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$ReceiptSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceRevision,
 [Parameter(Mandatory)][string]$CliExe,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$GuestAgentSha256,
 [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{64}\z')][string]$WorkflowSourceSha256
)
# Only the independently selected, package-hash-matched CLI identity command executes.

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

try{
 $root=Hold-Directory $PackageRoot;$null=Hold-Directory (Join-Path $root 'product');$null=Hold-Directory (Join-Path $root 'product\sevenzip')
 # Enumerate only the three declared directories; extras and unknown directories fail closed.
 foreach($entry in @(@($root,@('LICENSE','README.txt','aiw-desktop.exe','aiw.exe','checksums.txt','product','receipt.json')),@((Join-Path $root 'product'),@('sevenzip')),@((Join-Path $root 'product\sevenzip'),@('7z2605-x64.exe','aiw-guest-agent.exe','manifest.json')))){
  $actual=[string[]]@(Get-ChildItem -LiteralPath $entry[0] -Force|ForEach-Object{$_.Name});$expected=[string[]]$entry[1]
  [Array]::Sort($actual,[StringComparer]::Ordinal);[Array]::Sort($expected,[StringComparer]::Ordinal)
  if(($actual -join '|') -cne ($expected -join '|')){throw 'Package closed inventory differs'}
 }
 $receiptFile=Hold-File (Join-Path $root 'receipt.json') 1048576;if((Hash-Stream $receiptFile) -cne $ReceiptSha256){throw 'Receipt differs from independently supplied hash'}
 $receipt=Read-Json $receiptFile;Assert-Keys $receipt @('schemaVersion','sourceRevision','guestAgentSha256','workflowSourceSha256','installerSha256','installerSizeBytes','files','receiptLast')
 if($receipt.schemaVersion -cne 'aiw.dev/sevenzip-desktop-package/v0alpha1' -or $receipt.sourceRevision -cne $SourceRevision -or $receipt.guestAgentSha256 -cne $GuestAgentSha256 -or $receipt.workflowSourceSha256 -cne $WorkflowSourceSha256 -or $receipt.installerSha256 -cne $installerHash -or $receipt.installerSizeBytes -ne $installerSize -or $receipt.receiptLast -cne $true){throw 'Package receipt commitments differ'}
 $expectedPaths=@($payloadPaths[0..3])+@('checksums.txt')+@($payloadPaths[4..6]);$records=@($receipt.files)
 if($records.Count -ne $expectedPaths.Count){throw 'Package receipt file count differs'}
 $streams=@{};$checksumText=''
 for($i=0;$i -lt $expectedPaths.Count;$i++){
  $record=$records[$i];Assert-Keys $record @('path','sizeBytes','sha256');$name=$expectedPaths[$i]
  if($record.path -cne $name -or $record.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ($record.sizeBytes -isnot [long] -and $record.sizeBytes -isnot [int])){throw 'Closed package file record differs'}
  $stream=Hold-File (Join-Path $root $name.Replace('/','\'));$streams[$name]=$stream
  if($stream.Length -ne $record.sizeBytes -or (Hash-Stream $stream) -cne $record.sha256){throw 'Package file bytes differ from receipt'}
 }
 foreach($name in $payloadPaths){$checksumText+=("$(Hash-Stream $streams[$name])  $name"+[char]10)}
 $bytes=[byte[]]::new([int]$streams['checksums.txt'].Length);$streams['checksums.txt'].ReadExactly($bytes);$streams['checksums.txt'].Position=0
 if([Text.UTF8Encoding]::new($false,$true).GetString($bytes) -cne $checksumText){throw 'Package checksums differ'}
 if((Hash-Stream $streams['product/sevenzip/aiw-guest-agent.exe']) -cne $GuestAgentSha256 -or (Hash-Stream $streams['product/sevenzip/7z2605-x64.exe']) -cne $installerHash -or $streams['product/sevenzip/7z2605-x64.exe'].Length -ne $installerSize){throw 'Pinned agent/vendor installer differs'}
 $manifest=Read-Json $streams['product/sevenzip/manifest.json'];Assert-Keys $manifest @('schemaVersion','guestAgentSha256','workflowSourceSha256','installerSha256','installerSizeBytes')
 if($manifest.schemaVersion -cne 'aiw.dev/sevenzip-product-assets/v0alpha1' -or $manifest.guestAgentSha256 -cne $GuestAgentSha256 -or $manifest.workflowSourceSha256 -cne $WorkflowSourceSha256 -or $manifest.installerSha256 -cne $installerHash -or $manifest.installerSizeBytes -ne $installerSize){throw 'Product manifest commitments differ'}
 $cli=Hold-File $CliExe;if((Hash-Stream $cli) -cne (Hash-Stream $streams['aiw.exe'])){throw 'Supplied identity CLI differs from independently verified package CLI'}
 $identityText=& (Full-LocalPath $CliExe) provider sevenzip-identity;if($LASTEXITCODE -ne 0 -or ($identityText -join '').Length -gt 4096){throw 'Read-only CLI source identity failed'}
 $identity=$identityText|ConvertFrom-Json -AsHashtable;Assert-Keys $identity @('schemaVersion','sourceSha256','installerSha256','installerSizeBytes')
 if($identity.schemaVersion -cne 'aiw.dev/sevenzip-source-identity/v0alpha1' -or $identity.sourceSha256 -cne $WorkflowSourceSha256 -or $identity.installerSha256 -cne $installerHash -or $identity.installerSizeBytes -ne $installerSize){throw 'CLI source/installer identity differs'}
 [ordered]@{schemaVersion='aiw.dev/sevenzip-desktop-package-verification/v0alpha1';packageRoot=$root;sourceRevision=$SourceRevision;receiptSha256=$ReceiptSha256;filesVerified=$records.Count;exactInventory=$true;providerInvoked=$false}|ConvertTo-Json -Compress
}finally{for($i=$held.Count-1;$i -ge 0;$i--){$held[$i].Dispose()}}

