[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [ValidatePattern('^[0-9a-f]{40}$')] [string]$SourceRevision,
    [Parameter(Mandatory)] [string]$OutputFile
)
$ErrorActionPreference = 'Stop'
$file = Get-Item -LiteralPath $Path -Force
if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Signing control must be an ordinary file' }
if (Test-Path -LiteralPath $OutputFile) { throw 'Signing verification output must be fresh' }
$heldFile = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
$signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
$subject = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
$publisher = if ($signature.SignerCertificate) { $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } else { $null }
$verified = $signature.Status -eq 'Valid' -and $signature.SignatureType -eq 'Authenticode' -and
    $publisher -ceq 'Nathan McNulty' -and $null -ne $signature.TimeStamperCertificate
$record = [ordered]@{
    schemaVersion = 'aiw.dev/signing-control/v0alpha1'
    sourceRevision = $SourceRevision
    fileName = $file.Name
    sizeBytes = $heldFile.Length
    sha256 = $(
        $sha = [Security.Cryptography.SHA256]::Create()
        try { ([BitConverter]::ToString($sha.ComputeHash($heldFile))).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    )
    signatureStatus = [string]$signature.Status
    signatureType = [string]$signature.SignatureType
    publisher = $publisher
    certificateSubject = $subject
    certificateThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToLowerInvariant() } else { $null }
    timestampPresent = $null -ne $signature.TimeStamperCertificate
    verified = $verified
    scope = 'Project-built CLI signing control only; not a desktop package or application compatibility trial'
}
$json = $record | ConvertTo-Json -Depth 5
$output = [IO.File]::Open([IO.Path]::GetFullPath($OutputFile), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
    $output.Write($bytes, 0, $bytes.Length)
}
finally { $output.Dispose() }
if (-not $verified) { throw 'Signing control requires valid timestamped Authenticode from Nathan McNulty; inspect the retained verification record' }
$record | ConvertTo-Json -Compress
}
finally { $heldFile.Dispose() }
