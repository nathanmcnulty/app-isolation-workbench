#Requires -Version 7.6
#Requires -PSEdition Core
# Bounded, local-only source/ACL regressions. No VM, WinRM or application is used.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\..\powershell-runtime.ps1')
$runtime=Assert-AiwPowerShellRuntime -AllowCurrentProcessForInertTests
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
function Read-Ast([string]$Path) {
 $tokens=$null;$errors=$null
 $ast=[Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
 if($errors.Count){throw ($errors|Out-String)}
 $ast
}
$transport=Read-Ast (Join-Path $repo 'scripts\vm-msix\transport.ps1')
$observer=Read-Ast (Join-Path $repo 'scripts\vm-msix\observe-runtime.ps1')
function Get-OneAst($Ast,[string]$Name,[type]$Type) {
 $nodes=@($Ast.FindAll({param($node) $node -is $Type -and (($node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $Name) -or ($node -is [Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -ceq ('$'+$Name)))},$true))
 if($nodes.Count -ne 1){throw "Expected one $Name; found $($nodes.Count)"};$nodes[0]
}
$proof=Get-OneAst $transport 'runtimeProof' ([Management.Automation.Language.AssignmentStatementAst])
$observationProof=Get-OneAst $observer 'runtimeProof' ([Management.Automation.Language.AssignmentStatementAst])
if($proof.Extent.Text -cne $observationProof.Extent.Text){throw 'Runtime observation and execution proof must be identical'}
$source=$transport.Extent.Text
foreach($forbidden in @('ConfigurationName Microsoft.PowerShell','WindowsPowerShell\v1.0\powershell.exe','-UseWindowsPowerShell','SkipCACheck','SkipCNCheck','SkipRevocationCheck')){if($source.Contains($forbidden)){throw "Forbidden execution route: $forbidden"}}
if($source.IndexOf('Legacy prepared workspace') -gt $source.IndexOf('$stored=Import-Clixml')){throw 'Legacy runtime binding must be rejected before credential import'}
if($source.IndexOf('Assert-AiwRuntimeBinding $workerRuntime') -gt $source.IndexOf("if(`$Operation -eq 'Ready')")){throw 'Remote proof must precede any operation'}
$binding=Get-OneAst $transport 'Assert-AiwRuntimeBinding' ([Management.Automation.Language.FunctionDefinitionAst])
. ([scriptblock]::Create($binding.Extent.Text))
$identity=[pscustomobject]@{edition='Core';version='7.6.5';prerelease='';architecture='X64';executable='C:\Program Files\PowerShell\7\pwsh.exe';psHome='C:\Program Files\PowerShell\7';executableSha256=('a'*64);capabilities=@('Add-Type','New-PSSession');compatibilitySessionCount=0}
Assert-AiwRuntimeBinding $identity $identity
$rejected=0
foreach($field in @('edition','version','prerelease','architecture','executable','psHome','executableSha256','compatibilitySessionCount','capabilities')) {
 $changed=$identity|ConvertTo-Json|ConvertFrom-Json
 if($field -ceq 'capabilities'){$changed.capabilities=@('New-PSSession')}else{$changed.$field='different'}
 try{Assert-AiwRuntimeBinding $changed $identity;throw 'Expected rejected runtime mismatch'}catch{if($_.Exception.Message -like 'Expected rejected*'){throw};$rejected++}
}
try{Assert-AiwRuntimeBinding $identity $null;throw 'Expected rejected missing runtime'}catch{if($_.Exception.Message -like 'Expected rejected*'){throw};$rejected++}
$creation=Get-OneAst $transport 'New-AiwProtectedDirectory' ([Management.Automation.Language.FunctionDefinitionAst])
. ([scriptblock]::Create($creation.Extent.Text))
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('aiw-pwsh76-acl-'+[guid]::NewGuid().ToString('N'))
$created=$false
try {
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($sid)
 $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
 New-AiwProtectedDirectory $temporary $acl;$created=$true
 $before=(Get-Acl -LiteralPath $temporary).Sddl
 try{New-AiwProtectedDirectory $temporary $acl;throw 'Expected rejected existing directory'}catch{if($_.Exception.Message -notlike '*Fresh protected directory required*'){throw}}
 if((Get-Acl -LiteralPath $temporary).Sddl -cne $before){throw 'Existing protected directory ACL changed'}
}finally{if($created){Remove-Item -LiteralPath $temporary -Force}}
$retiredManifest=Get-Content -LiteralPath (Join-Path $repo 'scripts\research\RETIRED-EXECUTION.md') -Raw
$paths=[regex]::Matches($retiredManifest,'(?m)^- `([^`]+)`$')
foreach($match in $paths){
 $path=Join-Path $repo $match.Groups[1].Value
 $text=[IO.File]::ReadAllText($path)
 if($path.EndsWith('.ps1') -or $path.EndsWith('.in')){
  $ast=Read-Ast $path
  if(@($ast.FindAll({param($node) $node -is [Management.Automation.Language.ThrowStatementAst]},$true)).Count -ne 1 -or @($ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)).Count -ne 0){throw "Retired PowerShell route became active: $path"}
 }elseif($path.EndsWith('.py')){if($text -notmatch 'raise SystemExit' -or $text -match '(?m)^import |(?m)^from '){throw "Retired Python route became active: $path"}}
}
[pscustomobject]@{passed=$true;runtimeVersion=$runtime.version;runtimeBindingRejections=$rejected;aclAtCreation=$true;existingAclPreserved=$true;retiredEntryPoints=$paths.Count;vmContacted=$false;applicationExecuted=$false}|ConvertTo-Json -Compress