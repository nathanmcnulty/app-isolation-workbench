#Requires -Version 7.6
#Requires -PSEdition Core
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
trap{[Console]::Error.WriteLine($_.ToString()+[Environment]::NewLine+$_.ScriptStackTrace);exit 1}
$operatorSid='S-1-5-21-3556347314-2314855617-1438300668-1001'
$sid='S-1-5-21-3556347314-2314855617-1438300668-1006'
$other='S-1-5-21-3556347314-2314855617-1438300668-1007'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'system.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Generated script parse failed'}
foreach($name in @('New-AiwInputReadSecurity','Assert-AiwInputSecurity','Assert-AiwInputLayout')){
 $definitions=@($ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
 if($definitions.Count -ne 1){throw 'One production input guard required'}
 Invoke-Expression $definitions[0].Extent.Text
}
$accepted=0;$rejected=0
function Reject([scriptblock]$Action){$failed=$false;try{& $Action}catch{$failed=$true};if(!$failed){throw 'Unsafe input access accepted'};$script:rejected++}
function DirectoryAcl([string]$Sddl){$a=[Security.AccessControl.DirectorySecurity]::new();$a.SetSecurityDescriptorSddlForm($Sddl);return $a}
function FileAcl([string]$Sddl){$a=[Security.AccessControl.FileSecurity]::new();$a.SetSecurityDescriptorSddlForm($Sddl);return $a}
$directory="O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;$operatorSid)(A;OICI;0x1200a9;;;$sid)"
$staged="O:$operatorSid"+'G:SYD:P(A;OICI;FA;;;SY)'+"(A;OICI;FA;;;$operatorSid)"
$file="O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;$operatorSid)(A;ID;0x1200a9;;;$sid)"
Assert-AiwInputSecurity (DirectoryAcl $directory) $sid;$accepted++
Assert-AiwInputSecurity (DirectoryAcl $staged) $sid -Staged;$accepted++
Assert-AiwInputSecurity (DirectoryAcl ($staged.Replace('D:P','D:PAI'))) $sid -Staged;$accepted++
Assert-AiwInputSecurity (DirectoryAcl ($directory.Replace('D:P','D:PAI'))) $sid;$accepted++
Assert-AiwInputSecurity (FileAcl $file) $sid -File;$accepted++
Assert-AiwInputSecurity (FileAcl ($file.Replace("(A;ID;0x1200a9;;;$sid)",''))) $sid -File -Staged;$accepted++
Reject {New-AiwInputReadSecurity $operatorSid}
Reject {New-AiwInputReadSecurity 'S-1-1-0'}
Reject {Assert-AiwInputSecurity (DirectoryAcl $staged) $sid}
Reject {Assert-AiwInputSecurity (DirectoryAcl $directory) $other}
Reject {Assert-AiwInputSecurity (DirectoryAcl ($directory.Replace('O:SY',"O:$sid"))) $sid}
Reject {Assert-AiwInputSecurity (DirectoryAcl ($directory.Replace('D:P','D:'))) $sid}
Reject {Assert-AiwInputSecurity (DirectoryAcl ($directory+"(A;OICI;GR;;;$other)")) $sid}
Reject {Assert-AiwInputSecurity (DirectoryAcl ($directory.Replace("0x1200a9;;;$sid","FA;;;$sid"))) $sid}
Reject {Assert-AiwInputSecurity (DirectoryAcl ($directory.Replace('(A;OICI;FA;;;SY)',''))) $sid}
Reject {Assert-AiwInputSecurity (DirectoryAcl ($directory.Replace("(A;OICI;0x1200a9;;;$sid)","(D;OICI;0x1200a9;;;$sid)"))) $sid}
Reject {Assert-AiwInputSecurity (FileAcl $file) $other -File}
Reject {Assert-AiwInputSecurity (FileAcl ($file.Replace('O:BA',"O:$sid"))) $sid -File}
Reject {Assert-AiwInputSecurity (FileAcl ($file.Replace('D:AI','D:PAI'))) $sid -File}
Reject {Assert-AiwInputSecurity (FileAcl ($file.Replace(';ID;',';;'))) $sid -File}
Reject {Assert-AiwInputSecurity (FileAcl ($file.Replace("0x1200a9;;;$sid","FA;;;$sid"))) $sid -File}
Reject {Assert-AiwInputSecurity (FileAcl ($file+"(A;ID;GR;;;$other)")) $sid -File}
Reject {Assert-AiwInputSecurity (FileAcl ($file.Replace("(A;ID;0x1200a9;;;$sid)",''))) $sid -File}
$root=Join-Path $PSScriptRoot 'layout';$input=Join-Path $root 'input'
$null=New-Item -ItemType Directory -Path $input
foreach($name in @('application.msix','assembly.json','signing.json')){[IO.File]::WriteAllText((Join-Path $input $name),'inert')}
Assert-AiwInputLayout $root;$accepted++
[IO.File]::WriteAllText((Join-Path $input 'unexpected.txt'),'inert')
Reject {Assert-AiwInputLayout $root}
Remove-Item -LiteralPath (Join-Path $input 'unexpected.txt')
Remove-Item -LiteralPath (Join-Path $input 'application.msix')
Reject {Assert-AiwInputLayout $root}
$null=New-Item -ItemType Directory -Path (Join-Path $input 'application.msix')
Reject {Assert-AiwInputLayout $root}
Remove-Item -LiteralPath (Join-Path $input 'application.msix')
[IO.File]::WriteAllText((Join-Path $input 'application.msix'),'inert')
$linkRoot=Join-Path $PSScriptRoot 'linked-layout';$null=New-Item -ItemType Directory -Path $linkRoot
$link=Join-Path $linkRoot 'input'
$null=New-Item -ItemType Junction -Path $link -Target $input
try{Reject {Assert-AiwInputLayout $linkRoot}}finally{Remove-Item -LiteralPath $link}
# Exercise Windows propagation on existing ordinary files without elevating,
# creating an account or assigning SYSTEM ownership on the controller. Keep
# this inert fixture owned by its current operator; test SYSTEM-owner policy
# above with real security descriptors, and file ACEs below with real Get-Acl.
$savedOperator=$operatorSid
try{
 $operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 $transition=Join-Path $PSScriptRoot 'inheritance-transition'
 $stagedSecurity=New-AiwInputReadSecurity $sid -Staged
 $null=[IO.FileSystemAclExtensions]::CreateDirectory($stagedSecurity,$transition)
 foreach($name in @('application.msix','assembly.json','signing.json')){
  $path=Join-Path $transition $name;[IO.File]::WriteAllText($path,'inert')
  Assert-AiwInputSecurity (Get-Acl -LiteralPath $path) $sid -File -Staged;$accepted++
 }
 $policy=New-AiwInputReadSecurity $sid
 $directoryInfo=[IO.DirectoryInfo]::new($transition)
 $grant=[IO.FileSystemAclExtensions]::GetAccessControl($directoryInfo,[Security.AccessControl.AccessControlSections]::Access)
 foreach($rule in $policy.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier])){
  if($rule.IdentityReference.Value -ceq $sid){$grant.AddAccessRule($rule)}
 }
 [IO.FileSystemAclExtensions]::SetAccessControl($directoryInfo,$grant)
 foreach($name in @('application.msix','assembly.json','signing.json')){
  Assert-AiwInputSecurity (Get-Acl -LiteralPath (Join-Path $transition $name)) $sid -File;$accepted++
 }
 Reject {Assert-AiwInputSecurity (Get-Acl -LiteralPath $transition) $sid}
 $path=Join-Path $transition 'application.msix';$fileInfo=[IO.FileInfo]::new($path)
 $broken=[IO.FileSystemAclExtensions]::GetAccessControl($fileInfo,[Security.AccessControl.AccessControlSections]::Access)
 $broken.SetAccessRuleProtection($true,$false);[IO.FileSystemAclExtensions]::SetAccessControl($fileInfo,$broken)
 Reject {Assert-AiwInputSecurity (Get-Acl -LiteralPath $path) $sid -File}
}finally{$operatorSid=$savedOperator}
@{passed=$true;accepted=$accepted;rejected=$rejected;realInheritanceTransition=$true;systemOwnershipChanged=$false;enrollmentExecuted=$false;applicationExecuted=$false}|ConvertTo-Json -Compress
