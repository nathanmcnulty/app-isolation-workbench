#Requires -Version 7.6
#Requires -PSEdition Core
# Inert samples of actual Cargo verbose command syntax; no build or app execution.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'build-assessment-tools.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Build script does not parse'}
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Inspect-CompilerLog'},$true)
if(-not $function){throw 'Compiler log inspector absent'}
. ([scriptblock]::Create($function.Extent.Text))
$path=Join-Path ([IO.Path]::GetTempPath()) ('aiw-compiler-log-'+[guid]::NewGuid().ToString('N')+'.txt')
$count=0
try {
    foreach($flags in @('-C strip=debuginfo','-C debuginfo=0','-Cdebuginfo=0','-C debuginfo=none','')) {
        [IO.File]::WriteAllText($path,('Running `rustc --crate-name aiw '+$flags+'`'))
        if((Inspect-CompilerLog $path).rustcInvocations -ne 1){throw 'Compiler invocation missing'};$count++
    }
    foreach($flags in @('-g','-C debuginfo=2','-Cdebuginfo=1','-C debuginfo=line-tables-only','-C incremental=C:\owned-cache','-Cincremental=C:\owned-cache')) {
        [IO.File]::WriteAllText($path,('Running `rustc --crate-name aiw '+$flags+'`'))
        $refused=$false;try{$null=Inspect-CompilerLog $path}catch{$refused=$true}
        if(-not $refused){throw 'Compiler storage override was accepted'};$count++
    }
    [IO.File]::WriteAllText($path,'Fresh aiw v0.1.0')
    if((Inspect-CompilerLog $path).rustcInvocations -ne 0){throw 'Fresh build was counted as compilation'};$count++
} finally {if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}}
[ordered]@{passed=$count;cargoInvocations=0;fixtureRemoved=-not(Test-Path -LiteralPath $path)}|ConvertTo-Json -Compress
