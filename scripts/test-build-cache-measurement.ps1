#Requires -Version 7.6
#Requires -PSEdition Core
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'build-assessment-tools.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Build script does not parse'}
$function=$ast.Find({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Measure-Cache'},$true)
. ([scriptblock]::Create($function.Extent.Text))
$root=Join-Path ([IO.Path]::GetTempPath()) ('aiw-cache-sample-'+[guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($root)
$writer=[PowerShell]::Create();$pending=$null;$samples=0
try {
    $null=$writer.AddScript({param($root)
        for($i=0;$i -lt 1000;$i++){
            $directory=Join-Path $root ('rustc-temp-'+($i%3))
            $null=[IO.Directory]::CreateDirectory($directory)
            $file=Join-Path $directory 'temporary.o'
            [IO.File]::WriteAllBytes($file,[byte[]]::new(64))
            [IO.File]::Delete($file);[IO.Directory]::Delete($directory)
        }
    }).AddArgument($root)
    $pending=$writer.BeginInvoke()
    while(-not $pending.IsCompleted -or $samples -lt 20){
        $measurement=Measure-Cache $root -AllowTransientIO
        # A running sample spans generations, unlike the strict final sample.
        if($measurement.bytes -lt 0 -or $measurement.bytes -gt 64000 -or $measurement.files -lt 0 -or $measurement.files -gt 1000){throw 'Invalid sampled cache size'}
        $samples++
    }
    $null=$writer.EndInvoke($pending)
    if($writer.HadErrors){throw 'Owned file-churn worker failed'}
    if((Measure-Cache $root).bytes -ne 0){throw 'Temporary compiler files remain'}
} finally {
    if($pending -and -not $pending.IsCompleted){$writer.Stop()}
    $writer.Dispose()
    if([IO.Path]::GetFileName($root) -cnotmatch '^aiw-cache-sample-[0-9a-f]{32}$'){throw 'Unexpected fixture root'}
    Remove-Item -LiteralPath $root -Recurse -Force
}
[ordered]@{passed=$true;samples=$samples;transientDirectoryCycles=1000;fixtureRemoved=-not(Test-Path -LiteralPath $root);cargoInvocations=0}|ConvertTo-Json -Compress
