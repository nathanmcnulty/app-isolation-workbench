#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Check the actual Windows account API's description limit without creating users.
$tokens=$null;$errors=$null
$workerAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'worker107-msix.ps1'),[ref]$tokens,[ref]$errors)
$createUser=@($workerAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq 'New-LocalUser'},$true))
if($createUser.Count -ne 1){throw 'One closed account creation command required'}
$elements=$createUser[0].CommandElements
$description=$null
for($index=0;$index -lt $elements.Count-1;$index++){
    if($elements[$index] -is [Management.Automation.Language.CommandParameterAst] -and $elements[$index].ParameterName -eq 'Description'){
        if($elements[$index+1] -isnot [Management.Automation.Language.StringConstantExpressionAst]){throw 'Literal trial account description required'}
        $description=$elements[$index+1].Value
    }
}
$limits=@((Get-Command New-LocalUser).Parameters['Description'].Attributes|Where-Object{$_ -is [Management.Automation.ValidateLengthAttribute]})
if(!$description -or $limits.Count -ne 1 -or $description.Length -gt $limits[0].MaxLength -or $description.Length -lt $limits[0].MinLength){throw 'Trial account description violates Windows API constraint'}
. (Join-Path $PSScriptRoot 'worker107-msix-templates.ps1')
$parsed=0
$roundTrips=0;$wrongDurations=0;$scopeBindings=0
foreach($name in @('worker107-msix.ps1','worker107-editor.ps1','invoke-worker107-msix.ps1','build-worker107-msix-payload.ps1')){
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors|Out-String)};$parsed++
}
foreach($mode in @('Control','Trial')){
    $worker=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'worker107-scheduler-worker.ps1.in') -Raw
    $controller=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'worker107-scheduler-controller.ps1.in') -Raw
    if($mode -eq 'Trial'){$worker=ConvertTo-LifecycleWorker $worker;$controller=ConvertTo-LifecycleController $controller}
    $values=@{MODE=$mode;NONCE=('b'*64);TRIAL_SID='S-1-5-21-3556347314-2314855617-1438300668-2000';DRIVER_SHA=('a'*64);CMD_SHA=('c'*64);PREP_SHA=('d'*64);BASELINE_SHA=('e'*64);ROOT=('C:\AIW-Task-Primary-'+$mode+'-'+('b'*64))}
    foreach($key in $values.Keys){$worker=$worker.Replace('@@'+$key+'@@',$values[$key]);$controller=$controller.Replace('@@'+$key+'@@',$values[$key])}
    $controller=$controller.Replace('@@WORKER_B64@@',[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($worker)))
    if($worker.Contains('@@') -or $controller.Contains('@@')){throw 'Unresolved template'}
    foreach($source in @($worker,$controller)){
        $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
        if($errors.Count){throw ($errors|Out-String)};$parsed++
        if($source.Contains('169.254.169.254') -or $source.Contains('3407263227-439785483-4249424476')){throw 'Historical Azure binding survived'}
    }
    # Exercise the actual Scheduler XML round trip in memory. No task is registered.
    $nonce='b'*64;$root=$values.ROOT;$ps='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$root+'\worker.ps1"'
    $xmlMatch=[regex]::Match($controller,'(?ms)^\$xml=@"\r?\n(.*?)\r?\n"@')
    if(!$xmlMatch.Success){throw 'Actual controller XML source missing'}
    $scheduler=New-Object -ComObject Schedule.Service;$scheduler.Connect()
    $definition=$scheduler.NewTask(0);$definition.XmlText=$ExecutionContext.InvokeCommand.ExpandString($xmlMatch.Groups[1].Value)
    $definition.Principal.UserId='S-1-5-18';$definition.Principal.LogonType=5;$definition.Principal.RunLevel=1;$definition.Principal.Id='AiwSystem';$definition.Actions.Context='AiwSystem'
    $tokens=$null;$errors=$null;$controllerAst=[Management.Automation.Language.Parser]::ParseInput($controller,[ref]$tokens,[ref]$errors)
    $verify=$controllerAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Verify-Definition'},$true)
    . ([scriptblock]::Create($verify.Extent.Text))
    Verify-Definition $definition;$roundTrips++
    $definition.Settings.ExecutionTimeLimit='PT261S'
    $rejected=$false;try{Verify-Definition $definition}catch{if($_.Exception.Message -ne 'Task execution duration differs'){throw};$rejected=$true}
    if(!$rejected){throw 'Wrong Scheduler duration accepted'};$wrongDurations++
    $binding=$controllerAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Bind-Native'},$true)
    & {
        param($functionSource)
        Set-StrictMode -Version Latest
        $nativeCustody=[pscustomobject]@{Process=$null}
        function Test-Path {param($LiteralPath) $false}
        . ([scriptblock]::Create($functionSource))
        Bind-Native
        $held=[pscustomobject]@{sentinel=$true};$nativeCustody.Process=$held
        Bind-Native
        if(![object]::ReferenceEquals($held,$nativeCustody.Process)){throw 'Held identity changed across function scope'}
    } $binding.Extent.Text
    $scopeBindings++
    if(!$controller.Contains('Exact native process custody was not acquired') -or !$controller.Contains('Native custody/exit unconfirmed; cold recovery required')){throw 'Native process custody guard missing'}
    if($mode -eq 'Trial'){
        if(!$worker.Contains("'vm-controller'") -or $worker.Contains('launch-control-result.json') -or !$worker.Contains("Publish 'native-lifecycle.json'")){throw 'Full lifecycle terminal path differs'}
        if($controller.Contains('$native.result.exitCode -ne 42') -or !$controller.Contains('PT1500S')){throw 'Trial kept control-only predicate/deadline'}
    }elseif(!$worker.Contains("'vm-launch-control'") -or !$worker.Contains('launch-control-result.json')){throw 'Control path differs'}
}
Add-Type -Path (Join-Path $PSScriptRoot 'worker107-editor-input.cs')
$inputValue=[Activator]::CreateInstance([AiwOwnedEditorInput].GetNestedType('Input',[Reflection.BindingFlags]::NonPublic),$true)
if([Runtime.InteropServices.Marshal]::SizeOf($inputValue) -ne 40){throw 'Expected x64 INPUT layout differs'}
# All executable worker operations must refuse this ordinary development token
# before touching worker paths or invoking the native editor input methods.
foreach($op in @('Stage','Enroll','Trial','Edit')){
    $rejected=$false
    try {& (Join-Path $PSScriptRoot 'worker107-msix.ps1') -Operation $op|Out-Null}catch{if($_.Exception.Message -like '*SYSTEM session zero*'){$rejected=$true}else{throw}}
    if(!$rejected){throw 'Development token entered an executable worker operation'}
}
[ordered]@{passed=$true;powerShellVersion=$PSVersionTable.PSVersion.ToString();parsedSources=$parsed;renderedModes=2;schedulerXmlRoundTrips=$roundTrips;wrongDurationsRejected=$wrongDurations;childScopeBindings=$scopeBindings;tasksRegistered=$false;developmentTokenRejections=4;editorSourceCompiled=$true;editorInputInvoked=$false;applicationTrialExecuted=$false}|ConvertTo-Json
