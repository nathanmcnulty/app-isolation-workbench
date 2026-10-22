# Mock only the read-only firewall APIs; never changes any real firewall rule.
$ErrorActionPreference='Stop'
$t=$null;$e=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot Enable-Worker106Management.ps1),[ref]$t,[ref]$e)
$f=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-Firewall'},$true))
if($e.Count -or $f.Count -ne 1){throw 'Unique parsed verifier required'}
Invoke-Expression $f[0].Extent.Text
function Get-Service {param($Name) [pscustomobject]@{Status='Running'}}
function Get-NetAdapter {param([switch]$Physical) [pscustomobject]@{Name='Ethernet';MacAddress='CC-34-21-7E-FE-59'}}
function Get-NetFirewallProfile {param($PolicyStore) if($PolicyStore -cne 'ActiveStore'){throw 'ActiveStore required'};1..3|ForEach-Object{[pscustomobject]@{Enabled=$true;DefaultInboundAction='Block';DefaultOutboundAction='Block'}}}
function Get-NetFirewallRule {param($PolicyStore,$Enabled,$Action) if($PolicyStore -cne 'ActiveStore'){throw 'ActiveStore required'};$script:rules}
function Get-NetFirewallAddressFilter {param([Parameter(ValueFromPipeline)]$InputObject) process{$InputObject.Address}}
function Get-NetFirewallPortFilter {param([Parameter(ValueFromPipeline)]$InputObject) process{$InputObject.Port}}
function Get-NetFirewallInterfaceFilter {param([Parameter(ValueFromPipeline)]$InputObject) process{$InputObject.Interface}}
function Get-NetFirewallServiceFilter {param([Parameter(ValueFromPipeline)]$InputObject) process{$InputObject.ServiceFilter}}
function Get-NetFirewallApplicationFilter {param([Parameter(ValueFromPipeline)]$InputObject) process{$InputObject.Application}}
$script:rules=@(
    [pscustomobject]@{Name='AIW106-WinRM-Controller';Profile='Any';EdgeTraversalPolicy='Block';Direction='Inbound';Address=[pscustomobject]@{LocalAddress=@('Any');RemoteAddress=@('192.168.1.165')};Port=[pscustomobject]@{Protocol='TCP';LocalPort=@('5986');RemotePort=@('Any')};Interface=[pscustomobject]@{InterfaceAlias=@('Ethernet')};ServiceFilter=[pscustomobject]@{Service='Any'};Application=[pscustomobject]@{Program='Any'}},
    [pscustomobject]@{Name='AIW106-DHCP-In';Profile='Any';EdgeTraversalPolicy='Block';Direction='Inbound';Address=[pscustomobject]@{LocalAddress=@('Any');RemoteAddress=@('192.168.1.0/24')};Port=[pscustomobject]@{Protocol='UDP';LocalPort=@('68');RemotePort=@('67')};Interface=[pscustomobject]@{InterfaceAlias=@('Ethernet')};ServiceFilter=[pscustomobject]@{Service='Dhcp'};Application=[pscustomobject]@{Program='Any'}},
    [pscustomobject]@{Name='AIW106-DHCP-Out';Profile='Any';EdgeTraversalPolicy='Block';Direction='Outbound';Address=[pscustomobject]@{LocalAddress=@('Any');RemoteAddress=@('255.255.255.255','192.168.1.0/24')};Port=[pscustomobject]@{Protocol='UDP';LocalPort=@('68');RemotePort=@('67')};Interface=[pscustomobject]@{InterfaceAlias=@('Ethernet')};ServiceFilter=[pscustomobject]@{Service='Dhcp'};Application=[pscustomobject]@{Program='Any'}}
)
Assert-Firewall
$valid=$rules|ConvertTo-Json -Depth 7
$cases=@(
 {param($r)$r[2].Address.RemoteAddress=@('Any')}, {param($r)$r[2].Port.RemotePort=@('Any')},
 {param($r)$r[2].Port.LocalPort=@('Any')}, {param($r)$r[2].Port.Protocol='Any'},
 {param($r)$r[2].ServiceFilter.Service='Any'}, {param($r)$r[1].Interface.InterfaceAlias=@('Any')},
 {param($r)$r[0].Interface.InterfaceAlias=@('Any')}, {param($r)$r[0].Direction='Outbound'},
 {param($r)$r[0].Address.RemoteAddress=@('Any')}, {param($r)$r[0].Port.LocalPort=@('Any')},
 {param($r)$r[1].Address.RemoteAddress=@('0.0.0.0/0')}, {param($r)$r[1].Profile='Public'},
 {param($r)$r[0].EdgeTraversalPolicy='Allow'}
)
foreach($case in $cases){$script:rules=@($valid|ConvertFrom-Json);&$case $rules;$reject=$false;try{Assert-Firewall}catch{$reject=$true};if(-not $reject){throw 'Broadened firewall accepted'}}
$script:rules=@($valid|ConvertFrom-Json)
$rules[1].Address.RemoteAddress=@('192.168.1.0/255.255.255.0')
Assert-Firewall
[ordered]@{Accepted=2;Rejected=$cases.Count;RealFirewallAccess=$false}|ConvertTo-Json
