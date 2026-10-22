param([Parameter(Mandatory=$true)][ValidateSet('Guard','Bind','Info')][string]$Operation)
# Fixed management bootstrap for the human-authorized fresh account, not a trial.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$directory='C:\AIW-Worker-Setup\Management'
$controller='192.168.1.165'
$adminSid='S-1-5-21-3849540285-1795134874-2442050430-1006'
$ruleNames=@('AIW106-WinRM-Controller','AIW106-DHCP-In','AIW106-DHCP-Out')

function Assert-ManagementIdentity([object]$o) {
    if ($o.Uuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or $o.Computer -cne 'PASSKEYS-WORKER' -or $o.Sid -cne 'S-1-5-18' -or -not $o.Is64Bit) {throw 'Worker SYSTEM identity required'}
    if ($o.Adapters.Count -ne 1 -or $o.Adapters[0].MacAddress -cne 'CC-34-21-7E-FE-59') {throw 'Exact worker adapter required'}
    if ($o.DomainJoined -or $o.TailscalePresent -or $o.AdminSid -cne 'S-1-5-21-3849540285-1795134874-2442050430-1006' -or -not $o.AdminEnabled) {throw 'Fresh offline worker identity changed'}
}
function Save-Management([string]$Phase) {
    $script:state.Phase=$Phase;$script:state.Utc=[DateTime]::UtcNow.ToString('o')
    $script:state|ConvertTo-Json -Depth 6|Set-Content -LiteralPath "$directory\state.json" -Encoding UTF8
}
function Assert-Firewall {
    # This same function is transported by the controller for remote proof.
    $controller='192.168.1.165'
    $ruleNames=@('AIW106-WinRM-Controller','AIW106-DHCP-In','AIW106-DHCP-Out')
    if (@(Get-Service MpsSvc,BFE|Where-Object Status -NE Running).Count) {throw 'Firewall services must be running'}
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
    if ($profiles.Count -ne 3 -or @($profiles|Where-Object {-not $_.Enabled -or $_.DefaultInboundAction -ne 'Block' -or $_.DefaultOutboundAction -ne 'Block'}).Count) {throw 'Effective firewall default-deny not verified'}
    $allow=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Action Allow)
    if ($allow.Count -ne 3 -or @($allow|Where-Object {$_.Name -notin $ruleNames}).Count) {throw 'Unexpected effective allow rule; keep NIC disconnected'}
    $adapter=@(Get-NetAdapter -Physical)
    if ($adapter.Count -ne 1 -or $adapter[0].MacAddress -cne 'CC-34-21-7E-FE-59') {throw 'Firewall interface identity changed'}
    foreach($name in $ruleNames) {
        $rule=@($allow|Where-Object Name -CEQ $name)
        if ($rule.Count -ne 1 -or $rule[0].Profile -ne 'Any' -or $rule[0].EdgeTraversalPolicy -ne 'Block') {throw 'Unexpected firewall rule profile or edge policy'}
        $rule=$rule[0]
        $address=$rule|Get-NetFirewallAddressFilter
        $port=$rule|Get-NetFirewallPortFilter
        $interface=$rule|Get-NetFirewallInterfaceFilter
        $service=$rule|Get-NetFirewallServiceFilter
        $application=$rule|Get-NetFirewallApplicationFilter
        if (@($interface.InterfaceAlias).Count -ne 1 -or $interface.InterfaceAlias -cne $adapter[0].Name -or $application.Program -ne 'Any' -or @($address.LocalAddress).Count -ne 1 -or $address.LocalAddress -ne 'Any') {throw 'Unexpected firewall interface, program or local address'}
        $dynamic=$rule.PSObject.Properties['RemoteDynamicKeywordAddresses']
        if ($null -ne $dynamic -and @($dynamic.Value|Where-Object {$_}).Count) {throw 'Unexpected dynamic firewall addresses'}
        $remote=@($address.RemoteAddress|ForEach-Object {$_.ToLowerInvariant().Replace('/255.255.255.0','/24').Replace('/255.255.255.255','/32').Replace('/32','')})
        if ($name -ceq $ruleNames[0]) {
            $direction='Inbound';$protocol='TCP';$localPort='5986';$remotePort='Any';$expectedAddresses=@($controller);$expectedService='Any'
        } elseif ($name -ceq $ruleNames[1]) {
            $direction='Inbound';$protocol='UDP';$localPort='68';$remotePort='67';$expectedAddresses=@('192.168.1.0/24');$expectedService='Dhcp'
        } else {
            $direction='Outbound';$protocol='UDP';$localPort='68';$remotePort='67';$expectedAddresses=@('192.168.1.0/24','255.255.255.255');$expectedService='Dhcp'
        }
        if ($rule.Direction -ne $direction -or $port.Protocol -ne $protocol -or @($port.LocalPort).Count -ne 1 -or $port.LocalPort -ne $localPort -or @($port.RemotePort).Count -ne 1 -or $port.RemotePort -ne $remotePort -or $service.Service -ine $expectedService -or (($remote|Sort-Object)-join ',') -cne (($expectedAddresses|Sort-Object)-join ',')) {throw "Firewall rule scope mismatch: $name"}
    }
}
try {
    $vm=Get-CimInstance Win32_ComputerSystemProduct
    if ($vm.UUID -ine '7e686bee-8c05-43c7-9603-a9562ece224c') {throw 'Wrong VM'}
    $computer=Get-CimInstance Win32_ComputerSystem
    $adapters=@(Get-NetAdapter -Physical)
    $admin=Get-LocalUser -Name AiwWorkerAdmin
    Assert-ManagementIdentity ([pscustomobject]@{Uuid=$vm.UUID;Computer=$env:COMPUTERNAME;Sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Is64Bit=[Environment]::Is64BitProcess;Adapters=$adapters;DomainJoined=$computer.PartOfDomain;TailscalePresent=@(Get-Service Tailscale -ErrorAction SilentlyContinue).Count -ne 0;AdminSid=$admin.SID.Value;AdminEnabled=$admin.Enabled})
    if ($Operation -eq 'Guard') {
        if ($adapters[0].Status -ne 'Disconnected' -or (Test-Path -LiteralPath $directory)) {throw 'Initial disconnected worker and absent management stage required'}
        $profile=@(Get-CimInstance Win32_UserProfile -Filter "SID='$adminSid'")
        if ($computer.UserName -ine 'PASSKEYS-WORKER\AiwWorkerAdmin' -or $profile.Count -ne 1 -or -not $profile[0].Loaded -or $profile[0].LocalPath -cne 'C:\Users\AiwWorkerAdmin') {throw 'Fresh administrator console session required'}
        if (@(Get-LocalGroupMember -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))|Where-Object {$_.SID.Value -ceq $adminSid}).Count -ne 1) {throw 'Fresh administrator membership required'}
        $parent=Get-Item -LiteralPath 'C:\AIW-Worker-Setup' -Force
        if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Unexpected management parent'}
        $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false)
        foreach($sid in @('S-1-5-18','S-1-5-32-544')) {$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))}
        [void][IO.Directory]::CreateDirectory($directory,$acl)
        $script:state=[ordered]@{VmUuid=$vm.UUID;Phase='Started';Controller=$controller;AdminSid=$adminSid;Ip=$null;CertificateThumbprint=$null;CertificateDer=$null;Result='inProgress'}
        Save-Management Started
        & "$env:WINDIR\System32\netsh.exe" advfirewall export "$directory\firewall-before.wfw" | Out-Null
        if ($LASTEXITCODE -ne 0) {throw 'Firewall backup failed'}
        Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
        Get-PSSessionConfiguration|Where-Object Name -CNE 'Microsoft.PowerShell'|ForEach-Object {Disable-PSSessionConfiguration -Name $_.Name -Force -NoServiceRestart|Out-Null}
        Restart-Service WinRM
        Set-Service WinRM -StartupType Automatic
        Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
        # This clone shares the controller's machine SID. Avoid NTLM/Kerberos;
        # explicit local credentials are sent only through validated HTTPS.
        Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
        Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false
        Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $false
        Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $false
        Get-ChildItem WSMan:\localhost\Listener|Where-Object {$_.Keys -contains 'Transport=HTTP'}|Remove-Item -Recurse -Force
        New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name LocalAccountTokenFilterPolicy -PropertyType DWord -Value 1 -Force|Out-Null
        # No copied profile is logged out/revoked/deleted. Disable copied accounts
        # only after measuring the real fresh administrator's console session.
        foreach($name in @('labadmin','CodexSandboxOffline','CodexSandboxOnline')) {
            $copied=Get-LocalUser -Name $name
            if ($copied.SID.AccountDomainSid.Value -cne $admin.SID.AccountDomainSid.Value) {throw 'Copied account domain SID changed'}
            Disable-LocalUser -SID $copied.SID
        }
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -AllowInboundRules True -AllowLocalFirewallRules True
        Get-NetFirewallRule -PolicyStore PersistentStore -Enabled True -Action Allow|Disable-NetFirewallRule
        New-NetFirewallRule -Name $ruleNames[0] -DisplayName 'VM106 WinRM HTTPS from controller only' -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort 5986 -RemoteAddress $controller -InterfaceAlias $adapters[0].Name|Out-Null
        New-NetFirewallRule -Name $ruleNames[1] -DisplayName 'VM106 DHCP replies only' -Direction Inbound -Action Allow -Profile Any -Protocol UDP -LocalPort 68 -RemotePort 67 -RemoteAddress '192.168.1.0/24' -Service Dhcp -InterfaceAlias $adapters[0].Name|Out-Null
        New-NetFirewallRule -Name $ruleNames[2] -DisplayName 'VM106 DHCP requests only' -Direction Outbound -Action Allow -Profile Any -Protocol UDP -LocalPort 68 -RemotePort 67 -RemoteAddress @('255.255.255.255','192.168.1.0/24') -Service Dhcp -InterfaceAlias $adapters[0].Name|Out-Null
        Assert-Firewall
        $state.Result='firewallGuardedBeforeNetwork'
        Save-Management Guarded
    } else {
        $item=Get-Item -LiteralPath $directory -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Unexpected management directory'}
        $script:state=Get-Content -LiteralPath "$directory\state.json" -Raw|ConvertFrom-Json
        if ($state.VmUuid -ine $vm.UUID -or $state.Controller -cne $controller -or $state.AdminSid -cne $adminSid) {throw 'Management stage identity changed'}
        Assert-Firewall
        if ($Operation -eq 'Bind') {
            if ($state.Phase -cne 'Guarded') {throw 'Management stage already used; preserve evidence'}
            $deadline=[DateTime]::UtcNow.AddSeconds(60)
            do {
                $ips=@(Get-NetIPAddress -InterfaceIndex $adapters[0].InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.AddressState -eq 'Preferred' -and $_.IPAddress -like '192.168.1.*' -and $_.PrefixLength -eq 24 -and $_.IPAddress -notin @('192.168.1.1','192.168.1.6',$controller)})
                if ($ips.Count -eq 1) {break}
                Start-Sleep -Seconds 2
            } while ([DateTime]::UtcNow -lt $deadline)
            if ($ips.Count -ne 1) {throw 'No unique worker IPv4 lease; preserve firewall and stage'}
            $ip=$ips[0].IPAddress
            Save-Management Binding
            $cert=New-SelfSignedCertificate -Type SSLServerAuthentication -Subject "CN=$ip" -TextExtension "2.5.29.17={text}IPAddress=$ip&DNS=PASSKEYS-WORKER" -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddMonths(3) -FriendlyName 'VM106 controller-only WinRM HTTPS'
            New-Item WSMan:\localhost\Listener -Transport HTTPS -Address '*' -Hostname $ip -CertificateThumbPrint $cert.Thumbprint -Force|Out-Null
            $state.Ip=$ip;$state.CertificateThumbprint=$cert.Thumbprint
            $state.CertificateDer=[Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            $state.Result='httpsManagementConfigured'
            Save-Management Ready
        }
        if ($state.Phase -cne 'Ready') {throw 'Management not ready'}
    }
    $state|ConvertTo-Json -Depth 6 -Compress
} catch {Write-Error -Message $_.Exception.Message -ErrorAction Continue;exit 1}
exit 0
