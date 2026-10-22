# Standard remote administration explicitly requested by the operator.
# Establish trust only from the fixed QGA bootstrap's authenticated certificate.
Set-StrictMode -Version Latest
function Connect-Worker106 {
    $ErrorActionPreference='Stop'
    if ((Get-CimInstance Win32_ComputerSystemProduct).UUID -ieq '7e686bee-8c05-43c7-9603-a9562ece224c') {throw 'Connect from controller only'}
    if (@(Get-NetIPAddress -AddressFamily IPv4|Where-Object IPAddress -CEQ '192.168.1.165').Count -ne 1) {throw 'Pinned controller address changed'}
    $record=Get-Content -LiteralPath 'C:\passkeys\worker106-tools\management-bootstrap-result.json' -Raw|ConvertFrom-Json
    if ($record.ExitCode -ne 0) {throw 'Bootstrap receipt failed'}
    $journal=$record.Output[0]|ConvertFrom-Json
    if ($journal.phase -cne 'finished' -or $journal.operation -cne 'Bind' -or $journal.result.exitcode -ne 0 -or $journal.result.'out-truncated') {throw 'Bootstrap not complete'}
    $binding=$journal.result.'out-data'|ConvertFrom-Json
    if ($binding.Phase -cne 'Ready' -or $binding.Result -cne 'httpsManagementConfigured' -or $binding.VmUuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or $binding.Controller -cne '192.168.1.165' -or $binding.AdminSid -cne 'S-1-5-21-3849540285-1795134874-2442050430-1006') {throw 'Unexpected management identity'}
    $payloadPath=Join-Path $PSScriptRoot Enable-Worker106Management.ps1
    $source=[IO.File]::ReadAllText($payloadPath).Replace("`r`n","`n")
    $hash=[Security.Cryptography.SHA256]::Create()
    try {$sourceHash=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($source)))).Replace('-','').ToLowerInvariant()} finally {$hash.Dispose()}
    if ($journal.payload -cne $sourceHash) {throw 'Bootstrap and local firewall verifier source hashes differ'}
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$parseErrors)
    $functions=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Assert-Firewall'},$true))
    if ($parseErrors.Count -or $functions.Count -ne 1) {throw 'Unique fixed firewall verifier required'}
    $firewallFunction=$functions[0].Extent.Text
    $ip=[Net.IPAddress]::Parse($binding.Ip)
    $octets=$ip.GetAddressBytes()
    if ($octets.Length -ne 4 -or $octets[0] -ne 192 -or $octets[1] -ne 168 -or $octets[2] -ne 1 -or $octets[3] -in @(0,1,6,165,255)) {throw 'Unexpected worker address'}
    $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($binding.CertificateDer))
    if ($certificate.Thumbprint -cne $binding.CertificateThumbprint -or $certificate.Subject -cne "CN=$ip" -or $certificate.NotAfter -le (Get-Date) -or $certificate.NotBefore -gt (Get-Date)) {throw 'QGA certificate identity mismatch'}
    $store=[Security.Cryptography.X509Certificates.X509Store]::new('Root','CurrentUser')
    try {$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$store.Add($certificate)} finally {$store.Close()}
    [ordered]@{Ip=$ip.ToString();Port=5986;CertificateThumbprint=$certificate.Thumbprint;TrustStore='CurrentUser\Root';TrustRemoval="Remove-Item Cert:\CurrentUser\Root\$($certificate.Thumbprint)";Authentication='Basic inside validated HTTPS';Utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content 'C:\passkeys\worker106-tools\management-trust.json'
    $credential=Import-Clixml -LiteralPath 'C:\passkeys\worker106-tools\worker-admin-recovery\worker-admin.credential.clixml'
    $session=New-PSSession -ComputerName $ip.ToString() -Port 5986 -UseSSL -Authentication Basic -Credential $credential -ConfigurationName Microsoft.PowerShell -SessionOption (New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 60000)
    try {
        $proof=Invoke-Command -Session $session -ArgumentList $ip.ToString(),$certificate.Thumbprint,$firewallFunction -ScriptBlock {
            param($ExpectedIp,$ExpectedThumbprint,$FirewallFunction)
            $ErrorActionPreference='Stop'
            $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
            $admin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            $uuid=(Get-CimInstance Win32_ComputerSystemProduct).UUID
            $adapter=@(Get-NetAdapter -Physical)
            if ($uuid -ine '7e686bee-8c05-43c7-9603-a9562ece224c' -or $env:COMPUTERNAME -cne 'PASSKEYS-WORKER' -or $identity.User.Value -cne 'S-1-5-21-3849540285-1795134874-2442050430-1006' -or -not $admin) {throw 'Remote administrator proof failed'}
            if ($adapter.Count -ne 1 -or $adapter[0].MacAddress -cne 'CC-34-21-7E-FE-59' -or $adapter[0].Status -ne 'Up') {throw 'Remote worker adapter mismatch'}
            if (@(Get-NetIPAddress -InterfaceIndex $adapter[0].InterfaceIndex -AddressFamily IPv4|Where-Object {$_.IPAddress -ceq $ExpectedIp -and $_.PrefixLength -eq 24}).Count -ne 1) {throw 'Remote worker IP mismatch'}
            . ([scriptblock]::Create($FirewallFunction))
            Assert-Firewall
            $listeners=@(Get-ChildItem WSMan:\localhost\Listener)
            if ($listeners.Count -ne 1 -or $listeners[0].Keys -notcontains 'Transport=HTTPS') {throw 'Unexpected WinRM listener'}
            if ((Get-Item ($listeners[0].PSPath+'\CertificateThumbprint')).Value -cne $ExpectedThumbprint -or (Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value -ne 'false') {throw 'Remote TLS binding mismatch'}
            if (@(Get-Service MpsSvc,BFE,WinRM|Where-Object Status -NE Running).Count) {throw 'Management/firewall service stopped'}
            [pscustomobject]@{VmUuid=$uuid;Computer=$env:COMPUTERNAME;User=$identity.Name;Sid=$identity.User.Value;Elevated=$admin;Ip=$ExpectedIp;Mac=$adapter[0].MacAddress;CertificateThumbprint=$ExpectedThumbprint;CertificateValidation='normal HTTPS validation; no skip switches';Firewall='all profiles enabled, default inbound/outbound block, three scoped exceptions';WinRM='HTTPS only';Utc=[DateTime]::UtcNow.ToString('o')}
        }
        $proof|ConvertTo-Json -Depth 5|Set-Content 'C:\passkeys\worker106-tools\management-remote-proof.json'
        return $session
    } catch {Remove-PSSession $session;throw}
}
