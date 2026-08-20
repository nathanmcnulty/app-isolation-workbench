@{
    RootModule = 'AppIsolationWorkbench.psm1'
    ModuleVersion = '0.1.0'
    GUID = '8f8a7a85-09e0-4d1f-b19e-c6f401f9243c'
    Author = 'Nathan McNulty'
    CompanyName = 'Community'
    Copyright = '(c) 2026 Nathan McNulty. All rights reserved.'
    Description = 'Thin PowerShell administration surface for the App Isolation Workbench CLI.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'ConvertTo-AiwWindowsSandboxConfig',
        'Get-AiwHostProbe',
        'Get-AiwMxcCapabilityProbePlan',
        'Get-AiwMxcInvocationPlan',
        'Get-AiwTokenEvidence',
        'Invoke-Aiw',
        'Get-AiwAssessmentBundleManifest',
        'Test-AiwAssessmentBundle',
        'Test-AiwCanaryObservationSet',
        'Test-AiwEvidence',
        'Test-AiwProject'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Tags = @('Windows', 'AppContainer', 'MSIX', 'Sandbox', 'Security')
            ProjectUri = 'https://github.com/nathanmcnulty/app-isolation-workbench'
        }
    }
}
