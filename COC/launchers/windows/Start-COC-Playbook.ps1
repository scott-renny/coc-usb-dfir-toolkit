#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu','FieldAssessment','IncidentTriage','Practice')][string]$Mode='Menu',
    [string]$OutputRoot,[string]$CaseId,[string]$Authority,
    [switch]$Authorized,[switch]$ProtectedDestination
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Playbooks.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if ($Mode -eq 'Menu') {
    Write-CocMenuHeader 'AUTOMATED PLAYBOOKS'
    Write-CocCentered '1 Field security assessment'
    Write-CocCentered '2 Live incident triage (includes current processes/connections)'
    Write-CocCentered '3 Harmless practice run (synthetic data only)'
    Write-CocCentered '0 Exit'
    $choice=Read-CocPrompt 'Select'
    switch ($choice) {'1' {$Mode='FieldAssessment'} '2' {$Mode='IncidentTriage'} '3' {$Mode='Practice'} '0' {return} default {throw 'Invalid selection'}}
    $CaseId=Read-CocPrompt 'Case ID'
    $OutputRoot=Read-CocPrompt 'Existing output directory outside executable toolkit'
    if ($Mode -eq 'Practice') {$Authority='Synthetic practice only'} else {$Authority=Read-CocPrompt 'Owner authorization/reference'}
    $plan=@(Get-CocPlaybookPlan $Mode)
    $plan|Select-Object phase,id,purpose|Format-Table -AutoSize
    Write-CocCentered 'After approval, collection, logging, reports and hash verification run automatically.'
    if ($Mode -ne 'Practice') {Write-CocCentered 'Use protected output. Do not mount an existing shared vault on a suspect host. Collection changes live state.'}
    if ((Read-CocPrompt 'Confirm this scope and destination: type RUN') -cne 'RUN') {return}
    $Authorized=$true
    if ($Mode -ne 'Practice') {$ProtectedDestination=$true}
}
if ($Mode -ne 'Practice' -and -not $Authorized) {throw 'Explicit authorization is required for real-host collection.'}
Test-CocRelease $root | Out-Host
if ($Mode -eq 'Practice' -and [string]::IsNullOrWhiteSpace($Authority)) {$Authority='Synthetic practice only'}
$session=New-CocRun $root $OutputRoot $CaseId $Authority $Mode -ProtectedDestination:$ProtectedDestination -Synthetic:($Mode -eq 'Practice')
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$session.Metadata.collector_runtime=$PSVersionTable.PSVersion.ToString()
$completed=$false
try {
    Invoke-CocPlaybook $session $Mode
    $completed=$true
} catch {
    Write-CocEvent $session 'playbook.failed' -Level ERROR -Message $_.Exception.Message
    throw
} finally {
    $status=if ($completed) {''} else {'FAILED'}
    $casePath=Complete-CocRun $session -FinalStatus $status
    Test-CocArtifacts $casePath | Out-Host
    Write-CocCentered ('Report: '+(Join-Path $casePath 'report.html')) -ForegroundColor Green
    Write-CocCentered ('Logs and documentation: '+$casePath)
}
