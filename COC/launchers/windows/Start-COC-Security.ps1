#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu','Verify','Posture','Triage','FileCheck','VerifyCase')][string]$Profile='Menu',
    [string]$OutputRoot,[string]$CaseId,[string]$Authority,[string]$SelectedFile,[string]$RunPath,
    [switch]$ProtectedDestination,[switch]$Authorized,[switch]$IncludeImages
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Playbooks.psm1') -Force
$toolkitRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if ($Profile -eq 'VerifyCase') { Test-CocArtifacts $RunPath; return }
if ($Profile -eq 'Menu') {
    Write-CocMenuHeader 'SECURITY COLLECTION'
    Write-CocCentered '1 Verify toolkit (including boot images)'
    Write-CocCentered '2 Windows security posture collection'
    Write-CocCentered '3 Windows live incident triage (no memory acquisition)'
    Write-CocCentered '4 Selected file hash and signature check'
    Write-CocCentered '5 Verify an existing case'
    Write-CocCentered '6 Automated playbook (assessment / incident / harmless practice)'
    Write-CocCentered '7 Expanded tool catalog and acquired-file parsers'
    Write-CocCentered '8 DFIR evidence automation'
    Write-CocCentered '0 Exit'
    $choice=Read-CocPrompt 'Select'
    switch ($choice) {
        '0' { return }
        '1' { Test-CocRelease $toolkitRoot -IncludeImages; return }
        '2' { $Profile='Posture' }
        '3' { $Profile='Triage' }
        '4' { $Profile='FileCheck';$SelectedFile=Read-CocPrompt 'Full path to one selected file (no execution)' }
        '5' { $RunPath=Read-CocPrompt 'Case run directory';Test-CocArtifacts $RunPath;return }
        '6' { & (Join-Path $PSScriptRoot 'Start-COC-Playbook.ps1');return }
        '7' { & (Join-Path $PSScriptRoot 'Start-COC-Tools.ps1');return }
        '8' { & (Join-Path $PSScriptRoot 'Start-COC-DFIR.ps1');return }
        default { throw 'Invalid menu choice.' }
    }
    $CaseId=Read-CocPrompt 'Case ID (letters/digits/underscore/hyphen)'
    $Authority=Read-CocPrompt 'Owner authorization/reference'
    $OutputRoot=Read-CocPrompt 'Existing protected output directory outside toolkit'
    Write-CocCentered 'This collects local security data and leaves normal Windows execution artifacts. No repair or upload is performed.'
    Write-CocCentered 'Do not unlock a shared case vault on a suspect host. Protect and control the output medium separately.'
    if ((Read-CocPrompt 'Confirm authority, selected profile and protected destination: type RUN') -cne 'RUN') { return }
    $Authorized=$true;$ProtectedDestination=$true
}
Test-CocRelease $toolkitRoot | Out-Host
if ($Profile -eq 'Verify') { if ($IncludeImages) { Test-CocRelease $toolkitRoot -IncludeImages };return }
if (-not $Authorized) { throw 'Explicit -Authorized scope acknowledgment is required.' }
if ($Profile -eq 'FileCheck') {
    if (-not (Test-Path -LiteralPath $SelectedFile -PathType Leaf)) { throw 'Select one existing file.' }
    Assert-CocNoReparse $SelectedFile
    if ((Get-Item -LiteralPath $SelectedFile).Length -gt 1GB) { throw 'File exceeds the 1 GiB limit.' }
    $SelectedFile=(Resolve-Path -LiteralPath $SelectedFile).Path
}
$session=New-CocRun -ToolkitRoot $toolkitRoot -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile $Profile -ProtectedDestination:$ProtectedDestination
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $toolkitRoot 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$session.Metadata.collector_runtime=$PSVersionTable.PSVersion.ToString()
$completed=$false
try {
    if ($Profile -in @('Posture','Triage')) {
        $mode=if ($Profile -eq 'Triage') {'IncidentTriage'} else {'FieldAssessment'}
        Invoke-CocPlaybook $session $mode
    } else {
        Invoke-CocModule $session 'selected-file' { param($File) $item=Get-Item -LiteralPath $File;$sig=Get-AuthenticodeSignature -LiteralPath $File;[pscustomobject]@{name=$item.Name;bytes=$item.Length;last_write_utc=$item.LastWriteTimeUtc.ToString('o');sha256=(Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash;signature_status=[string]$sig.Status;signer=if ($sig.SignerCertificate) {$sig.SignerCertificate.Subject}else {$null}} } -TimeoutSeconds 120 -Arguments @($SelectedFile)
    }
    $completed=$true
} finally {
    $final=if ($completed) { '' } else { 'FAILED' }
    $result=Complete-CocRun $session -FinalStatus $final
    Test-CocArtifacts $result | Out-Host
    Write-CocCentered "Case saved: $result"
}
