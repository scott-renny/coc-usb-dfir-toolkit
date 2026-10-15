#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','URLs','MSG','Decode','ExecutionReview','LateralReview','CloudAudit','RansomwareTriage','Coverage')][string]$Profile='Menu',[string]$InputRoot,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[switch]$Authorized,[switch]$ProtectedDestination)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if($Profile -eq 'Menu'){
    Write-CocMenuHeader 'SPECIALIST FIELD REVIEW' -ContentHeight 28
    Write-CocMenuOptions @('1. Offline URL interpretation (Unfurl)','2. Outlook MSG and attachment inventory','3. Strict base64 / hex decoding (Binary Refinery)','4. Tool guide and limits','5. Execution-related export review','6. Remote-access / lateral-movement event leads','7. Acquired cloud audit export review','8. Ransomware file / note triage','9. Supplied-evidence coverage report','0. Back')
    $choice=Read-CocPrompt 'Select';if($choice -eq '0'){return}
    if($choice -eq '4'){Start-Process -FilePath (Join-Path $root 'COC\docs\ENRICHMENT-TOOLS.md');return}
    $map=@{'1'='URLs';'2'='MSG';'3'='Decode';'5'='ExecutionReview';'6'='LateralReview';'7'='CloudAudit';'8'='RansomwareTriage';'9'='Coverage'}
    if(-not $map.ContainsKey($choice)){throw 'Invalid selection'};$Profile=$map[$choice]
    $InputRoot=Read-CocPrompt 'Acquired working-copy folder outside toolkit'
    $OutputRoot=Read-CocPrompt 'Existing protected output parent outside input and toolkit'
    $CaseId=Read-CocPrompt 'Case ID';$Authority=Read-CocPrompt 'Owner authorization/reference'
    if((Read-CocPrompt 'Type RUN to approve offline analysis') -cne 'RUN'){return};$Authorized=$true;$ProtectedDestination=$true
}
if(-not $Authorized){throw 'Explicit authority required'}
Test-CocRelease $root|Out-Host
$session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('Enrichment-'+$Profile) -ProtectedDestination:$ProtectedDestination
$session.Metadata.limitations=@('Acquired working-copy analysis only. No URLs visited, uploads, or evidence execution.','Parser subprocess audit hooks block network connection and process-launch APIs; this is not an operating-system malware sandbox.','Unfurl optional extras and Binary Refinery operations beyond the fixed base64/hex workflow are not accepted.','Source hashes are checked before and after; excerpts and unsupported MSG objects need analyst review.')
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$complete=$false
try{
    Write-CocEvent $session 'enrichment.started' -Message ('Selected '+$Profile)
    & (Join-Path $root 'COC\tools\windows\Python\python.exe') -B (Join-Path $PSScriptRoot 'enrichment_pipeline.py') --toolkit $root --case $session.Path --profile $Profile --input $InputRoot
    if($LASTEXITCODE -ne 0){throw 'Analysis is partial; inspect raw results and parser logs'}
    $complete=$true;Write-CocEvent $session 'enrichment.finished' -Message 'Fixed offline parser completed; analyst review required'
}catch{Write-CocEvent $session 'enrichment.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $artifact=Join-Path $session.Path 'raw\analysis-result.json'
    if(-not (Test-Path -LiteralPath $artifact)){Write-CocJson $artifact @{status='PARTIAL';reason='Stopped before parser result'}}
    $session.Metadata.modules+=@{name=('enrichment-'+$Profile);status=$(if($complete){'collected'}else{'failed'});detail='Review parser results, excerpts and limitations';artifact='raw/analysis-result.json'}
    $result=Complete-CocRun $session -FinalStatus $(if($complete){''}else{'PARTIAL'})
    Test-CocArtifacts $result|Out-Host;Write-CocCentered ('Case saved: '+$result)
}
