#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','Inventory','ArtifactBatch','EventTimeline','FileTriage','SQLiteReview','Practice','BrowserProfile','AndroidArtifacts','iOSArtifacts','OfflineTriage','CollectEventLogs','ExecutableAssessment','MetadataAssessment','NetworkAssessment','GoSymbols','IncidentTimeline','SuspiciousAssessment','BulkFeatures')][string]$Profile='Menu',[string]$InputRoot,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[switch]$Authorized,[switch]$ProtectedDestination)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if($Profile -eq 'Menu'){
    Write-CocMenuHeader 'ACQUIRED-EVIDENCE AUTOMATION' -ContentHeight 35
    Write-CocMenuOptions @('1 Evidence inventory and hashes','2 Artifact batch','3 EVTX timeline','4 File triage','5 SQLite schema review','6 Harmless practice','7 Browser profile','8 Android artifacts','9 iOS artifacts','10 Combined offline triage','11 Authorized live Windows EVTX export (24 hours)','12 Executable assessment','13 Basic file metadata inventory','14 Offline packet-capture assessment','15 Go executable symbol recovery','16 Combined Windows incident timeline','17 Suspicious executable or document assessment','18 Bounded email and URL feature extraction','0 Exit')
    $map=@{'1'='Inventory';'2'='ArtifactBatch';'3'='EventTimeline';'4'='FileTriage';'5'='SQLiteReview';'6'='Practice';'7'='BrowserProfile';'8'='AndroidArtifacts';'9'='iOSArtifacts';'10'='OfflineTriage';'11'='CollectEventLogs'}
    $map['12']='ExecutableAssessment';$map['13']='MetadataAssessment';$map['14']='NetworkAssessment'
    $map['15']='GoSymbols';$map['16']='IncidentTimeline';$map['17']='SuspiciousAssessment';$map['18']='BulkFeatures'
    $choice=Read-CocPrompt 'Select';if($choice -eq '0'){return};if(-not $map.ContainsKey($choice)){throw 'Invalid selection'};$Profile=$map[$choice]
    if($Profile -notin @('Practice','CollectEventLogs')){$InputRoot=Read-CocPrompt 'Acquired working folder; no live collection'}
    $OutputRoot=Read-CocPrompt 'Existing protected case output folder outside toolkit and input';$CaseId=Read-CocPrompt 'Case ID';$Authority=Read-CocPrompt 'Owner authority/reference'
    if((Read-CocPrompt 'Type RUN to approve the selected plan') -cne 'RUN'){return};$Authorized=$true;$ProtectedDestination=$true
}
if($Profile -ne 'Practice' -and -not $Authorized){throw 'Explicit authority required'}
Test-CocRelease $root|Out-Host
$session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('DFIR-'+$Profile) -ProtectedDestination:$ProtectedDestination -Synthetic:($Profile -eq 'Practice')
$session.Metadata.limitations=@('Acquired working-copy analysis; no live collection, repair or upload.','Case-specific rule review and forensic interpretation remain required.','Timestamp normalization uses explicit offsets only.','Tool completion does not establish absence of compromise.')
if($Profile -eq 'CollectEventLogs'){$session.Metadata.limitations=@('Authorized live event-log export leaves normal execution artifacts.','System/Application/Security logs: last 24 hours using unverified host clock.','Access-denied outcomes remain explicit; no silent elevation.','No repairs or uploads.')}
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$complete=$false
try{
    Write-CocEvent $session 'dfir.started' -Message ('Selected '+$Profile+'; bounded offline analysis')
    $arguments=@('-B',(Join-Path $PSScriptRoot 'dfir_pipeline.py'),'--toolkit',$root,'--case',$session.Path,'--profile',$Profile)
    if($Profile -notin @('Practice','CollectEventLogs')){$arguments+=@('--input',$InputRoot)}
    & (Join-Path $root 'COC\tools\windows\Python\python.exe') @arguments
    if($LASTEXITCODE -ne 0){throw 'DFIR plan partially failed; inspect raw analysis-result.json and logs'}
    $complete=$true
    Write-CocEvent $session 'dfir.finished' -Message 'Analysis completed; source hashes checked'
}catch{Write-CocEvent $session 'dfir.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $status=if($complete){'collected'}else{'failed'}
    $artifact=Join-Path $session.Path 'raw\analysis-result.json'
    if(-not (Test-Path -LiteralPath $artifact)){Write-CocJson $artifact @{status='failed-before-analysis-result'}}
    $session.Metadata.modules+=@{name=('dfir-'+$Profile);status=$status;detail='Review bounded analysis plan, tool logs, correlation.csv and input inventory';artifact='raw/analysis-result.json'}
    $final=if($complete){''}else{'PARTIAL'};$result=Complete-CocRun $session -FinalStatus $final
    Test-CocArtifacts $result|Out-Host;Write-CocCentered ('Case saved: '+$result)
}
