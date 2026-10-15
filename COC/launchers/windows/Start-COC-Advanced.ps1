#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','APK','Carve','AppleLogs','YaraFull','Config','Similarity','Reference')][string]$Profile='Menu',[string]$InputRoot,[string]$Query,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[switch]$Authorized,[switch]$ProtectedDestination)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if($Profile -eq 'Menu'){
    Write-CocMenuHeader 'ADVANCED ACQUIRED-EVIDENCE REVIEW' -ContentHeight 27
    Write-CocMenuOptions @('1. Android APK manifest / code review','2. RAW working-image carving (PhotoRec)','3. Acquired Apple logarchive examination','4. Full YARA Forge signature scan','5. Static plaintext configuration indicators','6. Selected-file TLSH similarity','7. Offline ATTACK / LOLBAS reference search','8. Guide / readiness and limitations','0. Back')
    $choice=Read-CocPrompt 'Select';if($choice -eq '0'){return}
    if($choice -eq '8'){Start-Process -FilePath (Join-Path $root 'COC\docs\COMBINED-FIELD-TOOLS.md');return}
    $map=@{'1'='APK';'2'='Carve';'3'='AppleLogs';'4'='YaraFull';'5'='Config';'6'='Similarity';'7'='Reference'}
    if(-not $map.ContainsKey($choice)){throw 'Invalid selection'};$Profile=$map[$choice]
    if($Profile -eq 'Reference'){$Query=Read-CocPrompt 'Search phrase (up to 128 characters)'}else{$InputRoot=Read-CocPrompt 'Acquired working-copy folder outside toolkit'}
    $OutputRoot=Read-CocPrompt 'Existing protected output parent outside input and toolkit'
    $CaseId=Read-CocPrompt 'Case ID';$Authority=Read-CocPrompt 'Owner authorization/reference'
    if((Read-CocPrompt 'Type RUN to approve this offline operation') -cne 'RUN'){return};$Authorized=$true;$ProtectedDestination=$true
}
if(-not $Authorized){throw 'Explicit authority required'}
if($Profile -eq 'Carve' -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'PhotoRec requires an elevated authorized analysis session. No automatic elevation or raw-device operation will occur.'}
Test-CocRelease $root|Out-Host
$session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('Advanced-'+$Profile) -ProtectedDestination:$ProtectedDestination
$session.Metadata.limitations=@('Working copies only. No input execution, cloud upload, raw-device acquisition or partition writes.','Static Python workers block socket/process APIs; this is not an operating-system malware sandbox.','Native/Java parser outputs and GUI results require analyst review.','Real carving, complete Apple logs, arbitrary APKs and GUI acceptance remain separate checks.')
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$complete=$false
try{
    Write-CocEvent $session 'advanced.started' -Message ('Selected '+$Profile)
    $arguments=@('-B',(Join-Path $PSScriptRoot 'advanced_pipeline.py'),'--toolkit',$root,'--case',$session.Path,'--profile',$Profile)
    if($InputRoot){$arguments+=@('--input',$InputRoot)};if($Query){$arguments+=@('--query',$Query)}
    & (Join-Path $root 'COC\tools\windows\Python\python.exe') @arguments
    if($LASTEXITCODE -ne 0){throw 'Analysis partial; review raw results and parser logs'}
    $complete=$true;Write-CocEvent $session 'advanced.finished' -Message 'Fixed analysis completed; analyst review required'
}catch{Write-CocEvent $session 'advanced.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $artifact=Join-Path $session.Path 'raw\analysis-result.json'
    if(-not (Test-Path -LiteralPath $artifact)){Write-CocJson $artifact @{status='PARTIAL';reason='Stopped before parser result'}}
    $session.Metadata.modules+=@{name=('advanced-'+$Profile);status=$(if($complete){'collected'}else{'failed'});detail='Review parser logs and acceptance limits';artifact='raw/analysis-result.json'}
    $path=Complete-CocRun $session -FinalStatus $(if($complete){''}else{'PARTIAL'});Test-CocArtifacts $path|Out-Host;Write-CocCentered ('Case saved: '+$path)
}
