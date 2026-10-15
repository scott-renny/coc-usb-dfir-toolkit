#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','ServerLogs','PyInstaller','ContainerReview','Correlate','LiveSnapshot','ServerRunbook')][string]$Profile='Menu',[string]$InputRoot,[string]$Query,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[switch]$Authorized,[switch]$ProtectedDestination)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if($Profile -eq 'Menu'){
    Write-CocMenuHeader 'RESPONSE AND RECONSTRUCTION PLAYBOOKS' -ContentHeight 27
    Write-CocMenuOptions @('1. Automated server incident runbook','2. IIS / Apache / Nginx acquired access logs','3. Bounded Python-package static extraction','4. Acquired container image users (Dissect)','5. Correlate finalized COC cases','6. Authorized LIVE host snapshot (osquery)','7. Offline lab guide: Zeek / Suricata / Plaso','0. Back')
    $choice=Read-CocPrompt 'Select';if($choice -eq '0'){return}
    if($choice -eq '7'){Start-Process -FilePath (Join-Path $root 'COC\docs\RESPONSE-PLAYBOOKS.md');return}
    $map=@{'1'='ServerRunbook';'2'='ServerLogs';'3'='PyInstaller';'4'='ContainerReview';'5'='Correlate';'6'='LiveSnapshot'}
    if(-not $map.ContainsKey($choice)){throw 'Invalid selection'};$Profile=$map[$choice]
    if($Profile -ne 'LiveSnapshot'){$InputRoot=Read-CocPrompt 'Acquired working-copy folder (case parent for correlation)'}
    $OutputRoot=Read-CocPrompt 'Existing protected output parent outside input and toolkit'
    $CaseId=Read-CocPrompt 'Case ID';$Authority=Read-CocPrompt 'Owner authorization/reference'
    if((Read-CocPrompt 'Type RUN to approve this selected operation') -cne 'RUN'){return};$Authorized=$true;$ProtectedDestination=$true
}
if(-not $Authorized){throw 'Explicit authority required'}
if($Profile -eq 'LiveSnapshot' -and (Read-CocPrompt 'Live tools change this host. Type LIVE to authorize fixed queries') -cne 'LIVE'){return}
Test-CocRelease $root|Out-Host
$session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('Response-'+$Profile) -ProtectedDestination:$ProtectedDestination
$session.Metadata.limitations=@('Acquired working copies except explicitly authorized LIVE snapshot. No evidence execution, uploads, drivers, services or containment.','Container and lab runtime acceptance remains separate. Correlation leads do not establish identity or maliciousness.','Python extraction preserves nested PYZ archives without decoding or executing them. No boot testing.')
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$complete=$false
try{
    Write-CocEvent $session 'response.started' -Message ('Selected '+$Profile)
    $arguments=@('-B',(Join-Path $PSScriptRoot 'response_pipeline.py'),'--toolkit',$root,'--case',$session.Path,'--profile',$Profile)
    if($Profile -eq 'LiveSnapshot'){$arguments+='--live-authorized'}
    if($InputRoot){$arguments+=@('--input',$InputRoot)}
    & (Join-Path $root 'COC\tools\windows\Python\python.exe') @arguments
    if($LASTEXITCODE -ne 0){throw 'Analysis partial; review raw results and parser logs'}
    $complete=$true;Write-CocEvent $session 'response.finished' -Message 'Fixed analysis completed; analyst review required'
}catch{Write-CocEvent $session 'response.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $artifact=Join-Path $session.Path 'raw\analysis-result.json'
    if(-not (Test-Path -LiteralPath $artifact)){Write-CocJson $artifact @{status='PARTIAL';reason='Stopped before parser result'}}
    $session.Metadata.modules+=@{name=('response-'+$Profile);status=$(if($complete){'collected'}else{'failed'});detail='Review parser logs and acceptance limits';artifact='raw/analysis-result.json'}
    $path=Complete-CocRun $session -FinalStatus $(if($complete){''}else{'PARTIAL'});Test-CocArtifacts $path|Out-Host;Write-CocCentered ('Case saved: '+$path)
}
