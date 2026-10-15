#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','Transfer','Closeout','Health')][string]$Profile='Menu',[string]$InputRoot,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[string]$Notes='No analyst notes supplied',[switch]$Authorized,[switch]$ProtectedDestination)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if($Profile -eq 'Menu'){
    Write-CocMenuHeader 'CASE OPERATIONS AND READINESS' -ContentHeight 23
    Write-CocMenuOptions @('1. Evidence intake and verified file transfer','2. Case closeout and combined findings','3. Full toolkit integrity and readiness report','4. Acquisition and isolated-lab guidance','0. Back')
    $choice=Read-CocPrompt 'Select an option'
    if($choice -eq '0'){return}
    if($choice -eq '4'){Start-Process -FilePath (Join-Path $root 'COC\docs\FIELD-OPERATIONS.md');return}
    $map=@{'1'='Transfer';'2'='Closeout';'3'='Health'}
    if(-not $map.ContainsKey($choice)){throw 'Invalid selection'}
    $Profile=$map[$choice]
    if($Profile -ne 'Health'){$InputRoot=Read-CocPrompt 'Existing acquired folder or finalized case folder'}
    if($Profile -eq 'Closeout'){$Notes=Read-CocPrompt 'Analyst notes and unresolved questions'}
    $OutputRoot=Read-CocPrompt 'Existing protected output folder outside toolkit and input'
    $CaseId=Read-CocPrompt 'Case ID';$Authority=Read-CocPrompt 'Owner authorization/reference'
    if((Read-CocPrompt 'Type RUN to approve this offline operation') -cne 'RUN'){return}
    $Authorized=$true;$ProtectedDestination=$true
}
if(-not $Authorized){throw 'Explicit authority required'}
Test-CocRelease $root|Out-Host
$session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('Field-'+$Profile) -ProtectedDestination:$ProtectedDestination
$session.Metadata.limitations=@('Offline operation; no evidence execution, network upload, boot changes or live acquisition.','File transfer is not disk imaging and does not preserve NTFS streams or ACLs.','Host clock unverified; output protection and operator identity require owner attestation.','Integrity hashes do not authenticate custody or prove absence of compromise.')
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$complete=$false
try{
    Write-CocEvent $session 'field.started' -Message ('Selected '+$Profile)
    $arguments=@('-B',(Join-Path $PSScriptRoot 'field_operations.py'),'--toolkit',$root,'--case',$session.Path,'--profile',$Profile,'--notes',$Notes)
    if($Profile -ne 'Health'){$arguments+=@('--input',$InputRoot)}
    & (Join-Path $root 'COC\tools\windows\Python\python.exe') @arguments
    if($LASTEXITCODE -ne 0){throw 'Operation incomplete; inspect raw/analysis-result.json'}
    $complete=$true;Write-CocEvent $session 'field.finished' -Message 'Operation completed; review raw report and limitations'
}catch{Write-CocEvent $session 'field.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $status=if($complete){'collected'}else{'failed'}
    $artifact=Join-Path $session.Path 'raw\analysis-result.json'
    if(-not (Test-Path -LiteralPath $artifact)){Write-CocJson $artifact @{status='PARTIAL';reason='Failed before Python result'}}
    $session.Metadata.modules+=@{name=('field-'+$Profile);status=$status;detail='Review raw/analysis-result.json and linked raw reports; completion is not an investigative verdict';artifact='raw/analysis-result.json'}
    $final=if($complete){''}else{'PARTIAL'}
    $result=Complete-CocRun $session -FinalStatus $final
    Test-CocArtifacts $result|Out-Host;Write-CocCentered ('Case saved: '+$result)
}
