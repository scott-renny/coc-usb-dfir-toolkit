#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','Email','Linux','Persistence','Compare','Export','ResumeTransfer','SQLite','SQLiteCarve','RDPCache','Memory','Takajo','TakajoProcessTree','Practice')][string]$Profile='Menu',[string]$InputRoot,[string]$SecondaryRoot,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[string]$Notes='',[switch]$Authorized,[switch]$ProtectedDestination)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
if($Profile -eq 'Menu'){
    Write-CocMenuHeader 'SPECIALIST OFFLINE INVESTIGATIONS' -ContentHeight 32
    Write-CocMenuOptions @('1. Email / phishing and PST / OST review','2. Acquired Linux logs and configuration review','3. Windows persistence export review','4. Compare indicators across finalized cases','5. Export reviewed case metadata for COC','6. Start or resume a verified staging transfer','7. SQLite Dissect with journal companions','8. RDP bitmap-cache examination','9. Offline Windows memory process listing','10. Takajo computer and scheduled-task views','11. Takajo Sysmon process tree by GUID','12. Harmless practice and expected-result checks','13. Specialist tool and workstation guide','14. SQLite recovery carving on a working copy','0. Back')
    $choice=Read-CocPrompt 'Select an option';if($choice -eq '0'){return}
    if($choice -eq '13'){Start-Process -FilePath (Join-Path $root 'COC\docs\SPECIALIST-INVESTIGATIONS.md');return}
    $map=@{'1'='Email';'2'='Linux';'3'='Persistence';'4'='Compare';'5'='Export';'6'='ResumeTransfer';'7'='SQLite';'8'='RDPCache';'9'='Memory';'10'='Takajo';'11'='TakajoProcessTree';'12'='Practice';'14'='SQLiteCarve'}
    if(-not $map.ContainsKey($choice)){throw 'Invalid selection'};$Profile=$map[$choice]
    if($Profile -ne 'Practice'){$InputRoot=Read-CocPrompt 'Acquired working folder (Compare: parent of finalized cases; Export: one finalized case)'}
    if($Profile -eq 'ResumeTransfer'){$SecondaryRoot=Read-CocPrompt 'Existing protected staging folder; empty initially or created by this workflow'}
    if($Profile -eq 'TakajoProcessTree'){$Notes=Read-CocPrompt 'Sysmon process GUID'}
    $OutputRoot=Read-CocPrompt 'Existing protected output parent outside input, staging and toolkit';$CaseId=Read-CocPrompt 'Case ID';$Authority=Read-CocPrompt 'Owner authorization/reference'
    if((Read-CocPrompt 'Type RUN to approve this offline operation') -cne 'RUN'){return};$Authorized=$true;$ProtectedDestination=$true
}
if($Profile -ne 'Practice' -and -not $Authorized){throw 'Explicit authority required'}
Test-CocRelease $root|Out-Host
$session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('Specialist-'+$Profile) -ProtectedDestination:$ProtectedDestination -Synthetic:($Profile -eq 'Practice')
$session.Metadata.limitations=@('Acquired working-copy analysis only; no host acquisition, evidence execution or uploads.','Memory symbols are a selected collection; unmatched images remain unsupported.','Text matches and shared indicators require analyst interpretation.','Host clock unverified; operator attests destination protection.','MemProcFS is a separate-workstation package, not launched by this menu.')
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$complete=$false
try{
    Write-CocEvent $session 'specialist.started' -Message ('Selected '+$Profile)
    if($Profile -eq 'ResumeTransfer'){Write-CocEvent $session 'custody.transfer.authorized' -Message 'Owner-authorized acquired-file transfer to separate protected staging destination'}
    $arguments=@('-B',(Join-Path $PSScriptRoot 'investigation_pipeline.py'),'--toolkit',$root,'--case',$session.Path,'--profile',$Profile)
    if($InputRoot){$arguments+=@('--input',$InputRoot)};if($SecondaryRoot){$arguments+=@('--secondary',$SecondaryRoot)};if($Notes){$arguments+=@('--notes',$Notes)}
    & (Join-Path $root 'COC\tools\windows\Python\python.exe') @arguments
    if($LASTEXITCODE -ne 0){throw 'Specialist analysis is partial; inspect raw/analysis-result.json and parser logs'}
    $complete=$true;Write-CocEvent $session 'specialist.finished' -Message 'Selected operation completed; forensic review required'
    if($Profile -eq 'ResumeTransfer'){Write-CocEvent $session 'custody.transfer.verified' -Message 'Listed destination files read-back verified; receipt in raw/transfer-receipt.json'}
}catch{Write-CocEvent $session 'specialist.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $artifact=Join-Path $session.Path 'raw\analysis-result.json'
    if(-not (Test-Path -LiteralPath $artifact)){Write-CocJson $artifact @{status='PARTIAL';reason='Failed before analysis result'}}
    $session.Metadata.modules+=@{name=('specialist-'+$Profile);status=$(if($complete){'collected'}else{'failed'});detail='Review raw findings, coverage, parser logs and limitations';artifact='raw/analysis-result.json'}
    $result=Complete-CocRun $session -FinalStatus $(if($complete){''}else{'PARTIAL'})
    Test-CocArtifacts $result|Out-Host;Write-CocCentered ('Case saved: '+$result)
}
