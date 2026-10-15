#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','List','Help','Parse')][string]$Mode='Menu',[string]$Tool,[string]$InputFile,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[switch]$Authorized,[switch]$ProtectedDestination)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$catalog=Get-Content -LiteralPath (Join-Path $root 'COC\manifests\tools.json') -Raw|ConvertFrom-Json
if($Mode -eq 'List'){$catalog.tools|Select-Object name,category,version,workflow;return}
if($Mode -eq 'Menu'){
    Write-CocMenuHeader 'ARTIFACT EXAMINATION'
    $catalog.tools|Select-Object name,category,workflow|Format-Table -AutoSize
    Write-CocMenuOptions @('1 Offline tool help','2 Parse one previously acquired artifact','3 Existing automated playbooks','4 DFIR automation','0 Exit')
    switch(Read-CocPrompt 'Select'){
        '0'{return}
        '1'{$Mode='Help';$Tool=Read-CocPrompt 'Tool name exactly as listed'}
        '2'{$Mode='Parse';$Tool=Read-CocPrompt 'Parser name (MFTECmd, EvtxECmd, AmcacheParser, PECmd, LECmd, JLECmd, RBCmd or AppCompatCacheParser)';$InputFile=Read-CocPrompt 'Full path to one acquired file';$OutputRoot=Read-CocPrompt 'Existing protected output folder outside toolkit';$CaseId=Read-CocPrompt 'Case ID';$Authority=Read-CocPrompt 'Owner authority/reference';if((Read-CocPrompt 'Type RUN to approve this offline analysis') -cne 'RUN'){return};$Authorized=$true;$ProtectedDestination=$true}
        '3'{& (Join-Path $PSScriptRoot 'Start-COC-Playbook.ps1');return}
        '4'{& (Join-Path $PSScriptRoot 'Start-COC-DFIR.ps1');return}
        default{throw 'Invalid selection'}
    }
}
$selected=@($catalog.tools|Where-Object {$_.name -ceq $Tool})
if($selected.Count -ne 1){throw 'Select a tool from the bundled catalog'}
$entry=$selected[0]
Test-CocRelease $root|Out-Host
if($Mode -eq 'Help'){
    $help=Join-Path $root $entry.help
    if(-not (Test-CocChildPath $help $root)){throw 'Unsafe help path'}
    Get-Content -LiteralPath $help;return
}
$allowed=@('MFTECmd','EvtxECmd','AmcacheParser','PECmd','LECmd','JLECmd','RBCmd','AppCompatCacheParser')
if($Tool -notin $allowed){throw 'This tool uses the documented supervised workflow; consult its offline help'}
if(-not $Authorized){throw 'Explicit authority is required'}
if(-not (Test-Path -LiteralPath $InputFile -PathType Leaf)){throw 'Select one existing acquired artifact'}
Assert-CocNoReparse $InputFile
$InputFile=(Resolve-Path -LiteralPath $InputFile).Path
if((Get-Item -LiteralPath $InputFile).Length -gt 4GB){throw 'Guided parser input exceeds the 4 GiB bound; use the supervised upstream workflow'}
$sourceHash=(Get-FileHash -LiteralPath $InputFile).Hash
$session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('Offline-'+$Tool) -ProtectedDestination:$ProtectedDestination
$session.Metadata.toolkit_manifest_sha256=(Get-FileHash -LiteralPath (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
$session.Metadata.limitations=@('Analysis of one previously acquired artifact; no live acquisition.','Parser completion is not a security verdict.','Source hashing observes file access; run against working evidence copies.','Windows reports and raw parser output can contain sensitive data.')
Write-CocEvent $session 'analysis.selected' -Message ('Selected acquired artifact for '+$Tool) -Detail @{sha256=$sourceHash.ToLowerInvariant();input=$InputFile}
$complete=$false
try{
    $python=Join-Path $root 'COC\tools\windows\Python\python.exe'
    $runner=Join-Path $PSScriptRoot 'run_offline_parser.py'
    Write-CocEvent $session 'analysis.started' -Message ($Tool+' fixed offline parser; 300-second limit')
    & $python -B $runner --toolkit $root --tool $Tool --input $InputFile --case $session.Path
    if($LASTEXITCODE -ne 0){throw 'Parser failed or timed out; inspect parser logs'}
    if((Get-FileHash -LiteralPath $InputFile).Hash -ne $sourceHash){throw 'Source file changed during analysis; investigate before using output'}
    Write-CocEvent $session 'analysis.finished' -Message ($Tool+' finished; input hash unchanged')
    $complete=$true
}catch{Write-CocEvent $session 'analysis.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $moduleStatus=if($complete){'collected'}else{'failed'}
    $session.Metadata.modules+=@{name=('offline-'+$Tool);status=$moduleStatus;detail='Fixed offline parser; consult raw analysis outputs and parser logs';artifact='raw/parser-result.json'}
    if(-not (Test-Path -LiteralPath (Join-Path $session.Path 'raw\parser-result.json'))){Write-CocJson (Join-Path $session.Path 'raw\parser-result.json') @{tool=$Tool;status='failed-before-parser-result'}}
    $state=if($complete){''}else{'FAILED'}
    $result=Complete-CocRun $session -FinalStatus $state
    Test-CocArtifacts $result|Out-Host
    Write-CocCentered ('Analysis case saved: '+$result)
}
