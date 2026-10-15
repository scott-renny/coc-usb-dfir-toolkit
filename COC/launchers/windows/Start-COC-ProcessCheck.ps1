#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('PE-sieve','HollowsHunter')][string]$Tool)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
Write-CocMenuOptions @('Supervised live process examination. One selected PID','report-only','no memory dumping, remediation or elevation.')
if(-not $Tool){$tool=Read-CocPrompt 'Tool: PE-sieve or HollowsHunter'}
if($tool -notin @('PE-sieve','HollowsHunter')){throw 'Select one listed tool'}
$selectedPid=0
if(-not [int]::TryParse((Read-CocPrompt 'Authorized process PID'),[ref]$selectedPid) -or $selectedPid -lt 1){throw 'Invalid PID'}
$target=Get-Process -Id $selectedPid
$selectedStartUtc=$target.StartTime.ToUniversalTime()
Write-CocCentered ('Selected '+$target.ProcessName+' (PID '+$selectedPid+')')
$output=Read-CocPrompt 'Existing protected case-output folder';$caseId=Read-CocPrompt 'Case ID';$authority=Read-CocPrompt 'Owner authorization/reference'
if((Read-CocPrompt 'Type RUN to approve this specific live-process examination') -cne 'RUN'){return}
Test-CocRelease $root|Out-Host
$current=Get-Process -Id $selectedPid
if($current.StartTime.ToUniversalTime() -ne $selectedStartUtc -or $current.ProcessName -ne $target.ProcessName){throw 'Selected process identity changed during preflight; no scan will run'}
$session=New-CocRun -ToolkitRoot $root -OutputRoot $output -CaseId $caseId -Authority $authority -Profile ('Process-'+$tool) -ProtectedDestination
$session.Metadata.limitations=@('Live process reads create observer effects; no write-blocking guarantee.','PID may exit or be reused after selection.','Nonzero exit requires analyst interpretation; no automatic verdict or repair.','No driver installation, silent elevation, persistent scanning or memory dumps.')
Write-CocJson (Join-Path $session.Path 'raw\selected-process.json') @{pid=$selectedPid;name=$target.ProcessName;process_start_utc=$selectedStartUtc.ToString('o');observed_utc=[DateTime]::UtcNow.ToString('o')}
$done=$false
try{
    Write-CocEvent $session 'process.started' -Message ('Selected '+$tool+' for PID '+$selectedPid)
    & (Join-Path $root 'COC\tools\windows\Python\python.exe') -B (Join-Path $PSScriptRoot 'process_check.py') --toolkit $root --case $session.Path --tool $tool --pid $selectedPid
    $done=$LASTEXITCODE -eq 0
    Write-CocEvent $session 'process.finished' -Message 'Review raw report and scanner exit code; no automated malware verdict'
}catch{Write-CocEvent $session 'process.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    $session.Metadata.modules+=@{name='selected-process';status=$(if($done){'collected'}else{'failed'});detail='Report-only selected PID; raw findings require interpretation';artifact='raw/process-result.json'}
    if(-not (Test-Path (Join-Path $session.Path 'raw\process-result.json'))){Write-CocJson (Join-Path $session.Path 'raw\process-result.json') @{status='failed-before-result'}}
    $result=Complete-CocRun $session -FinalStatus $(if($done){''}else{'PARTIAL'});Test-CocArtifacts $result|Out-Host;Write-CocCentered ('Process report saved: '+$result)
}
