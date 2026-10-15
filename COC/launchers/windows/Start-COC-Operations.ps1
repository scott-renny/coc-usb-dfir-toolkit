#Requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Menu','Guide','Practice','Handoff','Freshness','Logs')][string]$Profile='Menu')
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
function Invoke-CocOperations {
    param([string]$Operation,[string]$InputRoot,[string]$Query,[string]$Notes,[string]$ArchiveRoot,[string]$Selection,[string]$Confirmation,[string]$OutputRoot,[string]$CaseId,[string]$Authority)
    $session=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile ('Operations-'+$Operation) -ProtectedDestination
    $session.Metadata.toolkit_manifest_sha256=(Get-FileHash (Join-Path $root 'COC\manifests\release.json')).Hash.ToLowerInvariant()
    $session.Metadata.limitations=@('No host collection, evidence execution, uploads or boot testing. Readiness is distinct from integrity.','Log cleanup only removes explicitly selected generated COC logs after verified full archive. Original manifest lineage is preserved.','Protection is operator attestation; archives are not automatically encrypted. Hashes do not authenticate custody.')
    $complete=$false;$path=$null
    try{
        Write-CocEvent $session 'operations.started' -Message $Operation
        $arguments=@('-B',(Join-Path $PSScriptRoot 'operations_manager.py'),'--toolkit',$root,'--case',$session.Path,'--profile',$Operation)
        foreach($pair in @(@('--input',$InputRoot),@('--query',$Query),@('--notes',$Notes),@('--archive-root',$ArchiveRoot),@('--selection',$Selection),@('--confirm',$Confirmation))){if($pair[1]){$arguments+=@($pair[0],$pair[1])}}
        & (Join-Path $root 'COC\tools\windows\Python\python.exe') @arguments|Out-Host
        if($LASTEXITCODE -ne 0){throw 'Operation partial; inspect the saved result'}
        $complete=$true;Write-CocEvent $session 'operations.finished' -Message $Operation
    }catch{Write-CocEvent $session 'operations.failed' -Level ERROR -Message $_.Exception.Message;Write-CocCentered $_.Exception.Message -ForegroundColor Yellow}
    finally{
        $session.Metadata.modules+=@{name=('operations-'+$Operation);status=$(if($complete){'collected'}else{'failed'});detail='See operations report and limits';artifact='raw/analysis-result.json'}
        $path=Complete-CocRun $session -FinalStatus $(if($complete){''}else{'PARTIAL'});Test-CocArtifacts $path|Out-Host
    }
    return [pscustomobject]@{Path=$path;Complete=$complete}
}
function Invoke-CocGuidedIncident {
    param([string]$OutputRoot,[string]$CaseId,[string]$Authority)
    Write-CocMenuHeader 'GUIDED INCIDENT SELECTOR' -ContentHeight 24
    Write-CocMenuOptions @('1. Suspected malware','2. Phishing / suspicious email','3. Compromised server','4. Suspicious acquired network traffic','5. Acquired evidence intake and triage','0. Back')
    $map=@{'1'='Malware';'2'='Phishing';'3'='Server';'4'='Network';'5'='Evidence'};$choice=Read-CocPrompt 'Select'
    if($choice -eq '0'){return};if(-not $map.ContainsKey($choice)){throw 'Invalid scenario'}
    $planned=Invoke-CocOperations -Operation Guide -Query $map[$choice] -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority
    if(-not $planned.Complete){return}
    $plan=Get-Content (Join-Path $planned.Path 'raw\incident-plan.json') -Raw|ConvertFrom-Json
    try{
        foreach($step in $plan.steps){
            $allowed=@('Start-COC-DFIR.ps1:SuspiciousAssessment','Start-COC-Advanced.ps1:Config','Start-COC-Investigation.ps1:Email','Start-COC-Enrichment.ps1:URLs','Start-COC-Response.ps1:ServerRunbook','Start-COC-DFIR.ps1:EventTimeline','Start-COC-DFIR.ps1:NetworkAssessment','Start-COC-Field.ps1:Transfer','Start-COC-DFIR.ps1:OfflineTriage')
            if(($step.launcher+':'+$step.profile) -notin $allowed){throw 'Unexpected guide route; nothing will launch'}
            Write-CocCentered ($step.number.ToString()+'. '+$step.title)
            $decision=Read-CocPrompt 'Type RUN, SKIP or REVIEW (anything else stops)'
            if($decision -ceq 'SKIP'){$step.status='skipped';continue}
            if($decision -ceq 'REVIEW'){$step.status='analyst-review';continue}
            if($decision -cne 'RUN'){break}
            $inputPath=Read-CocPrompt 'Acquired working-copy folder for this step (separate from toolkit/output)'
            $stepCase=$CaseId.Substring(0,[math]::Min(40,$CaseId.Length))+'_'+$step.number+'_'+[guid]::NewGuid().ToString('N').Substring(0,8)
            try{
                $parameters=@{Profile=$step.profile;InputRoot=$inputPath;OutputRoot=$OutputRoot;CaseId=$stepCase;Authority=$Authority;Authorized=$true;ProtectedDestination=$true}
                & (Join-Path $PSScriptRoot $step.launcher) @parameters|Out-Host
                $matches=@(Get-ChildItem -LiteralPath $OutputRoot -Directory|Where-Object {$_.Name.StartsWith($stepCase+'-')})
                if($matches.Count -ne 1){throw 'Expected one newly created step case'}
                $verified=Test-CocArtifacts $matches[0].FullName;$metadata=Get-Content (Join-Path $matches[0].FullName 'run.json') -Raw|ConvertFrom-Json
                if($metadata.case_id -ne $stepCase){throw 'Unexpected step identity'}
                $step.status=if($metadata.status -eq 'COMPLETE'){'completed'}else{'failed'}
                $step|Add-Member -NotePropertyName case_path -NotePropertyValue $matches[0].FullName
                $step|Add-Member -NotePropertyName manifest_sha256 -NotePropertyValue (Get-FileHash (Join-Path $matches[0].FullName 'artifact-manifest.json')).Hash.ToLowerInvariant()
                $step|Add-Member -NotePropertyName case_status -NotePropertyValue $metadata.status
            }catch{$step.status='failed';$step|Add-Member -NotePropertyName error -NotePropertyValue $_.Exception.Message -Force;Write-CocCentered $_.Exception.Message -ForegroundColor Yellow}
        }
    }finally{
        $summary=New-CocRun -ToolkitRoot $root -OutputRoot $OutputRoot -CaseId $CaseId -Authority $Authority -Profile 'Operations-GuideSummary' -ProtectedDestination
        Write-CocJson (Join-Path $summary.Path 'raw\incident-progress.json') @{source_plan=$planned.Path;scenario=$plan.scenario;steps=$plan.steps;analyst_review=$plan.analyst_review;limitations='Completed means the selected parser case completed and verified; it does not mean the incident is resolved. Planned steps were not attempted.'}
        $summary.Metadata.modules+=@{name='guided-incident-progress';status='collected';detail='Completed / skipped / failed / review / planned steps remain explicit';artifact='raw/incident-progress.json'}
        $saved=Complete-CocRun $summary;Test-CocArtifacts $saved|Out-Host;Write-CocCentered ('Progress saved: '+$saved)
    }
}
if($Profile -eq 'Menu'){
    Write-CocMenuHeader 'FIELD OPERATIONS MANAGER' -ContentHeight 24
    Write-CocMenuOptions @('1. Guided incident selector','2. One-click harmless practice check','3. Evidence handoff packet','4. Tool and rules freshness dashboard','5. Generated case log manager','6. Guide / safeguards','0. Back')
    $choice=Read-CocPrompt 'Select';if($choice -eq '0'){return}
    if($choice -eq '6'){Start-Process -FilePath (Join-Path $root 'COC\docs\OPERATIONS-MANAGER.md');return}
    $map=@{'1'='Guide';'2'='Practice';'3'='Handoff';'4'='Freshness';'5'='Logs'}
    if(-not $map.ContainsKey($choice)){throw 'Invalid selection'};$Profile=$map[$choice]
}
$inputPath='';$notes='';$archive=''
if($Profile -in @('Handoff','Logs')){$inputPath=Read-CocPrompt 'Existing finalized COC case folder'}
if($Profile -eq 'Handoff'){$notes=Read-CocPrompt 'Analyst notes and unresolved findings'}
$output=Read-CocPrompt 'Existing protected maintenance-output parent (different parent from source case)'
$caseId=Read-CocPrompt 'Case ID';$authority=Read-CocPrompt 'Owner authorization/reference'
if((Read-CocPrompt 'Type RUN to approve this selected operation') -cne 'RUN'){return}
Test-CocRelease $root|Out-Host
if($Profile -eq 'Guide'){Invoke-CocGuidedIncident -OutputRoot $output -CaseId $caseId -Authority $authority;return}
if($Profile -eq 'Logs'){
    $preview=Invoke-CocOperations -Operation LogsPreview -InputRoot $inputPath -OutputRoot $output -CaseId $caseId -Authority $authority
    if(-not $preview.Complete){return}
    $plan=Get-Content (Join-Path $preview.Path 'raw\log-plan.json') -Raw|ConvertFrom-Json
    Write-CocCentered ('Verified case: '+$plan.case)
    for($i=0;$i -lt $plan.files.Count;$i++){Write-CocCentered (($i+1).ToString()+'. '+$plan.files[$i].path+' | '+$plan.files[$i].bytes+' bytes')}
    Write-CocCentered ('Total generated log bytes: '+$plan.total_bytes)
    Write-CocMenuOptions @('1. Archive complete case; keep all originals','2. Archive complete case; clean selected generated logs','0. Keep everything and return')
    $choice=Read-CocPrompt 'Select';if($choice -notin @('1','2')){return}
    $archive=Read-CocPrompt 'Existing protected archive parent (ZIP is NOT encrypted)'
    $selected='';$confirm='';$operation='LogsArchive'
    if($choice -eq '2'){
        if($plan.files.Count -eq 0){Write-CocCentered 'No eligible generated logs';return}
        $selected=Read-CocPrompt 'Selected file numbers separated by commas, or ALL'
        $chosen=@()
        if($selected -ceq 'ALL'){$chosen=@($plan.files)}else{
            if($selected -notmatch '^\s*\d+\s*(,\s*\d+\s*)*$'){throw 'Select displayed numbers or ALL'}
            $indexes=@($selected.Split(',')|ForEach-Object {[int]$_.Trim()})
            if(@($indexes|Select-Object -Unique).Count -ne $indexes.Count){throw 'Duplicate selection'}
            foreach($number in $indexes){if($number -lt 1 -or $number -gt $plan.files.Count){throw 'Invalid selected number'};$chosen+=@($plan.files[$number-1])}
        }
        Write-CocCentered 'Selected for removal ONLY AFTER full archive verification:'
        foreach($entry in $chosen){Write-CocCentered ((Join-Path $plan.case $entry.path)+' | '+$entry.bytes+' bytes')}
        Write-CocCentered ('Selected bytes: '+(($chosen|Measure-Object -Property bytes -Sum).Sum))
        $notes=Read-CocPrompt 'Cleanup reason / retention authorization'
        Write-CocCentered ('Confirmation: DELETE '+$plan.plan_id)
        $confirm=Read-CocPrompt 'Type that exact confirmation to remove only selected logs after verified archive'
        if($confirm -cne ('DELETE '+$plan.plan_id)){Write-CocCentered 'Cleanup cancelled; no logs removed';return};$operation='LogsClean'
    }
    $result=Invoke-CocOperations -Operation $operation -InputRoot $inputPath -Notes $notes -ArchiveRoot $archive -Selection $selected -Confirmation $confirm -OutputRoot $output -CaseId $caseId -Authority $authority
}else{$result=Invoke-CocOperations -Operation $Profile -InputRoot $inputPath -Notes $notes -OutputRoot $output -CaseId $caseId -Authority $authority}
Write-CocCentered ('Operation report: '+$result.Path)
