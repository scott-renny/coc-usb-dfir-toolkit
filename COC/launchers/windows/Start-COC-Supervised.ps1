#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Tool)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$routes=Get-Content -LiteralPath (Join-Path $root 'COC\manifests\menu-tools.json') -Raw|ConvertFrom-Json
$entries=@($routes.tools|Where-Object {$_.name -ceq $Tool -and $_.action -eq 'gui'})
if($entries.Count -ne 1){throw 'Select a supported GUI from the fixed menu'}
$entry=$entries[0]
if($entry.status -ne 'staged-candidate'){throw 'This tool is unavailable for launch'}
Test-CocRelease $root|Out-Host
Write-CocCentered $entry.note
Write-CocMenuOptions @('Open acquired working copies only. GUI actions are supervised','their internal operations are not captured automatically.')
if($entry.lab){if((Read-CocPrompt 'Inside an isolated analysis VM, type LAB to acknowledge dynamic-analysis scope') -cne 'LAB'){return}}
$output=Read-CocPrompt 'Existing protected case-output folder outside toolkit'
$caseId=Read-CocPrompt 'Case ID';$authority=Read-CocPrompt 'Owner authorization/reference'
if((Read-CocPrompt 'Type RUN to approve opening this tool without a selected input') -cne 'RUN'){return}
$session=New-CocRun -ToolkitRoot $root -OutputRoot $output -CaseId $caseId -Authority $authority -Profile ('GUI-'+$Tool) -ProtectedDestination
$session.Metadata.limitations=@('Tool launch log only; GUI operations and findings require analyst notes.','Acquired working copies only; GUI tools may permit edits.','Launch success does not validate forensic results.','Windows settings/cache redirection is best effort; normal execution artifacts remain.')
$saved=@{};$names=@('JAVA_HOME','JAVA_TOOL_OPTIONS','APPDATA','LOCALAPPDATA','TEMP','TMP','WIRESHARK_CONFIG_DIR')
foreach($name in $names){$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
$started=$false
try{
    $runtime=Join-Path $session.Path 'raw\runtime';[void][IO.Directory]::CreateDirectory($runtime)
    foreach($name in @('APPDATA','LOCALAPPDATA','TEMP','TMP','WIRESHARK_CONFIG_DIR')){[Environment]::SetEnvironmentVariable($name,$runtime,'Process')}
    $exe=Join-Path $root $entry.executable
    if(-not (Test-CocChildPath $exe $root)){throw 'Unsafe tool path'};Assert-CocNoReparse $exe
    $launch=$exe
    if($Tool -eq 'NetworkMiner'){
        # NetworkMiner writes assembled files beside its application by default.
        $working=Join-Path $runtime 'NetworkMiner';Copy-Item -LiteralPath (Split-Path -Parent $exe) -Destination $working -Recurse
        $launch=Join-Path $working 'NetworkMiner.exe'
    }
    if($Tool -in @('Ghidra','JADX')){
        $java=@(Get-ChildItem -LiteralPath (Join-Path $root 'COC\tools\windows\Java') -Directory)
        if($java.Count -ne 1){throw 'Missing/ambiguous bundled Java'}
        $env:JAVA_HOME=$java[0].FullName;$env:JAVA_TOOL_OPTIONS='-Duser.home="'+$runtime+'"'
        $process=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList @('/d','/s','/c',('""'+$launch+'""')) -WorkingDirectory $runtime -PassThru
    }else{$process=Start-Process -FilePath $launch -WorkingDirectory $runtime -PassThru}
    Write-CocEvent $session 'gui.launched' -Message ($Tool+' opened without an input argument') -Detail @{process_id=$process.Id;executable_sha256=(Get-FileHash -LiteralPath $launch).Hash}
    $started=$true
    Write-CocCentered 'Complete your supervised review, then return here. Keep findings and source paths in analyst notes.'
    $note=Read-CocPrompt 'When finished, enter a brief outcome/note; Enter records launch only'
    Write-CocJson (Join-Path $session.Path 'raw\gui-result.json') @{tool=$Tool;status='launch-observed';analyst_note=$note;analysis_validated=$false;gui_closed_verified=$false}
}catch{Write-CocEvent $session 'gui.failed' -Level ERROR -Message $_.Exception.Message;throw}
finally{
    foreach($name in $names){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
    $session.Metadata.modules+=@{name=('gui-'+$Tool);status=$(if($started){'collected'}else{'failed'});detail='Launch and analyst notes only; no automatic analysis verdict';artifact='raw/gui-result.json'}
    if(-not (Test-Path (Join-Path $session.Path 'raw\gui-result.json'))){Write-CocJson (Join-Path $session.Path 'raw\gui-result.json') @{status='launch-failed'}}
    $result=Complete-CocRun $session -FinalStatus $(if($started){''}else{'FAILED'});Test-CocArtifacts $result|Out-Host;Write-CocCentered ('Launch report saved: '+$result)
}
