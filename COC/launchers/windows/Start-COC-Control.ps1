#Requires -Version 5.1
[CmdletBinding()]
param([switch]$List)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'COC.Menu.psm1') -Force
$root=(Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1') -Force
$pages=@('Automated playbooks','Artifact examination','Malware and executable analysis','Network forensics','Memory and acquisition','Lab environments','Logs and reports','Documentation and tool status','Verify toolkit')
if($List){for($i=0;$i -lt $pages.Count;$i++){[pscustomobject]@{number=$i+1;page=$pages[$i]}};return}
function Show-Document([string]$Relative){
    $path=Join-Path $root $Relative
    if(-not (Test-CocChildPath $path $root) -or -not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'Bundled document is unavailable'}
    Assert-CocNoReparse $path
    Start-Process -FilePath $path
}
function Show-Group([string]$Group){
    $routes=Get-Content -LiteralPath (Join-Path $root 'COC\manifests\menu-tools.json') -Raw|ConvertFrom-Json
    $entries=@($routes.tools|Where-Object {$_.group -eq $Group})
    while($true){
        Write-CocMenuHeader ($Group.ToUpper()+' TOOLS') -ContentHeight (16+$entries.Count)
        $options=@();for($i=0;$i -lt $entries.Count;$i++){$options+=(($i+1).ToString()+'. '+$entries[$i].name+' ['+$entries[$i].status+']')}
        Write-CocMenuOptions ($options+@('0. Back'))
        $choice=Read-CocPrompt 'Select';if($choice -eq '0'){return}
        $number=0;if(-not [int]::TryParse($choice,[ref]$number) -or $number -lt 1 -or $number -gt $entries.Count){Write-CocCentered 'Select a listed number';continue}
        $entry=$entries[$number-1]
        Write-CocCentered $entry.note
        if($entry.action -eq 'gui'){& (Join-Path $PSScriptRoot 'Start-COC-Supervised.ps1') -Tool $entry.name}
        elseif($entry.action -eq 'process'){& (Join-Path $PSScriptRoot 'Start-COC-ProcessCheck.ps1') -Tool $entry.name}
        elseif($entry.action -eq 'profile'){
            $inputRoot=Read-CocPrompt 'Acquired working-copy folder outside toolkit'
            $outputRoot=Read-CocPrompt 'Existing protected case-output folder outside input and toolkit'
            $caseId=Read-CocPrompt 'Case ID';$authority=Read-CocPrompt 'Owner authorization/reference'
            if((Read-CocPrompt 'Type RUN to approve this offline analysis') -ceq 'RUN'){
                & (Join-Path $PSScriptRoot 'Start-COC-DFIR.ps1') -Profile $entry.profile -InputRoot $inputRoot -OutputRoot $outputRoot -CaseId $caseId -Authority $authority -Authorized -ProtectedDestination
            }
        }
        elseif($entry.action -eq 'help'){Show-Document $entry.help}
        else{Show-Document 'COC\docs\MALWARE-LAB-GUIDE.md'}
    }
}
while($true){
    Write-CocMenuHeader 'MAIN MENU'
    $options=@();for($i=0;$i -lt $pages.Count;$i++){$options+=(($i+1).ToString()+'. '+$pages[$i])}
    Write-CocMenuOptions ($options+@('0. Exit'))
    try{
        switch(Read-CocPrompt 'Select an option'){
            '0'{return}
            '1'{
                Write-CocMenuHeader 'AUTOMATED PLAYBOOKS'
                Write-CocMenuOptions @('1. Assessment / incident / harmless practice','2. Acquired-evidence automation','3. Case intake / closeout / toolkit readiness','4. Specialist offline investigations','5. Specialist field review / URL / MSG / cloud','6. Advanced APK / images / logs / signatures','7. Response / reconstruction playbooks','8. Guided incidents / practice / handoff / log manager','0. Back')
                switch(Read-CocPrompt 'Select'){
                    '1'{& (Join-Path $PSScriptRoot 'Start-COC-Playbook.ps1')}
                    '2'{& (Join-Path $PSScriptRoot 'Start-COC-DFIR.ps1')}
                    '3'{& (Join-Path $PSScriptRoot 'Start-COC-Field.ps1')}
                    '4'{& (Join-Path $PSScriptRoot 'Start-COC-Investigation.ps1')}
                    '5'{& (Join-Path $PSScriptRoot 'Start-COC-Enrichment.ps1')}
                    '6'{& (Join-Path $PSScriptRoot 'Start-COC-Advanced.ps1')}
                    '7'{& (Join-Path $PSScriptRoot 'Start-COC-Response.ps1')}
                    '8'{& (Join-Path $PSScriptRoot 'Start-COC-Operations.ps1')}
                }
            }
            '2'{& (Join-Path $PSScriptRoot 'Start-COC-Tools.ps1')}
            '3'{Show-Group 'Malware'}
            '4'{Show-Group 'Network'}
            '5'{Show-Group 'Acquisition'}
            '6'{Show-Group 'Lab'}
            '7'{
                Write-CocMenuOptions @('1. Open a verified case report / activity log','2. Generated case log manager (preview / archive / clean)','0. Back')
                $logChoice=Read-CocPrompt 'Select'
                if($logChoice -eq '2'){& (Join-Path $PSScriptRoot 'Start-COC-Operations.ps1') -Profile Logs;break}
                if($logChoice -ne '1'){break}
                $run=Read-CocPrompt 'Existing case run folder (Enter to return)'
                if($run){
                    Assert-CocNoReparse $run;Test-CocArtifacts $run|Out-Host
                    Write-CocMenuOptions @('1. Open report','2. Open activity log','0. Back')
                    $file=switch(Read-CocPrompt 'Select'){'1'{'report.html'};'2'{'activity.log'};default{$null}}
                    if($file){$path=Join-Path $run $file;Assert-CocNoReparse $path;if(Test-Path -LiteralPath $path -PathType Leaf){Start-Process -FilePath $path}}
                }
            }
            '8'{Show-Document 'COC-CONTROL-CENTER.html'}
            '9'{Test-CocRelease $root -IncludeImages|Out-Host}
            default{Write-CocCentered 'Select a listed number'}
        }
    }catch{Write-CocCentered ('Action stopped: '+$_.Exception.Message) -ForegroundColor Yellow}
    [void](Read-CocPrompt 'Press Enter to return to the control center')
}
