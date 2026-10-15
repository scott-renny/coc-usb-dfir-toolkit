#Requires -Version 5.1
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'COC.Core.psm1')

function Get-CocPlaybookPlan {
    param([ValidateSet('FieldAssessment','IncidentTriage','Practice')][string]$Mode)
    if ($Mode -eq 'Practice') {
        return @(
            [pscustomobject]@{id='practice-inventory';phase='Collection';purpose='Synthetic inventory only';collector={ [pscustomobject]@{asset='SYNTHETIC-01';os='Example Windows';source='synthetic fixture'} }}
            [pscustomobject]@{id='practice-firewall';phase='Collection';purpose='Synthetic posture observation';collector={ [pscustomobject]@{Name='Synthetic profile';Enabled=$false;note='Practice observation, not a real finding'} }}
            [pscustomobject]@{id='practice-events';phase='Collection';purpose='Synthetic event data';collector={ [pscustomobject]@{Id=999;message='<script>harmless test text</script>';source='synthetic fixture'} }}
        )
    }
    $plan=@()
    if ($Mode -eq 'IncidentTriage') {
        $plan+=@(
            [pscustomobject]@{id='processes';phase='Volatile observations';purpose='Process inventory without command-line arguments';collector={ Get-Process | Select-Object Id,ProcessName,StartTime,Path }}
            [pscustomobject]@{id='tcp-connections';phase='Volatile observations';purpose='Current TCP connection state';collector={ Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess }}
            [pscustomobject]@{id='udp-endpoints';phase='Volatile observations';purpose='Current UDP endpoints';collector={ Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess }}
        )
    }
    $plan+=@(
        [pscustomobject]@{id='os';phase='Security posture';purpose='OS version and boot time';collector={ Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime }}
        [pscustomobject]@{id='firewall';phase='Security posture';purpose='Firewall profile state';collector={ Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction }}
        [pscustomobject]@{id='defender';phase='Security posture';purpose='Defender status without initiating scans';collector={ Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureVersion }}
        [pscustomobject]@{id='encryption-status';phase='Security posture';purpose='Encryption status without recovery keys';collector={ Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod }}
        [pscustomobject]@{id='administrators';phase='Security posture';purpose='Local administrator membership';collector={ $g=Get-LocalGroup -SID 'S-1-5-32-544';Get-LocalGroupMember -Group $g.Name | Select-Object Name,ObjectClass,PrincipalSource }}
        [pscustomobject]@{id='startup';phase='Startup inventory';purpose='Startup entries';collector={ Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User }}
        [pscustomobject]@{id='services';phase='Startup inventory';purpose='Services and startup configuration';collector={ Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName,StartName }}
        [pscustomobject]@{id='scheduled-tasks';phase='Startup inventory';purpose='Scheduled task names and state';collector={ Get-ScheduledTask | Select-Object TaskName,TaskPath,State }}
        [pscustomobject]@{id='recent-system-events';phase='Bounded event collection';purpose='Up to 200 System events from the previous 72 hours';collector={ Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddDays(-3)} -MaxEvents 200 -ErrorAction Stop | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message }}
    )
    if ($Mode -eq 'IncidentTriage') {
        $plan+=[pscustomobject]@{id='recent-security-events';phase='Bounded event collection';purpose='Up to 200 Security events from the previous 24 hours';collector={ Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=(Get-Date).AddDays(-1)} -MaxEvents 200 -ErrorAction Stop | Select-Object TimeCreated,Id,ProviderName,Message }}
    }
    return $plan
}
function Invoke-CocPlaybook {
    param($Session,[ValidateSet('FieldAssessment','IncidentTriage','Practice')][string]$Mode)
    $plan=@(Get-CocPlaybookPlan $Mode)
    $Session.Metadata.playbook_version='1.0'
    $Session.Metadata.planned_module_ids=@($plan|ForEach-Object {$_.id})
    $Session.Metadata.planned_module_count=$plan.Count
    Write-CocJson (Join-Path $Session.Path 'playbook-plan.json') ([ordered]@{schema_version=1;version='1.0';mode=$Mode;scope='Local host only; no remote probes';module_timeout_seconds=120;profile_budget_seconds=900;event_format='Bounded JSON observations, not full native EVTX export';modules=@($plan|Select-Object id,phase,purpose);automatic_repairs=$false;automatic_uploads=$false;memory_capture=$false;disk_imaging=$false})
    Write-CocEvent $Session 'playbook.started' -Message ($Mode+': '+$plan.Count+' approved checks')
    $index=0
    foreach ($step in $plan) {
        $index++
        Write-Host ('Step {0}/{1}: {2} — {3}' -f $index,$plan.Count,$step.phase,$step.id) -ForegroundColor Cyan
        Write-Progress -Activity ('COC '+$Mode) -Status $step.id -PercentComplete ([int](100*($index-1)/$plan.Count))
        Invoke-CocModule $Session $step.id $step.collector
    }
    Write-Progress -Activity ('COC '+$Mode) -Completed
    Write-CocEvent $Session 'playbook.collection-finished' -Message 'Selected checks finished; next step is automatic report finalization.'
}
Export-ModuleMember -Function Get-CocPlaybookPlan,Invoke-CocPlaybook
