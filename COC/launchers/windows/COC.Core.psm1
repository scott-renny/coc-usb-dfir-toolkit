#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-CocJson {
    param([string]$Path,$Value)
    $json = ConvertTo-Json -InputObject $Value -Depth 12
    [IO.File]::WriteAllText($Path,$json,(New-Object Text.UTF8Encoding($false)))
}
function Write-CocEvent {
    param($Session,[ValidatePattern('^[a-z0-9][a-z0-9.-]{0,63}$')][string]$Event,[ValidateSet('INFO','WARNING','ERROR')][string]$Level='INFO',[string]$Message='',$Detail=$null)
    $entry=[ordered]@{time_utc=[DateTime]::UtcNow.ToString('o');elapsed_seconds=[math]::Round($Session.Stopwatch.Elapsed.TotalSeconds,3);event=$Event;level=$Level;message=$Message;detail=$Detail}
    $encoding=New-Object Text.UTF8Encoding($false)
    [IO.File]::AppendAllText((Join-Path $Session.Path 'events.jsonl'),((ConvertTo-Json $entry -Depth 8 -Compress)+[Environment]::NewLine),$encoding)
    $clean=($Message -replace '[\r\n\t]+',' ')
    $line=('{0} [{1}] {2}: {3}' -f $entry.time_utc,$Level,$Event,$clean)+[Environment]::NewLine
    [IO.File]::AppendAllText((Join-Path $Session.Path 'activity.log'),$line,$encoding)
    if ($Level -eq 'ERROR') {[IO.File]::AppendAllText((Join-Path $Session.Path 'errors.log'),$line,$encoding)}
}
function Test-CocCaseId {
    param([string]$CaseId)
    if ($CaseId -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') { throw 'Case ID must contain 1-64 letters, digits, underscores or hyphens.' }
}
function Test-CocChildPath {
    param([string]$Path,[string]$Parent)
    $p = [IO.Path]::GetFullPath($Path).TrimEnd('\','/')
    $root = [IO.Path]::GetFullPath($Parent).TrimEnd('\','/')
    return ($p -eq $root -or $p.StartsWith($root + [IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase))
}
function Assert-CocNoReparse {
    param([string]$Path)
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        $attributes=$null
        try { $attributes=[IO.File]::GetAttributes($current) }
        catch {
            $cause=$_.Exception
            if ($cause.InnerException) { $cause=$cause.InnerException }
            if ($cause -isnot [IO.FileNotFoundException] -and $cause -isnot [IO.DirectoryNotFoundException]) { throw }
        }
        if ($null -ne $attributes -and ($attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Reparse paths are not allowed for case storage.' }
        $next = [IO.Path]::GetDirectoryName($current)
        if ($next -eq $current) { break }
        $current = $next
    }
}
function Test-CocRelease {
    param([string]$ToolkitRoot,[switch]$IncludeImages)
    $root = (Resolve-Path -LiteralPath $ToolkitRoot).Path
    $manifestPath = Join-Path $root 'COC\manifests\release.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'Release manifest is missing.' }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $checked = 0
    foreach ($entry in $manifest.files) {
        # Normal tool launch checks executable payloads. Full verification also
        # checks large transport appliances, installers and reference archives.
        if (-not $IncludeImages -and ($entry.path.StartsWith('ISO/') -or $entry.path.StartsWith('COC/lab/') -or $entry.path.StartsWith('COC/installers/') -or $entry.path.StartsWith('COC/tools/reference/'))) { continue }
        if ([IO.Path]::IsPathRooted($entry.path) -or $entry.path -match '(^|[\\/])\.\.([\\/]|$)') { throw 'Unsafe release manifest path.' }
        $path = Join-Path $root $entry.path
        if (-not (Test-CocChildPath $path $root)) { throw 'Release path escapes toolkit.' }
        Assert-CocNoReparse $path
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Release file missing: $($entry.path)" }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $entry.sha256) { throw "Release integrity mismatch: $($entry.path)" }
        $checked++
    }
    [pscustomobject]@{Status='matched-local-manifest';Files=$checked;ImagesChecked=[bool]$IncludeImages;Trust='Unsigned manifest: compare its digest with the trusted workstation reference.'}
}
function New-CocRun {
    param([string]$ToolkitRoot,[string]$OutputRoot,[string]$CaseId,[string]$Authority,[string]$Profile,[switch]$ProtectedDestination,[switch]$Synthetic)
    Test-CocCaseId $CaseId
    if ([string]::IsNullOrWhiteSpace($Authority)) { throw 'An authorization reference is required.' }
    if (-not $Synthetic -and -not $ProtectedDestination) { throw 'Protected output must be prepared and explicitly attested. No plaintext fallback.' }
    $root = [IO.Path]::GetFullPath($OutputRoot)
    if (Test-CocChildPath $root $ToolkitRoot) { throw 'Output must be outside executable toolkit files. Use a mounted encrypted vault or separate protected case volume.' }
    Assert-CocNoReparse $root
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Output destination must already exist.' }
    $driveRoot = [IO.Path]::GetPathRoot($root)
    if ($driveRoot.StartsWith('\\')) { throw 'Network output is not enabled in this release.' }
    $drive = New-Object IO.DriveInfo($driveRoot)
    if ($drive.AvailableFreeSpace -lt 1GB) { throw 'Output destination needs at least 1 GiB free.' }
    $lock = [IO.File]::Open((Join-Path $root '.coc-session.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)
        $path = Join-Path $root ($CaseId + '-' + $runId)
        if (Test-Path -LiteralPath $path) { throw 'Output already exists.' }
        [void](New-Item -ItemType Directory -Path $path)
        [void](New-Item -ItemType Directory -Path (Join-Path $path 'raw'))
        $run = [ordered]@{schema_version=1;case_id=$CaseId;run_id=$runId;authority_reference=$Authority;profile=$Profile;status='RUNNING';started_utc=[DateTime]::UtcNow.ToString('o');ended_utc=$null;clock_confidence='Host clock unverified';local_offset=[DateTimeOffset]::Now.Offset.ToString();synthetic=[bool]$Synthetic;destination_protection='Operator attestation; not automatically verified';modules=@();limitations=@('Live collection changes system state.','Negative findings do not establish absence of compromise.','Memory acquisition is unavailable.','Network scanning and driver installation are not part of this Windows collector.')}
        Write-CocJson (Join-Path $path 'run.json') $run
        $session=[pscustomobject]@{Path=$path;Metadata=$run;Lock=$lock;Stopwatch=[Diagnostics.Stopwatch]::StartNew()}
        [IO.File]::WriteAllText((Join-Path $path 'errors.log'),'',(New-Object Text.UTF8Encoding($false)))
        Write-CocEvent $session 'run.started' -Message ('Started '+$Profile+'; host clock unverified.')
        return $session
    } catch { $lock.Dispose(); throw }
}
function Invoke-CocModule {
    param($Session,[ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')][string]$Name,[scriptblock]$Collector,[ValidateRange(1,120)][int]$TimeoutSeconds=120,$Arguments=@())
    $started = [DateTime]::UtcNow.ToString('o')
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $job = $null
    $status = 'collected'
    $detail = ''
    $data = @()
    Write-CocEvent $Session 'module.started' -Message $Name
    try {
        $remaining=900-[int]$Session.Stopwatch.Elapsed.TotalSeconds
        if ($remaining -le 0) { throw 'PROFILE_BUDGET_EXHAUSTED' }
        $TimeoutSeconds=[math]::Min($TimeoutSeconds,$remaining)
        $job = Start-Job -ScriptBlock { param($Code,$Params) $ErrorActionPreference='Stop'; & ([scriptblock]::Create($Code)) @Params } -ArgumentList $Collector.ToString(),$Arguments
        $finished = Wait-Job -Job $job -Timeout $TimeoutSeconds
        if (-not $finished) { Stop-Job -Job $job; $status='timed_out'; $detail="Exceeded $TimeoutSeconds seconds" }
        elseif ($job.State -eq 'Failed') { $status='failed'; $detail=[string]$job.ChildJobs[0].JobStateInfo.Reason }
        else { $data = @(Receive-Job -Job $job -ErrorAction Stop) }
    } catch {
        $status = if ($_.Exception.Message -eq 'PROFILE_BUDGET_EXHAUSTED') { 'skipped' } elseif ($_.Exception.Message -match 'denied|unauthorized') { 'access_denied' } elseif ($_.Exception.Message -match 'not recognized|not found|unavailable|unsupported') { 'unsupported' } else { 'failed' }
        $detail = $_.Exception.Message
    } finally {
        if ($null -ne $job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
    }
    if ($status -eq 'failed') {
        if ($detail -match 'denied|unauthorized') {$status='access_denied'}
        elseif ($detail -match 'not recognized|not found|unavailable|unsupported') {$status='unsupported'}
    }
    $record = [ordered]@{name=$Name;status=$status;started_utc=$started;ended_utc=[DateTime]::UtcNow.ToString('o');elapsed_seconds=[math]::Round($timer.Elapsed.TotalSeconds,3);detail=$detail;artifact=('raw/'+$Name+'.json');records=$data.Count}
    $serialized = ConvertTo-Json -InputObject $data -Depth 10
    if ([Text.Encoding]::UTF8.GetByteCount($serialized) -gt 16MB) {
        $record.status='failed';$record.detail='Module output exceeded 16 MiB; data was not saved.';$data=@()
    }
    Write-CocJson (Join-Path $Session.Path $record.artifact) $data
    $Session.Metadata.modules += $record
    Write-CocJson (Join-Path $Session.Path 'run.json') $Session.Metadata
    $level=if ($record.status -in @('failed','timed_out')) {'ERROR'} elseif ($record.status -ne 'collected') {'WARNING'} else {'INFO'}
    Write-CocEvent $Session 'module.finished' -Level $level -Message ($Name+': '+$record.status+'; '+$record.detail) -Detail $record
    Write-Host ("{0}: {1}" -f $Name,$record.status)
}
function Complete-CocRun {
    param($Session,[string]$FinalStatus='')
    try {
        $metadata = $Session.Metadata
        Write-CocEvent $Session 'run.finalizing' -Message 'Generating reports and integrity manifest.'
        if (-not $FinalStatus) { $FinalStatus = if (@($metadata.modules | Where-Object { $_.status -ne 'collected' }).Count -gt 0) { 'PARTIAL' } else { 'COMPLETE' } }
        $metadata.status=$FinalStatus
        $metadata.ended_utc=[DateTime]::UtcNow.ToString('o')
        $metadata.elapsed_seconds=[math]::Round($Session.Stopwatch.Elapsed.TotalSeconds,3)
        Write-CocJson (Join-Path $Session.Path 'run.json') $metadata
        $counts=[ordered]@{}
        foreach ($state in @('collected','skipped','access_denied','unsupported','timed_out','cancelled','failed')) {$counts[$state]=@($metadata.modules|Where-Object {$_.status -eq $state}).Count}
        Write-CocJson (Join-Path $Session.Path 'summary.json') ([ordered]@{schema_version=1;case_id=$metadata.case_id;run_id=$metadata.run_id;profile=$metadata.profile;status=$FinalStatus;counts=$counts;elapsed_seconds=$metadata.elapsed_seconds;clock_confidence=$metadata.clock_confidence;review_required=@($metadata.modules|Where-Object {$_.status -ne 'collected'}|ForEach-Object {$_.name});interpretation='Collection status, not a security verdict.'})
        $readme=@('COC CASE OUTPUT','','Open report.html for the readable report. Review raw/ for collected observations.','summary.json records outcomes. run.json records scope and execution metadata.','activity.log is the readable run timeline. events.jsonl contains structured events.','errors.log records failed/timed-out modules; denied/unsupported outcomes remain in activity.log and coverage.csv.','artifact-manifest.json hashes finalized files and excludes itself. Preserve its SHA-256 separately.','Verify artifacts on a trusted workstation before transfer or analysis. Keep case data protected.','COMPLETE means selected collection steps completed. It does not mean the system is clean.','An unfinished run.json or missing artifact manifest indicates an incomplete run. Do not auto-resume it.')
        [IO.File]::WriteAllLines((Join-Path $Session.Path 'READ-ME-FIRST.txt'),[string[]]$readme,(New-Object Text.UTF8Encoding($false)))
        $rows = foreach ($m in $metadata.modules) {
            '<tr><td>'+[Net.WebUtility]::HtmlEncode($m.name)+'</td><td>'+[Net.WebUtility]::HtmlEncode($m.status)+'</td><td>'+[Net.WebUtility]::HtmlEncode($m.detail)+'</td><td>'+[Net.WebUtility]::HtmlEncode($m.artifact)+'</td></tr>'
        }
        $observations = foreach ($m in $metadata.modules) {
            $rawPath=Join-Path $Session.Path $m.artifact
            if (Test-Path -LiteralPath $rawPath -PathType Leaf) {
                $raw=Get-Content -LiteralPath $rawPath -Raw
                if ($raw.Length -gt 24000) { $raw=$raw.Substring(0,24000)+[Environment]::NewLine+'[Report preview truncated; complete raw artifact retained.]' }
                '<details><summary>'+[Net.WebUtility]::HtmlEncode($m.name)+'</summary><pre style="white-space:pre-wrap">'+[Net.WebUtility]::HtmlEncode($raw)+'</pre></details>'
            }
        }
        $html = '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''"><title>COC Security Report</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;color:#182434}table{border-collapse:collapse;width:100%}td,th{border:1px solid #aaa;padding:10px;text-align:left}</style><h1>COC Security Report</h1><p>Case: '+[Net.WebUtility]::HtmlEncode($metadata.case_id)+'</p><p>Authority: '+[Net.WebUtility]::HtmlEncode($metadata.authority_reference)+'</p><p>Profile: '+[Net.WebUtility]::HtmlEncode($metadata.profile)+' — '+$FinalStatus+'</p><p>This report records collection coverage. It does not certify security or hardware health. Review the referenced raw JSON artifacts for observations; no vulnerability verdicts are inferred.</p><table><thead><tr><th>Module</th><th>Status</th><th>Notes</th><th>Evidence</th></tr></thead><tbody>'+($rows -join '')+'</tbody></table><h2>Limitations</h2><ul>'+ (($metadata.limitations | ForEach-Object { '<li>'+[Net.WebUtility]::HtmlEncode($_)+'</li>' }) -join '')+'</ul><p>Clock: host clock unverified. Output protection: operator attestation, not automatic verification.</p></html>'
        $html=$html.Replace('</html>','<h2>Collected observations</h2>'+($observations -join '')+'</html>')
        [IO.File]::WriteAllText((Join-Path $Session.Path 'report.html'),$html,(New-Object Text.UTF8Encoding($false)))
        $md = @('# COC Security Collection Report','','Case: '+$metadata.case_id,'','Status: '+$FinalStatus,'','Collection coverage; review raw JSON before drawing conclusions.','')
        foreach ($m in $metadata.modules) { $md += '- '+$m.name+': '+$m.status+'; '+$m.detail+'; evidence: '+$m.artifact }
        $md += @('','Limitations:') + $metadata.limitations
        [IO.File]::WriteAllLines((Join-Path $Session.Path 'report.md'),[string[]]$md,(New-Object Text.UTF8Encoding($false)))
        $metadata.modules | Select-Object name,status,artifact,detail | Export-Csv -LiteralPath (Join-Path $Session.Path 'coverage.csv') -NoTypeInformation -Encoding UTF8
        Write-CocEvent $Session 'run.finished' -Message ('Collection '+$FinalStatus+'; report generation complete.')
        $files = @(Get-ChildItem -LiteralPath $Session.Path -File -Recurse | Sort-Object FullName)
        $manifest = foreach ($file in $files) { [ordered]@{path=$file.FullName.Substring($Session.Path.Length+1).Replace('\','/');bytes=$file.Length;sha256=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} }
        Write-CocJson (Join-Path $Session.Path 'artifact-manifest.json.tmp') ([ordered]@{schema_version=1;files=@($manifest);trust='Unsigned until verified and signed on trusted receiving workstation'})
        Move-Item -LiteralPath (Join-Path $Session.Path 'artifact-manifest.json.tmp') -Destination (Join-Path $Session.Path 'artifact-manifest.json')
        return $Session.Path
    } finally { $Session.Lock.Dispose() }
}
function Test-CocArtifacts {
    param([string]$RunPath)
    $root=(Resolve-Path -LiteralPath $RunPath).Path
    Assert-CocNoReparse $root
    $manifest = Get-Content -LiteralPath (Join-Path $root 'artifact-manifest.json') -Raw | ConvertFrom-Json
    foreach ($file in $manifest.files) {
        if ([IO.Path]::IsPathRooted($file.path) -or $file.path -match '(^|[\\/])\.\.([\\/]|$)') { throw 'Unsafe artifact path.' }
        $path=Join-Path $root $file.path
        if (-not (Test-CocChildPath $path $root)) { throw 'Artifact path escapes run.' }
        Assert-CocNoReparse $path
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $file.sha256) { throw "Artifact mismatch: $($file.path)" }
    }
    [pscustomobject]@{Status='matched-local-manifest';Files=@($manifest.files).Count;Trust='Confirm manifest digest independently; hashes alone do not authenticate custody.'}
}
Export-ModuleMember -Function Write-CocJson,Write-CocEvent,Test-CocCaseId,Test-CocChildPath,Assert-CocNoReparse,Test-CocRelease,New-CocRun,Invoke-CocModule,Complete-CocRun,Test-CocArtifacts
