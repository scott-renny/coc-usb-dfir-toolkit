"""Field usability, readiness and explicitly chosen generated-log retention."""
import argparse,contextlib,datetime,hashlib,html,importlib.util,json,os,pathlib,shutil,tempfile,uuid,zipfile
def sibling(name):
 s=importlib.util.spec_from_file_location('coc_'+name,pathlib.Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
dfir=sibling('dfir_pipeline');field=sibling('field_operations');response=sibling('response_pipeline');advanced=sibling('advanced_pipeline')
GUIDES={
 'Malware':[('Static executable review','Start-COC-DFIR.ps1','SuspiciousAssessment'),('Static configuration review','Start-COC-Advanced.ps1','Config')],
 'Phishing':[('Acquired email review','Start-COC-Investigation.ps1','Email'),('Extracted URL review','Start-COC-Enrichment.ps1','URLs')],
 'Server':[('Acquired access-log runbook','Start-COC-Response.ps1','ServerRunbook'),('Acquired event timeline','Start-COC-DFIR.ps1','EventTimeline')],
 'Network':[('Acquired PCAP review','Start-COC-DFIR.ps1','NetworkAssessment')],
 'Evidence':[('Verified file-copy intake','Start-COC-Field.ps1','Transfer'),('Acquired working-copy triage','Start-COC-DFIR.ps1','OfflineTriage')]}
def dump(p,v):p.write_text(json.dumps(v,indent=2,ensure_ascii=False),encoding='utf-8')
def read(p):
 if p.stat().st_size>16*1024**2:raise ValueError('JSON exceeds scope')
 return json.loads(p.read_text(encoding='utf-8-sig'))
def guide(scenario):
 if scenario not in GUIDES:raise ValueError('Unknown incident scenario')
 return dict(scenario=scenario,steps=[dict(number=i+1,title=t,launcher=l,profile=p,status='planned') for i,(t,l,p) in enumerate(GUIDES[scenario])],analyst_review=['Confirm authority and evidence scope.','Preserve volatile evidence through separately authorized acquisition procedures when appropriate.','Review coverage, timing and alternate explanations; negative findings do not clear a host.','Containment and remediation require separate decisions; nothing here runs them automatically.'])
def handoff(source,raw,notes):
 verified=field.verify_case(source);run=read(source/'run.json');manifest=read(source/'artifact-manifest.json')
 packet=dict(source_case=str(source),verification=verified,run=run,evidence_index=manifest['files'],analyst_notes=notes,unresolved_findings='Analyst must document outstanding findings; parser completion is not case resolution.',custody_transfer=dict(status='NOT TRANSFERRED',released_by='',received_by='',utc_time='',method='',purpose='',recipient_manifest_verification='Pending'),recipient_instructions=['Compare the manifest SHA256 against a separately supplied trusted reference.','Verify every artifact before analysis.','Record receipt identity/time/method separately; this template does not prove custody.'],tool_versions='See included toolkit-inventory.json; staged version does not prove execution.')
 dump(raw/'handoff.json',packet);(raw/'source-artifact-manifest.json').write_bytes((source/'artifact-manifest.json').read_bytes());dump(raw/'toolkit-inventory.json',read(pathlib.Path(__file__).resolve().parents[2]/'manifests/tools.json'))
 (raw/'custody-transfer-form.txt').write_text('COC EVIDENCE HANDOFF — NOT YET TRANSFERRED\nSource case: '+str(source)+'\nSource manifest SHA256: '+verified['manifest_sha256']+'\nReleased by:\nReceived by:\nUTC time and clock source:\nTransfer method and protection:\nPurpose:\nRecipient verification result:\nUnresolved findings:\n',encoding='utf-8');field.verify_case(source);return dict(indexed_files=len(manifest['files']),source_manifest_sha256=verified['manifest_sha256'])
def freshness(root,raw,asof=None):
 release=read(root/'COC/manifests/release.json');ready=read(root/'COC/manifests/field-readiness.json');entries={e['name']:e for e in ready};asof=asof or datetime.datetime.now(datetime.timezone.utc)
 rows=[]
 for tool in read(root/'COC/manifests/tools.json')['tools']:
  state=entries.get(tool['name'],{});rows.append(dict(name=tool['name'],version=tool.get('version','unknown'),status=state.get('status','not-recorded'),note=state.get('note',''),release_built_utc=release.get('built_utc'),upstream_release_date=None,current_upstream_version=None,freshness='UNKNOWN — no online check',dependencies='See tool readiness guide; not probed by this dashboard'))
 images=read(root/'COC/lab/Offline-Analysis/images.json');rules=read(root/'COC/manifests/response-acquisition.json')['rules']
 snapshot=datetime.datetime(2026,10,14,tzinfo=datetime.timezone.utc);age=(asof-snapshot).days
 data=dict(as_of_utc=asof.isoformat(),toolkit_release=release['release'],manifest_sha256=dfir.digest(root/'COC/manifests/release.json'),tools=rows,offline_images=images,suricata_rules=rules,rule_snapshot_date='2026-10-14',rule_snapshot_age_days=age if age>=0 else None,clock_warning='Local host clock unverified; negative age is unknown' if age<0 else 'Local host clock unverified',rule_snapshot_date_basis='Workstation acquisition date; not a publisher release timestamp',yara_snapshot=next((t for t in rows if t['name']=='YARA Forge full'),None),automatic_downloads=False,network_checks=False,limitations=['A package date or recent release does not establish current signatures or operational readiness.','Missing dates and upstream currency are explicitly unknown.','Existing blocked/pending tool states are preserved; use full toolkit integrity verification separately.'])
 dump(raw/'freshness.json',data);return dict(tools=len(rows),online_checks=False)
def practice(root,case):
 results=[];raw=case/'raw';python=root/'COC/tools/windows/Python/python.exe'
 # Only tool-created harmless input copies in a temporary sibling are cleaned.
 with tempfile.TemporaryDirectory(prefix='.coc-practice-',dir=case.parent) as temporary:
  temp=pathlib.Path(temporary)
  for profile,name in [('ServerRunbook','access.log'),('PyInstaller','practice-carchive.bin'),('ContainerReview','practice-container.tar')]:
   inp=temp/profile;inp.mkdir();shutil.copyfile(root/'COC/practice/response'/name,inp/name);out=raw/('practice-'+profile);out.mkdir()
   status=dfir.run_process([str(python),'-B',str(pathlib.Path(__file__).with_name('response_pipeline.py')),'--toolkit',str(root),'--case',str(out),'--profile',profile,'--input',str(inp)],str(raw),out/'process',advanced.environment(raw),120)
   result=read(out/'raw/analysis-result.json') if (out/'raw/analysis-result.json').exists() else {};passed=status['status']=='collected' and result.get('status')=='COMPLETE'
   if passed and profile=='ServerRunbook':passed=read(out/'raw/server-events.json')[0]['client']=='192.0.2.1'
   if passed and profile=='PyInstaller':passed=(out/'raw/members/0000.bin').read_bytes()==b'COC harmless data-only CArchive fixture\n'
   if passed and profile=='ContainerReview':passed=any(json.loads(line).get('name')=='practice' for line in (out/'raw/dissect/stdout.log').read_text().splitlines() if line.strip())
   results.append(dict(profile=profile,expected_result_matched=passed,process=status))
 dump(raw/'practice-results.json',dict(results=results,host_collection=False,boot_tested=False,live_queries_tested=False,lab_runtime_tested=False))
 if not all(r['expected_result_matched'] for r in results):raise ValueError('Practice partial; inspect expected-result checks')
 return dict(practice_checks=len(results),all_expected_results_matched=True)
def managed_case(source):
 verified=field.verify_case(source);run=read(source/'run.json')
 if run.get('schema_version')!=1 or not run.get('run_id') or not run.get('authority_reference') or run.get('status') in (None,'RUNNING') or not run.get('ended_utc'):raise ValueError('A finalized COC case is required')
 return verified
def eligible(rel):
 parts=pathlib.PurePosixPath(rel).parts
 return rel in {'activity.log','errors.log','events.jsonl'} or (len(parts)>=3 and parts[0]=='raw' and parts[-1] in {'stdout.log','stderr.log'} and not any(p.casefold() in {'verified-copy','input','inputs','evidence','extracted','members','working-copy','working','retention','attachments','attachment','recovered','carved','exports','mail','messages','sources'} for p in parts[1:-1]))
def log_plan(source):
 verified=managed_case(source);entries=read(source/'artifact-manifest.json')['files'];rows=[e for e in entries if eligible(e['path'])]
 plan=dict(case=str(source),source_manifest_sha256=verified['manifest_sha256'],files=rows,total_bytes=sum(e['bytes'] for e in rows),exclusions='Acquired evidence/system logs, non-allowlisted parser outputs, manifests, notes, backups and unknown files are excluded. No secure erase claim.')
 plan['plan_id']=hashlib.sha256(json.dumps(plan,sort_keys=True).encode()).hexdigest();return plan
def selection(plan,value):
 if value=='ALL':return list(plan['files'])
 try:indexes=[int(n.strip()) for n in value.split(',')]
 except ValueError:raise ValueError('Select displayed file numbers or ALL')
 if len(set(indexes))!=len(indexes) or not indexes or min(indexes)<1 or max(indexes)>len(plan['files']):raise ValueError('Invalid or duplicate selection')
 return [plan['files'][i-1] for i in indexes]
def archive_case(source,destination,plan):
 if managed_case(source)['manifest_sha256']!=plan['source_manifest_sha256']:raise ValueError('Case changed since preview')
 if destination.exists():raise ValueError('Archive destination already exists')
 entries=read(source/'artifact-manifest.json')['files'];total=sum(e['bytes'] for e in entries)
 if total>8*1024**3 or shutil.disk_usage(destination.parent).free<total+1024**3:raise ValueError('Archive exceeds 8 GiB scope or 1 GiB reserve')
 expected={e['path']:e for e in entries};expected['artifact-manifest.json']=dict(path='artifact-manifest.json',bytes=(source/'artifact-manifest.json').stat().st_size,sha256=plan['source_manifest_sha256'])
 with destination.open('xb') as handle,zipfile.ZipFile(handle,'w',compression=zipfile.ZIP_STORED,allowZip64=True,strict_timestamps=False) as z:
  for rel,e in expected.items():
   p=source/rel;dfir.reject_links(p)
   if dfir.digest(p)!=e['sha256']:raise ValueError('Case changed during archive')
   z.write(p,arcname=rel)
 with zipfile.ZipFile(destination) as z:
  if len(z.infolist())!=len(expected) or set(z.namelist())!=set(expected):raise ValueError('Archive membership mismatch')
  for rel,e in expected.items():
   with z.open(rel) as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!=e['sha256']:raise ValueError('Archive read-back mismatch')
 if managed_case(source)['manifest_sha256']!=plan['source_manifest_sha256']:raise ValueError('Source changed during archive')
 return dict(path=str(destination),sha256=dfir.digest(destination),bytes=destination.stat().st_size,read_back_verified=True,compression='stored',protection='Owner attestation; ZIP is not encrypted')
@contextlib.contextmanager
def source_lock(source,maintenance_case):
 if source.parent==maintenance_case.parent:raise ValueError('Use a different protected parent for the maintenance run; source parent must be exclusively locked')
 p=source.parent/'.coc-session.lock';dfir.reject_links(p)
 with p.open('a+b') as f:
  if os.name=='nt':
   import msvcrt
   f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)
  else:
   import fcntl
   fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
  try:yield
  finally:
   if os.name=='nt':f.seek(0);msvcrt.locking(f.fileno(),msvcrt.LK_UNLCK,1)
   else:fcntl.flock(f,fcntl.LOCK_UN)
def retain(source,case,root,mode,archive_root=None,chosen='',confirm='',reason=''):
 field.separate(source,case,root);raw=case/'raw'
 with source_lock(source,case):
  plan=log_plan(source);dump(raw/'log-plan.json',plan)
  if mode=='LogsPreview':return dict(plan_id=plan['plan_id'],candidates=len(plan['files']),bytes=plan['total_bytes'],changed_source=False)
  if not archive_root:raise ValueError('Existing protected archive parent required')
  dfir.reject_links(archive_root);archive_root=archive_root.resolve();field.separate(source,archive_root,root)
  if archive_root==case or archive_root.is_relative_to(case) or case.is_relative_to(archive_root):raise ValueError('Archive and maintenance case must be separate')
  selected=selection(plan,chosen) if mode=='LogsClean' else []
  if archive_root.drive.startswith('\\\\'):raise ValueError('Network archives are not enabled')
  if mode=='LogsClean' and (not selected or confirm!='DELETE '+plan['plan_id'] or not reason.strip() or reason=='Analyst notes not supplied'):raise ValueError('Exact preview plan confirmation and cleanup reason required')
  archived=archive_case(source,archive_root/(source.name+'-'+uuid.uuid4().hex[:12]+'.zip'),plan);dump(raw/'archive-verification.json',archived)
  if mode=='LogsArchive':return dict(archive=archived,changed_source=False)
  # All files remain accountable: original manifest is retained, selected logs
  # are archived, and a new manifest records the documented retention revision.
  original=(source/'artifact-manifest.json').read_bytes();old=read(source/'artifact-manifest.json');deleted=[];folder=source/'retention'/uuid.uuid4().hex
  try:
   if managed_case(source)['manifest_sha256']!=plan['source_manifest_sha256']:raise ValueError('Case changed after archive')
   if dfir.digest(pathlib.Path(archived['path']))!=archived['sha256']:raise ValueError('Archive changed before cleanup')
   dfir.reject_links(folder);folder.mkdir(parents=True);dfir.reject_links(folder);(folder/'artifact-manifest.before.json').write_bytes(original)
   dump(folder/'cleanup.json',dict(state='PREPARED',reason=reason,plan=plan,selected=selected,archive=archived))
   for e in selected:
    p=source/e['path'];dfir.reject_links(p)
    if dfir.digest(source/'artifact-manifest.json')!=plan['source_manifest_sha256'] or dfir.digest(p)!=e['sha256'] or p.stat().st_size!=e['bytes']:raise ValueError('Changed file/manifest; cleanup stopped')
    p.unlink();deleted.append(e)
   dump(folder/'cleanup.json',dict(state='SELECTED LOGS ARCHIVED AND REMOVED',utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),reason=reason,plan_id=plan['plan_id'],selected=selected,archive=archived,original_manifest_sha256=plan['source_manifest_sha256'],not_secure_erasure=True))
   selected_paths={e['path'] for e in selected};remaining=[e for e in old['files'] if e['path'] not in selected_paths]
   for e in remaining:
    p=source/e['path'];dfir.reject_links(p)
    if dfir.digest(p)!=e['sha256'] or p.stat().st_size!=e['bytes']:raise ValueError('Unselected artifact changed; cleanup revision stopped')
   additions=[dict(path=p.relative_to(source).as_posix(),bytes=p.stat().st_size,sha256=dfir.digest(p)) for p in folder.iterdir()]
   expected={e['path'] for e in remaining+additions}|{'artifact-manifest.json'};actual=set()
   for base,dirs,names in os.walk(source,followlinks=False):
    for n in dirs:dfir.reject_links(pathlib.Path(base)/n)
    for n in names:q=pathlib.Path(base)/n;dfir.reject_links(q);actual.add(q.relative_to(source).as_posix())
   if actual!=expected:raise ValueError('Unexpected/missing case files; revision stopped')
   updated=dict(old);updated['files']=sorted(remaining+additions,key=lambda e:e['path']);updated['retention_revision']=dict(original_manifest_sha256=plan['source_manifest_sha256'],receipt=(folder/'cleanup.json').relative_to(source).as_posix())
   if dfir.digest(source/'artifact-manifest.json')!=plan['source_manifest_sha256']:raise ValueError('Original manifest changed before commit')
   dfir.reject_links(folder);staged=folder/'manifest.pending';dump(staged,updated);os.replace(staged,source/'artifact-manifest.json');verified=field.verify_case(source)
   return dict(archive=archived,deleted_files=len(deleted),deleted_bytes=sum(e['bytes'] for e in deleted),new_manifest_sha256=verified['manifest_sha256'],original_manifest_sha256=plan['source_manifest_sha256'],changed_source=True,not_secure_erasure=True)
  except Exception:
   # Never overwrite a file that appeared/changed after removal. Recover only
   # this operation's missing originals from the verified archive.
   with zipfile.ZipFile(archived['path']) as z:
    for e in deleted:
     p=source/e['path'];dfir.reject_links(p)
     if not p.exists():
      with p.open('xb') as out,z.open(e['path']) as inp:shutil.copyfileobj(inp,out)
   if folder.exists():dump(folder/'cleanup.json',dict(state='INTERRUPTED — REVIEW REQUIRED',deleted_before_failure=deleted,recovery='Missing removed originals restored where possible; existing files never overwritten',archive=archived,original_manifest_sha256=plan['source_manifest_sha256']))
   dump(raw/'cleanup-interrupted.json',dict(deleted_before_failure=deleted,archive=archived,source_requires_review=True));raise
def main():
 p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--profile',choices=['Guide','Practice','Handoff','Freshness','LogsPreview','LogsArchive','LogsClean'],required=True);p.add_argument('--input');p.add_argument('--query',default='');p.add_argument('--notes',default='Analyst notes not supplied');p.add_argument('--archive-root');p.add_argument('--selection',default='');p.add_argument('--confirm',default='');a=p.parse_args()
 root=pathlib.Path(a.toolkit).absolute();case=pathlib.Path(a.case).absolute()
 for q in (root,case):dfir.reject_links(q)
 root=root.resolve();case=case.resolve()
 if root==case or root.is_relative_to(case) or case.is_relative_to(root):raise ValueError('Separate output required')
 raw=case/'raw';raw.mkdir(exist_ok=True);result=dict(status='PARTIAL',profile=a.profile)
 try:
  if a.profile=='Guide':data=guide(a.query);dump(raw/'incident-plan.json',data)
  elif a.profile=='Practice':data=practice(root,case)
  elif a.profile=='Freshness':data=freshness(root,raw)
  else:
   if not a.input:raise ValueError('Existing finalized case required')
   source=pathlib.Path(a.input).absolute();dfir.reject_links(source);source=source.resolve();field.separate(source,case,root)
   if a.profile=='Handoff':data=handoff(source,raw,a.notes)
   else:data=retain(source,case,root,a.profile,pathlib.Path(a.archive_root).absolute() if a.archive_root else None,a.selection,a.confirm,a.notes)
  result.update(status='COMPLETE',result=data)
 except Exception as e:result['error']=str(e)
 dump(raw/'analysis-result.json',result)
 artifacts={q.name:read(q) for q in raw.glob('*.json') if q.stat().st_size<8*1024**2}
 (raw/'operations.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;"><title>COC operations</title><h1>COC field operations</h1><pre>'+html.escape(json.dumps(artifacts,indent=2))+'</pre>',encoding='utf-8');print(json.dumps(result));return 0 if result['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
