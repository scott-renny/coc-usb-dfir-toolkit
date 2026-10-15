#!/usr/bin/env python3
"""Offline rootless Podman playbooks for a separately prepared Linux analysis host."""
import argparse,datetime,hashlib,html,json,os,pathlib,re,shutil,subprocess,time,uuid
HOME=pathlib.Path(__file__).resolve().parent
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def clean(p):
 for q in [p,*p.parents]:
  if q.is_symlink():raise ValueError('Symlinks rejected')
 if any(c in str(p) for c in ':,\n\r'):raise ValueError('Unsafe bind path')
def command(engine,image,profile,source,out,rules=None):
 base=[engine,'run','--rm','--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--userns=keep-id','--user',str(os.getuid())+':'+str(os.getgid()),'--pids-limit=128','--memory=2g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,size=512m','--mount=type=bind,source='+str(source)+',destination=/evidence,ro','--mount=type=bind,source='+str(out)+',destination=/output,rw','--workdir=/output']
 if profile=='zeek':return base+['--entrypoint=/usr/local/zeek/bin/zeek',image,'-C','-r','/evidence','LogAscii::use_json=T']
 if profile=='suricata':
  if not rules:raise ValueError('Reviewed Suricata rule file required')
  return base+['--mount=type=bind,source='+str(rules)+',destination=/rules.rules,ro','--entrypoint=/usr/bin/suricata',image,'-r','/evidence','--runmode','single','-c','/etc/suricata/suricata.yaml','-S','/rules.rules','-l','/output','--set','unix-command.enabled=no','--set','stats.enabled=no']
 if profile=='plaso':return base+['--entrypoint=/usr/bin/log2timeline.py',image,'--workers','1','--storage-file','/output/timeline.plaso','/evidence']
 if profile=='psort':return base+['--entrypoint=/usr/bin/psort.py',image,'-o','dynamic','-w','/output/timeline.csv','/output/timeline.plaso']
 raise ValueError('Unknown profile')
def run(cmd,folder,label,limit=900):
 with (folder/(label+'.stdout.log')).open('wb') as so,(folder/(label+'.stderr.log')).open('wb') as se:
  p=subprocess.Popen(cmd,stdout=so,stderr=se,shell=False);start=time.monotonic()
  try:
   while p.poll() is None:
    if time.monotonic()-start>limit or sum(q.stat().st_size for q in folder.rglob('*') if q.is_file())>2*1024**3:raise ValueError('Lab time/output cap reached')
    time.sleep(.5)
  finally:
   if p.poll() is None:p.kill();p.wait()
  if p.returncode:raise ValueError(label+' failed; inspect logs')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('profile',choices=['zeek','suricata','plaso']);p.add_argument('--input',required=True);p.add_argument('--output-parent',required=True);p.add_argument('--case-id',required=True);p.add_argument('--authority',required=True);p.add_argument('--rules');p.add_argument('--run',action='store_true');a=p.parse_args()
 if os.name!='posix' or not hasattr(os,'getuid') or os.getuid()==0:raise ValueError('Use a prepared non-root Linux analysis account with rootless Podman')
 if not a.run or not a.authority.strip() or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',a.case_id):raise ValueError('Explicit --run, authority and valid case ID required')
 source=pathlib.Path(a.input).absolute();parent=pathlib.Path(a.output_parent).absolute()
 for q in (source,parent,HOME):clean(q)
 source=source.resolve();parent=parent.resolve()
 if not source.is_file() or source.stat().st_size>2*1024**3 or not parent.is_dir():raise ValueError('Select one regular acquired file <=2 GiB and existing protected output parent')
 kit=HOME.parents[2]
 if source==parent or source.is_relative_to(parent) or parent.is_relative_to(source) or parent.is_relative_to(kit) or kit.is_relative_to(parent) or source.is_relative_to(kit):raise ValueError('Evidence, cases and toolkit must be separate')
 if a.profile in ('zeek','suricata') and source.suffix.lower() not in ('.pcap','.pcapng','.cap'):raise ValueError('Network workflows accept acquired PCAP files only')
 rules=pathlib.Path(a.rules).absolute() if a.rules else None
 if rules:
  clean(rules)
  if not rules.is_file() or rules.stat().st_size>64*1024**2:raise ValueError('Invalid rule file')
  rules=rules.resolve()
 if a.profile=='suricata' and not rules:raise ValueError('Select an analyst-reviewed rules file; no rules download occurs at runtime')
 engine=shutil.which('podman')
 if not engine:raise ValueError('Podman must already be installed; no engine will be installed by this toolkit')
 info=subprocess.run([engine,'info','--format','json'],capture_output=True,text=True,timeout=30,check=True);host=json.loads(info.stdout)
 if not host.get('host',{}).get('security',{}).get('rootless'):raise ValueError('Rootless engine required')
 if shutil.disk_usage(parent).free<5*1024**3:raise ValueError('At least 5 GiB case-destination free space required; engine storage is additional')
 case=parent/(a.case_id+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);case.mkdir();raw=case/'raw';raw.mkdir();work=raw/'output';work.mkdir();name='coc-'+uuid.uuid4().hex;result=dict(status='PARTIAL',profile=a.profile,authority=a.authority,container_name=name,boot_tested=False)
 before=sha(source);result.update(source=str(source),source_sha256=before,rules_sha256=sha(rules) if rules else None)
 try:
  row=next(r for r in json.loads((HOME/'images.json').read_text()) if r['name']==a.profile);archive=HOME/row['archive']
  if sha(archive)!=row['sha256']:raise ValueError('Offline image archive hash mismatch')
  result['image']=row;run([engine,'load','-i',str(archive)],raw,'image-load',300)
  check=subprocess.run([engine,'image','inspect',row['image_id'],'--format','{{.Id}}'],capture_output=True,text=True,timeout=30,check=True)
  if check.stdout.strip().removeprefix('sha256:')!=row['image_id'].removeprefix('sha256:'):raise ValueError('Loaded image ID mismatch')
  for profile in ([a.profile,'psort'] if a.profile=='plaso' else [a.profile]):
   cmd=command(engine,row['image_id'],profile,source,work,rules);cmd[2:2]=['--name',name];(raw/(profile+'-command.json')).write_text(json.dumps(cmd,indent=2));run(cmd,raw,profile)
  result['status']='COMPLETE'
 except Exception as e:result['error']=str(e)
 finally:
  # Remove only this run's explicitly named container after a timeout/failure.
  subprocess.run([engine,'rm','--force','--ignore',name],capture_output=True,timeout=30)
  result['source_hashes_unchanged']=sha(source)==before
  if not result['source_hashes_unchanged']:result['status']='PARTIAL'
  result['limitations']=['Container restrictions reduce risk; they are not a malware detonation sandbox.','Host/engine image storage changes are expected and logged. No live capture, network, devices, privileged mode or input execution.','Parser output requires analyst review; runtime acceptance was pending at release.','Working-copy timestamps and host clock accuracy require case context.']
  (raw/'analysis-result.json').write_text(json.dumps(result,indent=2));(case/'report.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;"><h1>COC offline lab</h1><pre>'+html.escape(json.dumps(result,indent=2))+'</pre>')
  files=[dict(path=f.relative_to(case).as_posix(),bytes=f.stat().st_size,sha256=sha(f)) for f in case.rglob('*') if f.is_file()];(case/'artifact-manifest.json').write_text(json.dumps(dict(files=files),indent=2));print(str(case))
 return 0 if result['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
