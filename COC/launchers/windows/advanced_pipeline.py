"""Bounded acquired-copy analysis with fixed command lines and source verification."""
import argparse,importlib.util,json,os,pathlib,re,time,zipfile,xml.etree.ElementTree as ET
def sibling(name):
 s=importlib.util.spec_from_file_location('coc_'+name,pathlib.Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
dfir=sibling('dfir_pipeline');field=sibling('field_operations')
PROFILES=['APK','Carve','AppleLogs','YaraFull','Config','Similarity','Reference']
def apk_check(path):
 if path.stat().st_size>64*1024**2:raise ValueError('APK exceeds 64 MiB')
 with zipfile.ZipFile(path) as z:
  members=z.infolist()
  if len(members)>2000 or sum(i.file_size for i in members)>256*1024**2:raise ValueError('APK expanded scope exceeded')
  seen=set()
  for i in members:
   name=i.filename;canonical=pathlib.PurePosixPath(name)
   if name in seen or '\\' in name or ':' in name or canonical.is_absolute() or '..' in canonical.parts or (i.external_attr>>16)&0o170000==0o120000:raise ValueError('Unsafe/duplicate APK path')
   seen.add(name)
   if i.file_size>1024**2 and i.file_size/max(i.compress_size,1)>100:raise ValueError('APK compression-ratio limit')
  if 'AndroidManifest.xml' not in seen:raise ValueError('No Android manifest')
  return dict(entries=len(members),expanded_bytes=sum(i.file_size for i in members),dex_present=any(re.fullmatch(r'classes\d*\.dex',n) for n in seen),signature_entries=[n for n in seen if n.startswith('META-INF/')][:100],signature_verified=False)
def java(root):return dfir.one(root/'COC/tools/windows/Java','java.exe')
def environment(raw):
 env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','PATH','COMSPEC','PATHEXT','PROCESSOR_ARCHITECTURE','PROCESSOR_ARCHITEW6432','NUMBER_OF_PROCESSORS'}}
 for k in ['TEMP','TMP','APPDATA','LOCALAPPDATA']:env[k]=str(raw)
 env['JADX_CONFIG_DIR']=str(raw/'jadx-config');env['JADX_CACHE_DIR']=str(raw/'jadx-cache')
 env['PYTHONIOENCODING']='utf-8';return env
def main():
 p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--input');p.add_argument('--query',default='');p.add_argument('--profile',choices=PROFILES,required=True);a=p.parse_args()
 root=pathlib.Path(a.toolkit).absolute();case=pathlib.Path(a.case).absolute()
 for path in [root,case]:dfir.reject_links(path)
 root=root.resolve();case=case.resolve()
 if root==case or root.is_relative_to(case) or case.is_relative_to(root):raise ValueError('Case must be outside toolkit')
 raw=case/'raw';raw.mkdir(exist_ok=True);result=dict(status='PARTIAL',profile=a.profile);steps=[]
 try:
  source=None;files=[]
  if a.profile!='Reference':
   if not a.input:raise ValueError('Acquired input folder required')
   source=pathlib.Path(a.input).absolute();dfir.reject_links(source);source=source.resolve();field.separate(source,case,root)
   if a.profile=='AppleLogs':dfir.MAX_FILES=2000
   files=dfir.inventory(source);(raw/'input-inventory.json').write_text(json.dumps(files,indent=2))
  env=environment(raw);started=time.monotonic()
  def run(name,cmd,timeout=120):
   if time.monotonic()-started>900:raise ValueError('15 minute batch scheduling cap reached')
   if sum(p.stat().st_size for p in raw.rglob('*') if p.is_file())>2*1024**3:raise ValueError('2 GiB output cap exceeded')
   out=raw/name;r=dfir.run_process([str(v) for v in cmd],str(raw),out,env,timeout);steps.append(dict(id=name,**r));return out
  python=root/'COC/tools/windows/Python/python.exe';worker=pathlib.Path(__file__).with_name('advanced_worker.py')
  if a.profile=='Reference':run('reference',[python,'-B',worker,'--toolkit',root,'--profile','Reference','--query',a.query,'--output',raw/'reference'])
  elif a.profile=='AppleLogs':
   if not any(f['relative'].lower().endswith('.tracev3') for f in files):raise ValueError('No acquired tracev3 files')
   names={p.name.casefold() for p in source.iterdir() if p.is_dir()}
   if not {'timesync','dsc'}.issubset(names) or not names.intersection({'uuidtext','uuidtexts'}):raise ValueError('Select complete logarchive including timesync, dsc and UUIDText companions')
   out=run('apple',[dfir.one(root/'COC/tools/windows/AppleLogs','*.exe'),'--mode','log-archive','--input',source,'--output',raw/'apple/events.jsonl','--format','jsonl','--bookmark-path',raw/'apple/bookmark.json'])
   data=out/'events.jsonl'
   if not data.exists() or not data.stat().st_size:raise ValueError('No decoded Apple events; coverage not established')
   with data.open(encoding='utf-8') as f:
    for line in f:
     if len(line)>4*1024**2:raise ValueError('Apple event line exceeds review cap')
     if line.strip():json.loads(line)
  elif a.profile=='Similarity':
   if not 2<=len(files)<=20 or any(f['bytes']>16*1024**2 for f in files):raise ValueError('Select 2-20 files, at most 16 MiB each')
   out=run('similarity',[java(root),'-Xmx256m','-cp',root/'COC/apps/tlsh/coc-tlsh.jar','COCTlsh',*[f['path'] for f in files]])
   value=(out/'stdout.log').read_text(encoding='utf-8',errors='replace')
   if 'UNSUPPORTED' in value or not any(line.startswith('DIFF\t') for line in value.splitlines()):raise ValueError('Some files could not produce TLSH hashes; review logs')
  elif a.profile=='Carve':
   if len(files)!=1 or pathlib.Path(files[0]['path']).suffix.lower() not in {'.img','.dd','.raw'}:raise ValueError('Select exactly one ordinary acquired RAW image file (.img/.dd/.raw); raw devices are prohibited')
   if files[0]['bytes']>2*1024**3:raise ValueError('Working image exceeds bounded 2 GiB carving scope')
   run('carve',[dfir.one(root/'COC/tools/windows/PhotoRec','photorec_win.exe'),'/log','/logname',raw/'carve/photorec.log','/d',raw/'carve/recovered','/cmd',files[0]['path'],'partition_none,fileopt,everything,enable,search'],300)
  elif a.profile=='APK':
   selected=[f for f in files if pathlib.Path(f['path']).suffix.lower()=='.apk']
   if not 1<=len(selected)<=5:raise ValueError('Select 1-5 acquired APKs')
   metadata=[]
   for i,f in enumerate(selected):
    apk=pathlib.Path(f['path']);record=dict(source=f['relative'],**apk_check(apk));base='apk-'+str(i)
    run(base+'-manifest',[java(root),'-Xmx512m','-Duser.home='+str(raw),'-jar',dfir.one(root/'COC/apps/apktool','*.jar'),'d','--only-manifest','-j','2','-p',raw/'framework','-o',raw/(base+'-decoded'),apk])
    manifest=raw/(base+'-decoded')/'AndroidManifest.xml'
    if not manifest.exists() or manifest.stat().st_size>2*1024**2:raise ValueError('Manifest decoding incomplete')
    content=manifest.read_bytes()
    if b'<!DOCTYPE' in content.upper() or b'<!ENTITY' in content.upper():raise ValueError('Unsafe manifest XML')
    tree=ET.fromstring(content);ns='{http://schemas.android.com/apk/res/android}'
    record.update(package=tree.get('package'),permissions=[n.get(ns+'name') for n in tree.findall('uses-permission')][:500])
    if record['dex_present']:run(base+'-code',[java(root),'-Xmx768m','-Duser.home='+str(raw),'-cp',dfir.one(root/'COC/apps/jadx','*.jar'),'jadx.cli.JadxCLI','--no-res','-j','2','-d',raw/(base+'-code-output'),apk])
    metadata.append(record)
   (raw/'apk-summary.json').write_text(json.dumps(metadata,indent=2))
  else:
   if not 1<=len(files)<=20 or any(f['bytes']>16*1024**2 for f in files):raise ValueError('Select 1-20 files up to 16 MiB each')
   for i,f in enumerate(files):
    name='item-'+str(i);run(name,[python,'-B',worker,'--toolkit',root,'--profile',a.profile,'--source',f['path'],'--output',raw/name])
  unchanged=not source or field.identities(files)==field.identities(dfir.inventory(source))
  result.update(status='COMPLETE' if unchanged and steps and all(s['status']=='collected' for s in steps) else 'PARTIAL',source_hashes_unchanged=unchanged,parser_results=steps,inputs=len(files))
 except Exception as e:result.update(error=str(e),parser_results=steps)
 (raw/'analysis-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result));return 0 if result['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
