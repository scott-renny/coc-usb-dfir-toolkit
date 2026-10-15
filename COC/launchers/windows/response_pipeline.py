"""Fixed, bounded response workflows. Evidence is parsed, never executed."""
import argparse,collections,csv,datetime,hashlib,html,importlib.util,ipaddress,json,os,pathlib,re,shutil,struct,zlib
def sibling(name):
 s=importlib.util.spec_from_file_location('coc_'+name,pathlib.Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
dfir=sibling('dfir_pipeline');field=sibling('field_operations');advanced=sibling('advanced_pipeline')
PROFILES=['ServerLogs','PyInstaller','ContainerReview','Correlate','LiveSnapshot','ServerRunbook']
QUERIES={
 'system':'SELECT hostname,uuid,cpu_brand,physical_memory FROM system_info LIMIT 1;',
 'os':'SELECT name,version,build,platform FROM os_version LIMIT 1;',
 'processes':'SELECT pid,parent,name,path,cmdline,uid FROM processes LIMIT 5000;',
 'listeners':'SELECT pid,port,protocol,family,address FROM listening_ports LIMIT 5000;',
 'connections':'SELECT pid,local_address,local_port,remote_address,remote_port,state FROM process_open_sockets LIMIT 5000;',
 'services':'SELECT name,display_name,status,start_type,path,pid FROM services LIMIT 5000;',
 'startup':'SELECT name,path,source,status,username FROM startup_items LIMIT 5000;',
 'users':'SELECT uid,gid,username,directory,shell FROM users LIMIT 5000;'}
def dump(p,x):p.write_text(json.dumps(x,indent=2,ensure_ascii=False),encoding='utf-8')
def utc(value):
 try:
  d=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
  if d.tzinfo is not None:return d.astimezone(datetime.timezone.utc).isoformat()
 except (ValueError,TypeError):pass
 return None
def server_logs(files,out):
 rows=[];unparsed=[];selected=[f for f in files if pathlib.Path(f['path']).suffix.lower() in {'.log','.txt'}]
 if not selected or len(selected)>20:raise ValueError('Select 1-20 acquired access logs (.log/.txt)')
 combined=re.compile(r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^]]+)\] "(?P<method>\S+) (?P<uri>.*?) (?P<protocol>[^" ]+)" (?P<status>\d{3}) (?P<bytes>\d+|-) (?:"[^"\r\n]*" "[^"\r\n]*")(?: .*)?$')
 for f in selected:
  if f['bytes']>16*1024**2:raise ValueError('Log exceeds 16 MiB')
  fields=None
  with pathlib.Path(f['path']).open(encoding='utf-8-sig',errors='replace') as stream:
   for line_no,line in enumerate(stream,1):
    if len(rows)+len(unparsed)>=100000:raise ValueError('100,000 log-line cap reached')
    if len(line)>65536:raise ValueError('Oversized log line')
    line=line.rstrip('\r\n')
    if line.startswith('#Fields:'):fields=line[8:].split();continue
    if not line or line.startswith('#'):continue
    base=dict(source=f['relative'],source_sha256=f['sha256'],line=line_no)
    if fields:
     values=line.split()
     if len(values)!=len(fields):unparsed.append(dict(**base,reason='IIS field count mismatch'));continue
     v=dict(zip(fields,values));t=v.get('date','')+' '+v.get('time','');stamp=utc(t+'+00:00') if v.get('date') and v.get('time') else None
     row=dict(**base,format='IIS-W3C',timestamp_original=t,timestamp_utc=stamp,timezone_basis='IIS W3C UTC convention; host clock accuracy unverified',client=v.get('c-ip'),method=v.get('cs-method'),uri=v.get('cs-uri-stem'),query=v.get('cs-uri-query'),status=v.get('sc-status'),record=v)
    else:
     m=combined.fullmatch(line)
     if not m:unparsed.append(dict(**base,reason='Unsupported combined log format'));continue
     v=m.groupdict();stamp=None
     try:stamp=datetime.datetime.strptime(v['time'],'%d/%b/%Y:%H:%M:%S %z').astimezone(datetime.timezone.utc).isoformat()
     except ValueError:pass
     row=dict(**base,format='Apache/Nginx-combined',timestamp_original=v['time'],timestamp_utc=stamp,timezone_basis='Explicit offset when valid; host clock accuracy unverified',client=v['ip'],method=v['method'],uri=v['uri'],status=v['status'],record=v)
    rows.append(row)
 dump(out/'server-events.json',rows)
 with (out/'server-events.csv').open('w',encoding='utf-8',newline='') as stream:
  columns=['source','source_sha256','line','format','timestamp_original','timestamp_utc','timezone_basis','client','method','uri','status'];writer=csv.DictWriter(stream,fieldnames=columns,extrasaction='ignore');writer.writeheader();writer.writerows(rows)
 dump(out/'server-summary.json',dict(parsed=len(rows),unparsed=unparsed,status_counts=dict(collections.Counter(r['status'] for r in rows)),interpretation='Counts and investigative leads only; no maliciousness or identity conclusion'))
 if not rows or unparsed:raise ValueError('Log coverage partial; inspect server-summary.json')
 return len(rows)
def safe_name(name):
 p=pathlib.PurePosixPath(name)
 if not name or '\\' in name or ':' in name or '\x00' in name or p.is_absolute() or '..' in p.parts or any(c in name for c in '<>"|?*') or any(x.endswith((' ','.')) or x.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*[f'{a}{i}' for a in ('COM','LPT') for i in range(1,10)]} for x in p.parts):raise ValueError('Unsafe archive path')
 return p
def extract_carchive(src,out):
 """CArchive only. PYZ remains opaque; no marshal, imports, crypto or code evaluation."""
 if src.stat().st_size>64*1024**2:raise ValueError('Input exceeds 64 MiB')
 data=src.read_bytes();magic=b'MEI\014\013\012\013\016';pos=data.rfind(magic)
 if pos<0 or pos+24>len(data):raise ValueError('Missing/truncated CArchive cookie')
 newer=b'python' in data[pos+24:pos+88].lower();cookie=88 if newer else 24
 if pos+cookie>len(data):raise ValueError('Truncated cookie')
 _,size,toc,tocsize,ver=struct.unpack('!8sIIII',data[pos:pos+24]);start=pos+cookie-size
 if start<0 or toc+tocsize>size-cookie or tocsize>4*1024**2:raise ValueError('Invalid CArchive bounds')
 cursor=start+toc;end=cursor+tocsize;entries=[];total=0;seen=set()
 while cursor<end:
  if cursor+18>end:raise ValueError('Truncated TOC')
  length,offset,packed,expanded,flag,kind=struct.unpack('!IIIIBc',data[cursor:cursor+18])
  if length<19 or cursor+length>end or offset+packed>toc or flag not in (0,1):raise ValueError('Invalid TOC bounds')
  name=data[cursor+18:cursor+length].rstrip(b'\x00').decode('utf-8');p=safe_name(name);key=p.as_posix().casefold()
  if key in seen:raise ValueError('Duplicate archive path')
  seen.add(key);total+=expanded
  if len(entries)>=2000 or total>128*1024**2 or expanded>32*1024**2:raise ValueError('Archive expanded scope exceeded')
  if kind not in (b'b',b'x',b's',b'm',b'M',b'z',b'Z',b'd',b'o'):raise ValueError('Unsupported archive entry type')
  entries.append((p,offset,packed,expanded,flag,kind));cursor+=length
 # Validate every entry before creating output. Output filenames are indexed;
 # archive-provided names are metadata only and cannot select filesystem paths.
 out.mkdir();records=[]
 for i,(p,offset,packed,expanded,flag,kind) in enumerate(entries):
  raw=data[start+offset:start+offset+packed]
  if flag:
   d=zlib.decompressobj();raw=d.decompress(raw,expanded+1)
   if not d.eof or d.unconsumed_tail or d.unused_data:raise ValueError('Invalid/oversized compressed entry')
  if len(raw)!=expanded:raise ValueError('Expanded size mismatch')
  if kind in (b'd',b'o'):continue
  target=out/('%04d.bin'%i);target.write_bytes(raw);records.append(dict(original_name=p.as_posix(),kind=kind.decode(),bytes=len(raw),sha256=dfir.digest(target),output=target.name,python_version=ver,nested_PYZ_decoded=False))
 if not records:raise ValueError('No extractable archive members')
 dump(out/'members.json',records);return len(records)
def correlate(source,out):
 cases=sorted(p for p in source.iterdir() if p.is_dir())
 if not 2<=len(cases)<=10:raise ValueError('Select parent of 2-10 finalized COC cases')
 events=[];observations=[];verified=[]
 for case in cases:
  field.verify_case(case);verified.append(case)
  for f in sorted((case/'raw').rglob('*')):
   if not f.is_file() or f.suffix.lower() not in {'.csv','.json','.jsonl','.log','.txt'} or f.stat().st_size>4*1024**2:continue
   rel=f.relative_to(case).as_posix();digest=dfir.digest(f)
   for n,line in enumerate(f.read_text(encoding='utf-8-sig',errors='replace').splitlines(),1):
    if len(line)>65536:continue
    # Exact textual occurrences are leads, not identities or attribution.
    candidates=[('sha256',m.group().lower(),m.start()) for m in re.finditer(r'\b[0-9a-fA-F]{64}\b',line)]
    for m in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',line):
     try:ipaddress.ip_address(m.group());candidates.append(('ipv4',m.group(),m.start()))
     except ValueError:pass
    for typ,value,offset in candidates:observations.append(dict(type=typ,value=value,case=case.name,source=rel,source_sha256=digest,line=n,character_offset=offset))
    if len(observations)>20000:raise ValueError('20,000 occurrence cap')
   if f.suffix.lower()=='.csv':
    with f.open(encoding='utf-8-sig',errors='replace',newline='') as stream:
     for n,row in enumerate(csv.DictReader(stream),2):
      times=[v for k,v in row.items() if k and k.lower() in {'timestamp','timestamp_original','timecreated','timecreatedutc','datetime'} and isinstance(v,str)]
      original=times[0] if len(times)==1 else None;normalized=utc(row.get('timestamp_utc','')) or (utc(original) if original else None);events.append(dict(case=case.name,source=rel,source_sha256=digest,row=n,timestamp_original=original,timestamp_utc=normalized,clock_offset_seconds=None,clock_accuracy='unverified',record=row))
      if len(events)>20000:raise ValueError('20,000 event cap')
 groups=collections.defaultdict(list)
 for r in observations:groups[(r['type'],r['value'])].append(r)
 links=[dict(type=k[0],value=k[1],occurrences=v) for k,v in groups.items() if len({r['case'] for r in v})>1]
 dump(out/'cross-case-links.json',links);dump(out/'correlation-events.json',events);dump(out/'correlation-coverage.json',dict(cases=[p.name for p in cases],text_occurrences=len(observations),csv_events=len(events),limitations=['Selected text SHA256/IPv4 and CSV timestamp fields only; not a universal timeline importer.','Naive/ambiguous timestamps remain unknown. No clock adjustment or attribution inferred.','No link is not evidence of no relationship.']))
 for case in verified:field.verify_case(case)
 return len(links)
def main():
 p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--input');p.add_argument('--profile',choices=PROFILES,required=True);p.add_argument('--live-authorized',action='store_true');a=p.parse_args()
 root=pathlib.Path(a.toolkit).absolute();case=pathlib.Path(a.case).absolute()
 for q in (root,case):dfir.reject_links(q)
 root=root.resolve();case=case.resolve()
 if root==case or root.is_relative_to(case) or case.is_relative_to(root):raise ValueError('Case must be outside toolkit')
 raw=case/'raw';raw.mkdir(exist_ok=True);steps=[];source=None;before=[];r=dict(status='PARTIAL',profile=a.profile)
 try:
  env=advanced.environment(raw)
  if a.profile=='LiveSnapshot':
   if not a.live_authorized:raise ValueError('Explicit LIVE authorization required')
   exe=dfir.one(root/'COC/tools/windows/osquery','osqueryi.exe');dump(raw/'fixed-query-pack.json',QUERIES)
   for label,query in QUERIES.items():
    step=raw/label;cmd=[str(exe),'--json','--disable_extensions=true','--disable_events=true','--ephemeral=true','--disable_logging=true',query]
    result=dfir.run_process(cmd,str(raw),step,env,45);steps.append(dict(query=label,**result))
    if result['status']=='collected':
     data=json.loads((step/'stdout.log').read_text(encoding='utf-8-sig'))
     if not isinstance(data,list):raise ValueError('Invalid osquery output')
   r.update(live_host_changed=True,limitations=['Executing a live tool changes host state; this is triage, not forensic acquisition.','Permissions and table availability affect coverage. No service, extensions, events, uploads or containment.'])
  else:
   if not a.input:raise ValueError('Working-copy input required')
   source=pathlib.Path(a.input).absolute();dfir.reject_links(source);source=source.resolve();field.separate(source,case,root)
   if not source.is_dir():raise ValueError('Input must be a directory')
   if a.profile=='Correlate':dfir.MAX_FILES=5000
   before=dfir.inventory(source);dump(raw/'input-inventory.json',before)
   if a.profile in ('ServerLogs','ServerRunbook'):
    count=server_logs(before,raw);steps.append(dict(step='server-log-review',status='collected',records=count))
    if a.profile=='ServerRunbook':
     dump(raw/'runbook.json',dict(completed=['Working-copy inventory and SHA256','IIS/combined access-log parsing','Coverage and status-count review','Source unchanged verification and case closeout'],analyst_next=['Review requests and time context; status codes alone do not identify an attack.','Correlate with acquired authentication/application logs using existing menu.','Use offline lab Plaso only on a compatible analysis host.'],automatic_containment=False))
   elif a.profile=='PyInstaller':
    if len(before)!=1:raise ValueError('Select exactly one acquired Python-packed file')
    count=extract_carchive(pathlib.Path(before[0]['path']),raw/'members');steps.append(dict(step='bounded-carchive',status='collected',members=count))
   elif a.profile=='Correlate':steps.append(dict(step='verified-case-correlation',status='collected',shared_leads=correlate(source,raw)))
   elif a.profile=='ContainerReview':
    if len(before)!=1 or pathlib.Path(before[0]['path']).suffix.lower() not in {'.tar','.oci'}:raise ValueError('Select one acquired Docker/OCI image tar')
    python=root/'COC/tools/windows/Python/python.exe';worker=pathlib.Path(__file__).with_name('response_dissect.py');step=raw/'dissect'
    result=dfir.run_process([str(python),'-B',str(worker),'--toolkit',str(root),'--input',before[0]['path']],str(raw),step,env,180);steps.append(dict(step='dissect-container-users',**result))
   if field.identities(before)!=field.identities(dfir.inventory(source)):raise ValueError('Source changed during analysis')
   r['source_hashes_unchanged']=True
  r.update(status='COMPLETE' if steps and all(s['status']=='collected' for s in steps) else 'PARTIAL',steps=steps)
 except Exception as e:r.update(error=str(e),steps=steps)
 dump(raw/'analysis-result.json',r);(raw/'response-findings.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;"><title>COC response result</title><h1>Response workflow</h1><pre>'+html.escape(json.dumps(r,indent=2))+'</pre>',encoding='utf-8');print(json.dumps(r));return 0 if r['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
