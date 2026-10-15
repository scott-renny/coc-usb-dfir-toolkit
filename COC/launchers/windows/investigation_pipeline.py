"""Offline investigations of acquired working copies; never execute evidence."""
import argparse,collections,csv,datetime,email.policy,email.parser,hashlib,html,importlib.util,ipaddress,json,os,pathlib,re,shutil,sqlite3,struct,sys,time,uuid,urllib.parse
def sibling(name):
    spec=importlib.util.spec_from_file_location('coc_'+name,pathlib.Path(__file__).with_name(name+'.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
dfir=sibling('dfir_pipeline');field=sibling('field_operations')
MAX_TEXT=2*1024**2
def dump(p,value):p.write_text(json.dumps(value,indent=2,ensure_ascii=False),encoding='utf-8')
def text(p):
    if p.stat().st_size>MAX_TEXT:raise ValueError('Text input exceeds 2 MiB: '+p.name)
    return p.read_text(encoding='utf-8-sig',errors='replace')
def indicators(value,source):
    rows=[]
    for match in re.finditer(r'https?://[^\s<>"\x00]+',value,re.I):
        url=match.group().rstrip('.,;)');rows.append(dict(type='url',value=url,source=source,offset=match.start()))
        try:
            host=urllib.parse.urlsplit(url).hostname
            if host and re.search('[A-Za-z]',host):rows.append(dict(type='domain',value=host.casefold().rstrip('.'),source=source,offset=match.start()))
        except ValueError:pass
    for match in re.finditer(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',value):
        rows.append(dict(type='email',value=match.group(),source=source,offset=match.start()))
        rows.append(dict(type='domain',value=match.group().rsplit('@',1)[1].casefold(),source=source,offset=match.start()))
    for match in re.finditer(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',value):
        try:ipaddress.ip_address(match.group());rows.append(dict(type='ipv4',value=match.group(),source=source,offset=match.start()))
        except ValueError:pass
    return rows[:5000]
def report(raw,title,records,limitations):
    dump(raw/'findings.json',dict(title=title,records=records,limitations=limitations))
    body='<h1>'+html.escape(title)+'</h1><p>'+html.escape(' '.join(limitations))+'</p><pre>'+html.escape(json.dumps(records,indent=2,ensure_ascii=False))+'</pre>'
    (raw/'findings.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;"><title>COC Investigation</title><style>body{font:16px system-ui;max-width:1100px;margin:32px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'+body,encoding='utf-8')
def validate_hayabusa(path):
    if path.stat().st_size>64*1024**2:raise ValueError('Hayabusa JSONL exceeds 64 MiB')
    count=0
    with path.open(encoding='utf-8-sig') as f:
        for line in f:
            if not line.strip():continue
            row=json.loads(line);count+=1
            if not isinstance(row,dict) or not all(isinstance(row.get(k),str) for k in ['Timestamp','RuleTitle','RuleID','Level','Computer','Channel']) or not all(isinstance(row.get(k),(dict,list)) for k in ['Details','ExtraFieldInfo']):raise ValueError('Unsupported Hayabusa JSONL schema; do not interpret empty Takajo output')
            if count>100000:raise ValueError('Hayabusa JSONL exceeds 100,000 rows')
    if not count:raise ValueError('Empty Hayabusa JSONL; no Takajo coverage established')
    return count
def email_review(files,raw):
    records=[];iocs=[];coverage=[];attachment_bytes=0;attachment_count=0;message_bytes=0
    for item in files:
        p=pathlib.Path(item['path'])
        if p.suffix.lower()!='.eml':continue
        if item['bytes']>25*1024**2:coverage.append(dict(file=item['relative'],status='unsupported',reason='EML exceeds 25 MiB'));continue
        message_bytes+=item['bytes']
        if message_bytes>128*1024**2:coverage.append(dict(file=item['relative'],status='unsupported',reason='128 MiB combined EML analysis cap'));break
        msg=email.parser.BytesParser(policy=email.policy.default).parsebytes(p.read_bytes())
        if not list(msg.keys()):coverage.append(dict(file=item['relative'],status='unsupported',reason='No email headers recognized'));continue
        if msg.defects:coverage.append(dict(file=item['relative'],status='unsupported',reason='Email parse defects require review'))
        headers={}
        for key in ['From','To','Cc','Reply-To','Return-Path','Subject','Date','Message-ID','Received','Authentication-Results']:
            values=msg.get_all(key,[]);headers[key]=[str(v)[:65536] for v in values[:100]]
            if len(values)>100 or any(len(str(v))>65536 for v in values[:100]):coverage.append(dict(file=item['relative'],status='unsupported',reason='Header excerpt cap reached'))
        record=dict(source=item['relative'],headers=headers,parts=[],parse_defects=[str(d) for d in msg.defects])
        for index,part in enumerate(msg.walk()):
            if index>=200:coverage.append(dict(file=item['relative'],status='unsupported',reason='MIME part cap'));break
            if part.is_multipart():continue
            content=part.get_payload(decode=True) or b'';filename=part.get_filename();kind=part.get_content_type()
            if filename or part.get_content_disposition()=='attachment':
                if attachment_count>=100 or attachment_bytes+len(content)>50*1024**2:coverage.append(dict(file=item['relative'],status='unsupported',reason='Attachment extraction cap'));continue
                attachment_count+=1;attachment_bytes+=len(content)
                suffix=pathlib.PureWindowsPath(filename or '').suffix.lower()
                if suffix not in ['.pdf','.doc','.docm','.docx','.xls','.xlsm','.xlsx','.ppt','.pptm','.pptx','.exe','.dll','.zip','.txt']:suffix='.bin'
                dest=raw/'attachments'/('attachment-'+str(attachment_count)+suffix);dest.parent.mkdir(exist_ok=True)
                with dest.open('xb') as f:f.write(content)
                record['parts'].append(dict(original_filename=filename,content_type=kind,artifact=dest.relative_to(raw).as_posix(),bytes=len(content),sha256=dfir.digest(dest)))
            elif kind in ['text/plain','text/html']:
                value=content[:65536].decode(part.get_content_charset() or 'utf-8',errors='replace')
                record['parts'].append(dict(content_type=kind,text_excerpt=value,truncated=len(content)>65536))
                iocs.extend(indicators(value,item['relative']+'#part-'+str(index)))
        iocs.extend(indicators(json.dumps(headers),item['relative']+'#headers'));records.append(record)
        if len(iocs)>50000:iocs=iocs[:50000];coverage.append(dict(status='unsupported',reason='50,000 email indicator cap'))
    dump(raw/'indicators.json',iocs)
    report(raw,'Email and phishing evidence review',records,['Headers and Authentication-Results are untrusted claims, not verified SPF/DKIM/DMARC results.','URLs are extracted as text, never visited. Attachments are never executed.','PST/OST message inventories use the separate bounded libpff worker; MSG containers are unsupported.'])
    return records,coverage
def linux_review(files,raw):
    records=[];coverage=[]
    for f in files:
        rel=f['relative'].lower();p=pathlib.Path(f['path'])
        selected=any(k in rel for k in ['auth.log','secure','journal','cron','systemd','sshd_config','authorized_keys','bash_history','zsh_history','audit.log'])
        if not selected:continue
        if f['bytes']>MAX_TEXT:coverage.append(dict(file=f['relative'],status='unsupported',reason='2 MiB text cap'));continue
        data=p.read_bytes()
        if b'\x00' in data[:4096]:coverage.append(dict(file=f['relative'],status='unsupported',reason='Binary journal requires an acquired text/JSON export or accepted journal parser'));continue
        for number,line in enumerate(data.decode('utf-8',errors='replace').splitlines(),1):
            if len(records)>=10000:coverage.append(dict(file=f['relative'],status='unsupported',reason='10,000 observation cap'));break
            if not line.strip():continue
            if any(k in rel for k in ['auth.log','secure','audit.log','journal']) and not re.search(r'fail|accept|session|sudo|ssh|auth|login|execve',line,re.I):continue
            records.append(dict(source=f['relative'],line=number,observation=line[:4096],interpretation='Review observation; no maliciousness inferred'))
    report(raw,'Linux acquired-evidence review',records,['No commands are run on the source host.','Raw journal databases, rotated compressed logs and unrecognized formats remain coverage gaps.','Log timestamps and shell-history attribution require analyst interpretation.'])
    return records,coverage
def persistence_review(files,raw):
    records=[];coverage=[]
    for f in files:
        p=pathlib.Path(f['path']);rel=f['relative'].lower()
        if p.suffix.lower() not in ['.csv','.json','.jsonl','.xml','.reg','.txt','.log']:
            if p.name.lower() in ['system','software','ntuser.dat','usrclass.dat']:coverage.append(dict(file=f['relative'],status='unsupported',reason='Binary hive: run existing RECmd/RegistryExplorer first'))
            continue
        if f['bytes']>MAX_TEXT:coverage.append(dict(file=f['relative'],status='unsupported',reason='2 MiB export cap'));continue
        for number,line in enumerate(text(p).splitlines(),1):
            tags=[name for name,pattern in [('registry-startup',r'\\run(?:once)?(?:\\|"|\])|winlogon|image file execution options'),('service',r'services|service(name|path)|imagepath'),('scheduled-task',r'<task|<exec|taskname|scheduled.?task'),('startup-folder',r'startup|start menu'),('event-log-reference',r'4698|7045|4697|4104') ] if re.search(pattern,line,re.I)]
            if tags:records.append(dict(source=f['relative'],line=number,categories=tags,observation=line[:4096],interpretation='Persistence-related text; verify parsed field and context'))
            if len(records)>=10000:coverage.append(dict(file=f['relative'],status='unsupported',reason='10,000 observation cap'));break
    report(raw,'Windows persistence export review',records,['Acquired text/JSON/CSV/XML exports only; no live registry, task or service collection.','Text matches are review leads and do not establish malicious persistence.','Use existing Registry and event-log parsers for binary sources; correlation retains source/line references.'])
    return records,coverage
def compare_cases(source,raw):
    cases=sorted(p for p in source.iterdir() if p.is_dir())
    if not 2<=len(cases)<=10:raise ValueError('Select a parent containing 2–10 finalized case folders')
    groups=collections.defaultdict(list);verified=[];limited=False;aggregate=0
    for case in cases:
        manifest=case/'artifact-manifest.json';dfir.reject_links(manifest)
        if manifest.stat().st_size>16*1024**2:raise ValueError('Manifest too large')
        declared=json.loads(manifest.read_text(encoding='utf-8-sig'))['files'];aggregate+=sum(max(0,int(f['bytes'])) for f in declared)
        if aggregate>16*1024**3:raise ValueError('Selected cases exceed 16 GiB combined verification scope')
        check=field.verify_case(case);verified.append(dict(case=case.name,verification=check));found=[]
        candidates=[p for p in (case/'raw').rglob('*') if p.is_file() and p.stat().st_size<=MAX_TEXT and p.suffix.lower() in ['.json','.jsonl','.csv','.log','.txt']]
        for p in candidates[:200]:
            value=text(p);origin=p.relative_to(case).as_posix()
            found.extend(indicators(value,origin))
            if p.name.endswith('input-inventory.json'):
                data=json.loads(value)
                if isinstance(data,list):
                    for f in data:
                        if re.fullmatch(r'[0-9a-fA-F]{64}',str(f.get('sha256',''))):found.append(dict(type='sha256',value=f['sha256'].lower(),source=origin,relative=f.get('relative','')))
                        name=pathlib.PurePosixPath(str(f.get('relative','')).replace('\\','/')).name
                        if name:found.append(dict(type='filename',value=name.casefold(),source=origin,relative=f.get('relative','')))
            if len(found)>5000:limited=True;found=found[:5000];break
        if len(candidates)>200:limited=True
        for item in found:groups[(item['type'],item['value'])].append(dict(case=case.name,**item))
        if field.verify_case(case)!=check:raise ValueError('Original case changed during comparison')
    matches=[dict(type=k[0],value=k[1],cases=sorted({r['case'] for r in rows}),references=rows) for k,rows in groups.items() if len({r['case'] for r in rows})>1]
    dump(raw/'case-verifications.json',verified)
    report(raw,'Cross-case exact indicator comparison',matches,['Exact strings/hashes only; shared indicators are investigative leads, not attribution.','Raw files may contain escaped/defanged values that this bounded extractor does not recognize.','No online lookups, file uploads or automatic case linking.'])
    return dict(status='PARTIAL' if limited else 'COMPLETE',cases=len(cases),matches=len(matches),limited=limited)
def export_case(source,raw):
    check=field.verify_case(source);run=json.loads((source/'run.json').read_text(encoding='utf-8-sig'));dest=raw/'COC-handoff';dest.mkdir()
    selected=['run.json','summary.json','report.md','coverage.csv','artifact-manifest.json']
    for name in selected:
        p=source/name
        if p.is_file():
            if p.stat().st_size>16*1024**2:raise ValueError('Export metadata too large')
            shutil.copyfile(p,dest/name)
    dump(dest/'handoff.json',dict(schema_version=1,original_case=str(source),original_status=run.get('status'),verification=check,evidence_copied=False,import_compatibility='Generic offline JSON package; no deployed COC API integration asserted'))
    entries=[dict(path=p.name,bytes=p.stat().st_size,sha256=dfir.digest(p)) for p in dest.iterdir() if p.is_file()]
    dump(dest/'handoff-manifest.json',dict(files=entries,trust='Unsigned; retain this manifest digest independently'))
    if field.verify_case(source)!=check:raise ValueError('Original case changed during export')
    return dict(status='COMPLETE',original_status=run.get('status'),exported_metadata_files=len(entries),evidence_copied=False)
def resume_transfer(source,destination,case,root):
    field.separate(source,case,root);dfir.reject_links(destination)
    if not destination.is_dir():raise ValueError('Existing protected staging folder required')
    for other in [source,case,root]:
        if destination==other or destination.is_relative_to(other) or other.is_relative_to(destination):raise ValueError('Staging, source, case and toolkit must be separate trees')
    before=dfir.inventory(source)
    if not before:raise ValueError('Empty source')
    if any(pathlib.PurePosixPath(f['relative']).name in ['.coc-transfer-state.json','.coc-transfer.lock'] or pathlib.PurePosixPath(f['relative']).name.startswith('.coc-partial-') for f in before):raise ValueError('Source uses reserved transfer-control filenames')
    state=destination/'.coc-transfer-state.json';lock=destination/'.coc-transfer.lock'
    state_data=dict(source=str(source),files=[dict(relative=f['relative'],bytes=f['bytes'],sha256=f['sha256']) for f in before])
    with lock.open('x') as gate:
        try:
            if state.exists():
                if state.stat().st_size>2*1024**2 or json.loads(state.read_text(encoding='utf-8'))!=state_data:raise ValueError('Resume scope/source changed; no overwrite')
            else:
                if any(p!=lock for p in destination.iterdir()):raise ValueError('Initial staging folder must be empty')
                with state.open('x',encoding='utf-8') as f:json.dump(state_data,f,indent=2)
            copied=0;skipped=0
            required=sum(f['bytes'] for f in before if not (destination/f['relative']).exists())
            if shutil.disk_usage(destination).free<required+1024**3:raise ValueError('Insufficient staging space plus 1 GiB reserve')
            for item in before:
                src=source/item['relative'];dst=destination/item['relative'];dfir.reject_links(src);dfir.reject_links(dst)
                if dst.exists():
                    if not dst.is_file() or dfir.digest(dst)!=item['sha256']:raise ValueError('Existing destination mismatch; preserved: '+item['relative'])
                    skipped+=1;continue
                dst.parent.mkdir(parents=True,exist_ok=True);partial=dst.with_name('.coc-partial-'+uuid.uuid4().hex)
                with src.open('rb') as inp,partial.open('xb') as out:
                    remaining=item['bytes']
                    while remaining:
                        chunk=inp.read(min(1024**2,remaining))
                        if not chunk:raise ValueError('Source shortened')
                        out.write(chunk);remaining-=len(chunk)
                    if inp.read(1):raise ValueError('Source grew')
                if dfir.digest(partial)!=item['sha256']:raise ValueError('Copy verification failed; partial preserved')
                # Windows rename refuses a destination race; no existing file is replaced.
                if os.name=='nt':partial.rename(dst)
                else:
                    with dst.open('xb') as out,partial.open('rb') as inp:shutil.copyfileobj(inp,out)
                copied+=1
            if field.identities(before)!=field.identities(dfir.inventory(source)):raise ValueError('Source changed during transfer')
            if any(dfir.digest(destination/f['relative'])!=f['sha256'] for f in before):raise ValueError('Final read-back mismatch')
            run=json.loads((case/'run.json').read_text(encoding='utf-8-sig')) if (case/'run.json').exists() else {}
            receipt=dict(status='COMPLETE',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),clock_confidence='Host clock unverified',authority_reference=run.get('authority_reference','not supplied to direct Python test'),source=str(source),destination=str(destination),copied=copied,previously_verified=skipped,files=state_data['files'],limitations=['Content copy only; not disk imaging or NTFS metadata preservation.','Stale lock after a crash requires owner inspection; no automatic lock removal.','Partial files are retained; only listed destination files are verified.','Unsigned transfer receipt, not an authenticated custody signature.'])
            dump(case/'raw'/'transfer-receipt.json',receipt);return receipt
        finally:
            gate.close();lock.unlink()

def external(root,raw,files,profile,notes):
    python=root/'COC/tools/windows/Python/python.exe';worker=pathlib.Path(__file__).with_name('investigation_worker.py');results=[];env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env['APPDATA']=str(raw/'runtime-cache');pathlib.Path(env['APPDATA']).mkdir(exist_ok=True)
    env['DOTNET_ROOT']=str(root/'COC/tools/windows/DotNet');env['DOTNET_MULTILEVEL_LOOKUP']='0'
    started=time.monotonic()
    for i,item in enumerate(files):
        if time.monotonic()-started>900:results.append(dict(id='budget',status='unsupported',reason='15 minute profile cap'));break
        if sum(p.stat().st_size for p in raw.rglob('*') if p.is_file())>2*1024**3:results.append(dict(id='output-budget',status='unsupported',reason='2 GiB case output cap'));break
        p=pathlib.Path(item['path']);suffix=p.suffix.lower();eligible=(profile in ['SQLite','SQLiteCarve'] and item['kind']=='sqlite') or (profile=='RDPCache' and (suffix=='.bmc' or re.fullmatch(r'cache[0-9a-f]{4}\.bin',p.name,re.I))) or (profile=='Memory' and suffix in ['.raw','.mem','.dmp','.vmem']) or (profile=='Email' and suffix in ['.pst','.ost']) or (profile in ['Takajo','TakajoProcessTree'] and (suffix=='.jsonl' or item['kind']=='evtx'))
        if not eligible:continue
        if profile=='RDPCache' and item['bytes']>128*1024**2:
            results.append(dict(id=profile+'-'+str(i),status='unsupported',reason='RDP input exceeds 128 MiB cap'));continue
        out=raw/(profile+'-'+str(i));out.mkdir();name={'RDPCache':'RDP','Email':'PST'}.get(profile,profile)
        if profile in ['SQLite','SQLiteCarve','RDPCache','Memory','Email']:
            cmd=[str(python),'-B',str(worker),'--tool',name,'--input',str(p),'--output',str(out/'parsed')]
            if profile in ['SQLite','SQLiteCarve']:
                # Work on a verified copy with its WAL/rollback companions.
                related=[p,*[pathlib.Path(str(p)+ending) for ending in ['-wal','-shm','-journal'] if pathlib.Path(str(p)+ending).exists()]]
                if sum(q.stat().st_size for q in related)>128*1024**2:results.append(dict(id=profile+'-'+str(i),status='unsupported',reason='SQLite working set exceeds 128 MiB cap'));continue
                work=out/'working';work.mkdir();shutil.copyfile(p,work/p.name)
                for ending in ['-wal','-shm','-journal']:
                    side=pathlib.Path(str(p)+ending)
                    if side.exists():dfir.reject_links(side);shutil.copyfile(side,work/side.name)
                cmd[cmd.index('--input')+1]=str(work/p.name)
            observed=dict(id=profile+'-'+str(i),**dfir.run_process(cmd,str(raw),out,env,120))
            if profile=='RDPCache' and observed['status']=='collected' and not any((out/'parsed').rglob('*.bmp')):observed.update(status='unsupported',reason='No bitmap artifacts produced; cache coverage not established')
            results.append(observed)
        else:
            if item['kind']=='evtx':
                hayabusa=dfir.one(root/'COC/tools/windows/Hayabusa','*.exe');timeline=out/'hayabusa.jsonl'
                converted=dict(id='Hayabusa-JSONL-'+str(i),**dfir.run_process([str(hayabusa),'dfir-timeline','-f',str(p),'-o',str(timeline),'-t','jsonl','-p','super-verbose','-w','-O','--threads','2'],str(hayabusa.parent),out/'conversion',env,120));results.append(converted)
                if converted['status']!='collected' or not timeline.is_file():continue
                p=timeline
            try:validate_hayabusa(p)
            except (ValueError,TypeError) as e:results.append(dict(id='Hayabusa-schema-'+str(i),status='unsupported',reason=str(e)));continue
            exe=dfir.one(root/'COC/tools/windows/Takajo','*.exe')
            commands=['stack-computers','timeline-tasks'] if profile=='Takajo' else ['sysmon-process-tree']
            if profile=='TakajoProcessTree' and not re.fullmatch(r'\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?',notes):raise ValueError('Supply one process GUID as the notes value')
            for command in commands:
                cmd=[str(exe),command,'-q','-t',str(p),'-o',str(out/(command+'.csv' if command!='sysmon-process-tree' else command+'.txt'))]
                if profile=='Takajo':cmd+=['-s']
                if profile=='TakajoProcessTree':cmd+=['-p',notes]
                results.append(dict(id=command+'-'+str(i),**dfir.run_process(cmd,str(exe.parent),out/command,env,120)))
        if len(results)>=20:results.append(dict(id='budget',status='unsupported',reason='20 parser-step cap'));break
    return results
def practice(source):
    source.mkdir();(source/'auth.log').write_text('Oct 14 10:00:00 lab sshd[1]: Failed password for synthetic from 192.0.2.1\n')
    (source/'services.json').write_text(json.dumps([dict(ServiceName='SyntheticService',ImagePath='C:\\Synthetic\\benign.exe')]))
    msg=b'From: sender@example.invalid\r\nTo: analyst@example.invalid\r\nSubject: Synthetic investigation\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHarmless reference https://example.invalid/practice\r\n'
    (source/'sample.eml').write_bytes(msg)
    con=sqlite3.connect(source/'sample.sqlite');con.execute('create table observations(note text)');con.execute("insert into observations values ('synthetic only')");con.commit();con.close()
    (source/'expected.json').write_text(json.dumps(dict(email_domain='example.invalid',linux_observation='Failed password',persistence_service='SyntheticService',sqlite_table='observations',rdp_tiles=1,takajo_computer='SYNTHETIC',dns_domain='example.invalid',http_uri='/synthetic-case')))
    (source/'cache0000.bin').write_bytes(b'RDP8bmp\x00'+struct.pack('<I',2)+struct.pack('<IIHH',1,2,64,64)+b'\x00\x80\xff\x00'*(64*64))
    row=dict(Timestamp='2026-10-14 00:00:00.000 +00:00',Computer='SYNTHETIC',Channel='Sec',EventID=4698,Level='low',RuleID='00000000-0000-0000-0000-000000000001',RuleTitle='Synthetic scheduled task',Details={'Name':'SyntheticTask','User':'SyntheticUser','Content':'<Task><Actions><Exec><Command>synthetic.exe</Command></Exec></Actions></Task>'},ExtraFieldInfo={},RecordID=1,RuleFile='synthetic.yml',EvtxFile='synthetic.evtx')
    (source/'synthetic.jsonl').write_text(json.dumps(row)+'\n')
    def packet(protocol,payload):
        return b'\x00\x11\x22\x33\x44\x55\x00\x66\x77\x88\x99\xaa\x08\x00'+struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),1,0,64,protocol,0,b'\xc0\x00\x02\x01',b'\xc6\x33\x64\x02')+payload
    dns=struct.pack('!HHHHHH',1,0x100,1,0,0,0)+b'\x07example\x07invalid\x00'+struct.pack('!HH',1,1)
    udp=struct.pack('!HHHH',53000,53,8+len(dns),0)+dns
    http=struct.pack('!HHIIBBHHH',50000,80,1,1,0x50,0x18,65535,0,0)+b'GET /synthetic-case HTTP/1.1\r\nHost: example.invalid\r\n\r\n'
    pcap=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    for i,data in enumerate([packet(17,udp),packet(6,http)]):pcap+=struct.pack('<IIII',1700000000+i,0,len(data),len(data))+data
    (source/'synthetic.pcap').write_bytes(pcap)
def main():
    profiles=['Email','Linux','Persistence','Compare','Export','ResumeTransfer','SQLite','SQLiteCarve','RDPCache','Memory','Takajo','TakajoProcessTree','Practice']
    p=argparse.ArgumentParser();p.add_argument('--profile',choices=profiles,required=True);p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--input');p.add_argument('--secondary');p.add_argument('--notes',default='');a=p.parse_args()
    root=pathlib.Path(a.toolkit).absolute();case=pathlib.Path(a.case).absolute()
    for path in [root,case]:dfir.reject_links(path)
    root=root.resolve();case=case.resolve()
    if case==root or case.is_relative_to(root) or root.is_relative_to(case):raise ValueError('Case must be outside toolkit')
    raw=case/'raw';raw.mkdir(exist_ok=True)
    try:
        source=pathlib.Path(a.input).absolute() if a.input else None
        if a.profile=='Practice':source=case/'synthetic-input';practice(source)
        if not source:raise ValueError('Input folder required')
        dfir.reject_links(source);source=source.resolve()
        if a.profile!='Practice':field.separate(source,case,root)
        if a.profile=='Compare':result=compare_cases(source,raw)
        elif a.profile=='Export':result=export_case(source,raw)
        elif a.profile=='ResumeTransfer':
            if not a.secondary:raise ValueError('Separate protected staging folder required')
            dest=pathlib.Path(a.secondary).absolute();dfir.reject_links(dest);result=resume_transfer(source,dest.resolve(),case,root)
        else:
            if a.profile=='Memory':dfir.MAX_INPUT=32*1024**3;dfir.MAX_FILES=4
            files=dfir.inventory(source);dump(raw/'input-inventory.json',files);coverage=[];records=[];results=[]
            if a.profile in ['Email','Practice']:records,coverage=email_review(files,raw)
            if a.profile in ['Linux','Practice']:
                target=raw/'linux' if a.profile=='Practice' else raw;target.mkdir(exist_ok=True);r,c=linux_review(files,target);records+=r;coverage+=c
            if a.profile in ['Persistence','Practice']:
                target=raw/'persistence' if a.profile=='Practice' else raw;target.mkdir(exist_ok=True);r,c=persistence_review(files,target);records+=r;coverage+=c
            if a.profile in ['SQLite','SQLiteCarve','RDPCache','Memory','Email','Takajo','TakajoProcessTree','Practice']:results=external(root,raw,files,'SQLite' if a.profile=='Practice' else a.profile,a.notes)
            if a.profile=='Practice':
                results+=external(root,raw,files,'RDPCache',a.notes)
                results+=external(root,raw,files,'Takajo',a.notes)
                for step in dfir.plan(root,files,'NetworkAssessment',raw/'NetworkAssessment'):results.append(dict(id=step['id'],**dfir.run_process(step['cmd'],step['cwd'],pathlib.Path(step['output']),os.environ.copy(),120)))
            if a.profile=='Email':
                attachment_sets=[folder for folder in raw.rglob('attachments') if folder.is_dir()]
                attachment_files=[]
                for folder in attachment_sets:attachment_files.extend(dfir.inventory(folder))
                env=os.environ.copy();steps=dfir.plan(root,attachment_files,'FileTriage',raw/'attachment-screening')
                screen_started=time.monotonic()
                for step in steps[:20]:
                    if time.monotonic()-screen_started>900:coverage.append(dict(status='unsupported',reason='Attachment screening time budget'));break
                    if sum(p.stat().st_size for p in raw.rglob('*') if p.is_file())>2*1024**3:coverage.append(dict(status='unsupported',reason='2 GiB case output cap'));break
                    results.append(dict(id=step['id'],**dfir.run_process(step['cmd'],step['cwd'],pathlib.Path(step['output']),env,120)))
                if len(steps)>20:coverage.append(dict(status='unsupported',reason='Attachment screening capped at 20 parser steps'))
            if a.profile=='Practice':
                email_data=json.loads((raw/'findings.json').read_text());linux_data=json.loads((raw/'linux/findings.json').read_text());persist=json.loads((raw/'persistence/findings.json').read_text())
                assertions=dict(email=bool(email_data['records']),linux=any('Failed password' in r['observation'] for r in linux_data['records']),persistence=any('SyntheticService' in r['observation'] for r in persist['records']),sqlite=any(r['id'].startswith('SQLite-') and r['status']=='collected' for r in results),rdp=any(raw.rglob('*.bmp')),takajo=any('SYNTHETIC' in p.read_text(encoding='utf-8-sig') for p in raw.rglob('stack-computers.csv')),dns=any('example.invalid' in p.read_text() for p in raw.glob('NetworkAssessment/*/DNS/stdout.log')),http=any('/synthetic-case' in p.read_text() for p in raw.glob('NetworkAssessment/*/HTTP/stdout.log')))
                dump(raw/'practice-assertions.json',assertions)
                if not all(assertions.values()):coverage.append(dict(status='failed',reason='Practice expectation mismatch'))
            if not records and not results:coverage.append(dict(status='unsupported',reason='No eligible inputs for selected profile'))
            unchanged=field.identities(files)==field.identities(dfir.inventory(source))
            result=dict(status='COMPLETE' if unchanged and not coverage and all(r['status']=='collected' for r in results) else 'PARTIAL',profile=a.profile,inputs=len(files),source_hashes_unchanged=unchanged,coverage=coverage,parser_results=results)
        dump(raw/'analysis-result.json',result);print(json.dumps(result));return 0 if result['status']=='COMPLETE' else 2
    except Exception as e:dump(raw/'analysis-result.json',dict(status='PARTIAL',profile=a.profile,error=str(e)));raise
if __name__=='__main__':raise SystemExit(main())
