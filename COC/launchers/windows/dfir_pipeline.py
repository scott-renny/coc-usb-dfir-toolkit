"""Bounded analysis of acquired working copies. Never executes an input file."""
import argparse,csv,datetime,hashlib,html,json,os,pathlib,sqlite3,subprocess,time,uuid
MAX_FILES=200;MAX_INPUT=8*1024**3;MAX_OUTPUT=2*1024**3;MAX_STEPS=100;MAX_SECONDS=900
def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(4*1024*1024),b''):h.update(b)
    return h.hexdigest()
def reject_links(p):
    for q in [p,*p.parents]:
        if q.exists() and (q.is_symlink() or (hasattr(q.stat(),'st_file_attributes') and q.stat().st_file_attributes&0x400)):raise ValueError('Reparse/symlink path rejected')
def inventory(folder):
    reject_links(folder);files=[];total=0
    for base,dirs,names in os.walk(folder,followlinks=False):
        for name in dirs:reject_links(pathlib.Path(base)/name)
        for name in sorted(names):
            p=pathlib.Path(base)/name;reject_links(p)
            size=p.stat().st_size;total+=size
            if len(files)>=MAX_FILES or total>MAX_INPUT:raise ValueError('Input scope exceeds 200 files / 8 GiB; select a smaller acquired working set')
            with p.open('rb') as f:magic=f.read(16)
            kind='sqlite' if magic.startswith(b'SQLite format 3') else 'pdf' if magic.startswith(b'%PDF') else 'pe' if magic.startswith(b'MZ') else 'evtx' if magic.startswith(b'ElfFile') else 'file'
            stat=p.stat()
            files.append(dict(path=str(p),relative=p.relative_to(folder).as_posix(),bytes=size,sha256=digest(p),kind=kind,filesystem_modified_utc=datetime.datetime.fromtimestamp(stat.st_mtime,datetime.timezone.utc).isoformat()))
    return files
def one(root,pattern):
    matches=list(root.rglob(pattern))
    if len(matches)!=1:raise ValueError('Ambiguous/missing packaged executable '+pattern)
    return matches[0]
def plan(root,files,profile,raw):
    steps=[];python=root/'COC/tools/windows/Python/python.exe'
    if profile in ['IncidentTimeline','SuspiciousAssessment']:
        selected=['ArtifactBatch','EventTimeline'] if profile=='IncidentTimeline' else ['ExecutableAssessment','FileTriage']
        for sub in selected:
            subset=files if sub!='FileTriage' else [f for f in files if f['kind']!='pe']
            steps.extend(plan(root,subset,sub,raw/sub))
        if profile=='SuspiciousAssessment':
            exe=one(root/'COC/tools/windows/YARA-X','yr.exe')
            for index,item in enumerate(files):
                if item['bytes']<=10*1024**2:
                    steps.append(dict(id=f'{index}-ReviewedYARA',cmd=[str(exe),'scan',str(root/'COC/rules/field-reviewed.yar'),item['path']],output=str(raw/'ReviewedYARA'/str(index)),cwd=str(exe.parent)))
                else:steps.append(dict(id=f'{index}-ReviewedYARA',internal='unsupported',reason='Reviewed-rule input exceeds 10 MiB cap',output=str(raw/'ReviewedYARA'/str(index))))
        if len(steps)>MAX_STEPS:raise ValueError('Combined plan exceeds 100 steps')
        return steps
    if profile=='OfflineTriage':
        for selected in ['ArtifactBatch','EventTimeline','FileTriage','SQLiteReview','BrowserProfile']:steps.extend(plan(root,files,selected,raw/selected))
        if len(steps)>MAX_STEPS:raise ValueError('Combined plan exceeds 100 steps')
        return steps
    if profile in ['AndroidArtifacts','iOSArtifacts'] and files:
        tool='ALEAPP' if profile=='AndroidArtifacts' else 'iLEAPP';exe=one(root/'COC/tools/mobile'/tool,tool.lower()+'.exe');out=raw/tool
        # Compute the selected root from the first inventory entry's relative path.
        source=pathlib.Path(files[0]['path'])
        for _ in pathlib.PurePosixPath(files[0]['relative']).parts:source=source.parent
        return [dict(id=tool,cmd=[str(exe),'-t','fs','-i',str(source),'-o',str(out)],output=str(out),cwd=str(exe.parent))]
    for index,item in enumerate(files):
        p=pathlib.Path(item['path']);name=p.name.lower();out=raw/('item-'+str(index));
        if profile=='ArtifactBatch':
            tool=('LECmd' if name.endswith('.lnk') else 'PECmd' if name.endswith('.pf') else 'JLECmd' if name.endswith(('.automaticdestinations-ms','.customdestinations-ms')) else 'EvtxECmd' if item['kind']=='evtx' else 'AmcacheParser' if name=='amcache.hve' else 'MFTECmd' if name in ['$mft','$j','$boot','$sds'] else 'SrumECmd' if name=='srudb.dat' else 'WxTCmd' if name=='activitiescache.db' else None)
            if tool:steps.append(dict(id=f'{index}-{tool}',cmd=[str(one(root/'COC/tools/windows/Zimmerman'/tool,tool+'.exe')),'-f',str(p),'--csv',str(out)],output=str(out),cwd=str(one(root/'COC/tools/windows/Zimmerman'/tool,tool+'.exe').parent)))
        elif profile=='EventTimeline' and item['kind']=='evtx':
            exe=one(root/'COC/tools/windows/Hayabusa','*.exe')
            steps.append(dict(id=f'{index}-Hayabusa',cmd=[str(exe),'dfir-timeline','-f',str(p),'-o',str(out/'timeline.csv'),'-w','-O','--threads','2'],output=str(out),cwd=str(exe.parent)))
        elif profile=='ExecutableAssessment' and item['kind']=='pe':
            for tool,folder,pattern,flags in [('DetectItEasy','DetectItEasy','diec.exe',['-j','-e','-i']),('bstrings','Zimmerman/bstrings','bstrings.exe',['-q','-f']),('FLOSS','FLOSS','floss.exe',['-j'])]:
                exe=one(root/'COC/tools/windows'/folder,pattern)
                steps.append(dict(id=f'{index}-{tool}',cmd=[str(exe),*flags,str(p)],output=str(out/tool),cwd=str(exe.parent)))
        elif profile=='GoSymbols' and item['kind']=='pe':
            exe=one(root/'COC/tools/windows/GoReSym','GoReSym.exe')
            steps.append(dict(id=f'{index}-GoReSym',cmd=[str(exe),str(p)],output=str(out/'go-symbols'),cwd=str(exe.parent)))
        elif profile=='MetadataAssessment':
            # Native ExifTool failed startup in this environment; retain basic
            # inventory without substituting another runtime around that failure.
            steps.append(dict(id=f'{index}-FileMetadata',internal='metadata',source=item,output=str(out/'metadata')))
        elif profile=='NetworkAssessment' and name.endswith(('.pcap','.pcapng','.cap')):
            exe=one(root/'COC/tools/windows/Wireshark','capinfos.exe')
            steps.append(dict(id=f'{index}-Capinfos',cmd=[str(exe),str(p)],output=str(out/'capture-info'),cwd=str(exe.parent)))
            exe=one(root/'COC/tools/windows/Wireshark','tshark.exe')
            steps.append(dict(id=f'{index}-TShark',cmd=[str(exe),'-n','-r',str(p),'-q','-z','io,phs','-z','conv,tcp','-z','endpoints,ip'],output=str(out/'network-summary'),cwd=str(exe.parent)))
            for label,filter_,fields in [('DNS','dns',['frame.number','frame.time_epoch','ip.src','ip.dst','dns.qry.name','dns.a','dns.aaaa']),('HTTP','http.request',['frame.number','frame.time_epoch','ip.src','ip.dst','http.request.method','http.host','http.request.uri'])]:
                flags=['-n','-r',str(p),'-Y',filter_,'-T','fields','-E','header=y','-E','separator=,','-E','quote=d']
                for field in fields:flags+=['-e',field]
                steps.append(dict(id=f'{index}-{label}',cmd=[str(exe),*flags],output=str(out/label),cwd=str(exe.parent)))
        elif profile=='BulkFeatures':
            exe=one(root/'COC/tools/windows/bulk_extractor','bulk_extractor64.exe')
            # Bounded email/URL extraction only; no carving, image mounting or host devices.
            steps.append(dict(id=f'{index}-bulk_extractor',cmd=[str(exe),'-E','email','-j','2','-M','3','-o',str(out/'features'),str(p)],output=str(out),cwd=str(exe.parent)))
        elif profile=='FileTriage':
            if item['kind']=='pe':
                # Windows policy blocked the packaged capa build during validation;
                # it is retained as a reference archive and is not retried here.
                for tool,exe_name,extra in [('FLOSS','floss.exe',['-j'])]:
                    exe=one(root/'COC/tools/windows'/tool,exe_name)
                    steps.append(dict(id=f'{index}-{tool}',cmd=[str(exe),*extra,str(p)],output=str(out/tool),cwd=str(exe.parent)))
            elif item['kind']=='pdf':
                script=one(root/'COC/tools/offline/DidierStevens','pdfid.py')
                steps.append(dict(id=f'{index}-PDFiD',cmd=[str(python),'-B',str(script),str(p)],output=str(out),cwd=str(script.parent)))
            elif name.endswith(('.doc','.docm','.docx','.xls','.xlsm','.xlsx','.ppt','.pptm','.pptx')):
                steps.append(dict(id=f'{index}-oleid',cmd=[str(python),'-B','-m','oletools.oleid',str(p)],output=str(out),cwd=str(raw)))
        elif profile=='SQLiteReview' and item['kind']=='sqlite':
            steps.append(dict(id=f'{index}-SQLite',internal='sqlite',source=str(p),output=str(out)))
        elif profile=='BrowserProfile' and item['kind']=='sqlite' and name in ['history','places.sqlite']:
            exe=one(root/'COC/tools/windows/Hindsight','hindsight.exe')
            steps.append(dict(id=f'{index}-Hindsight',cmd=[str(exe),'-i',str(p.parent),'-o',str(out/'browser'),'-f','jsonl','-l',str(out/'browser.log'),'--temp_dir',str(out/'working')],output=str(out),cwd=str(exe.parent)))
    if len(steps)>MAX_STEPS:raise ValueError('Plan exceeds 100 steps; select a smaller working set')
    return steps
def run_process(cmd,cwd,out,env,timeout=120):
    out.mkdir(parents=True,exist_ok=True);started=time.monotonic();reason='completed'
    with (out/'stdout.log').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
        proc=subprocess.Popen(cmd,cwd=cwd,env=env,stdout=stdout,stderr=stderr,shell=False)
        try:
            while proc.poll() is None:
                if time.monotonic()-started>timeout or sum(p.stat().st_size for p in out.rglob('*') if p.is_file())>256*1024**2:
                    reason='timeout-or-output-cap'
                    if os.name=='nt':subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],capture_output=True,timeout=15)
                    if proc.poll() is None:proc.kill()
                    proc.wait();break
                time.sleep(0.25)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    if sum(p.stat().st_size for p in out.rglob('*') if p.is_file())>256*1024**2:reason='output-cap-exceeded'
    return dict(exit_code=proc.returncode,reason=reason,elapsed_seconds=round(time.monotonic()-started,3),status='collected' if proc.returncode==0 and reason=='completed' else 'failed')
def sqlite_review(source,out):
    # Query a copied working database; SQLite cannot modify the acquired source.
    import shutil
    related=[source,*[pathlib.Path(str(source)+s) for s in ['-wal','-shm'] if pathlib.Path(str(source)+s).exists()]]
    if sum(p.stat().st_size for p in related)>256*1024**2:raise ValueError('SQLite working-copy set exceeds the 256 MiB step cap')
    out.mkdir(parents=True,exist_ok=True);copy=out/'working.sqlite';shutil.copyfile(source,copy)
    for suffix in ['-wal','-shm']:
        side=pathlib.Path(str(source)+suffix)
        if side.exists():reject_links(side);shutil.copyfile(side,str(copy)+suffix)
    con=sqlite3.connect(copy.as_uri()+'?mode=ro',uri=True)
    try:
        con.execute('PRAGMA query_only=ON')
        rows=[dict(type=r[0],name=r[1],table=r[2],sql=r[3]) for r in con.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name LIMIT 500')]
        (out/'schema.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
    finally:con.close()
def merge_csvs(raw,destination):
    rows=[];cap=50000;warnings=[]
    for p in sorted(raw.rglob('*.csv')):
        if p==destination or p.stat().st_size>64*1024**2:continue
        with p.open(encoding='utf-8-sig',errors='replace',newline='') as f:
            reader=csv.DictReader(f)
            for index,row in enumerate(reader,2):
                if len(rows)>=cap:warnings.append('Correlation capped at 50,000 rows');break
                candidates=[v for k,v in row.items() if k and k.lower() in ['timestamp','timecreated','timecreatedutc','datetime']]
                original=candidates[0] if len(candidates)==1 else '';utc=''
                try:
                    parsed=datetime.datetime.fromisoformat(original.replace('Z','+00:00'))
                    if parsed.tzinfo is not None:utc=parsed.astimezone(datetime.timezone.utc).isoformat()
                except (ValueError,TypeError):pass
                rows.append(dict(source_csv=p.relative_to(raw).as_posix(),source_row=index,timestamp_original=original,timestamp_utc=utc,record_json=json.dumps(row,ensure_ascii=False)))
    rows.sort(key=lambda r:(not bool(r['timestamp_utc']),r['timestamp_utc'],r['source_csv'],r['source_row']))
    with destination.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['source_csv','source_row','timestamp_original','timestamp_utc','record_json']);writer.writeheader()
        for row in rows:writer.writerow({k:("'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v) for k,v in row.items()})
    return dict(rows=len(rows),warnings=warnings,interpretation='Only explicit timezone timestamps are normalized/sorted by UTC; other rows retain provenance without inferred chronology')
def practice(folder):
    folder.mkdir();header=bytearray(80);header[:4]=(76).to_bytes(4,'little');header[4:20]=uuid.UUID('00021401-0000-0000-C000-000000000046').bytes_le;header[60:64]=(1).to_bytes(4,'little');(folder/'sample.lnk').write_bytes(header)
    (folder/'sample.pdf').write_bytes(b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n')
    con=sqlite3.connect(folder/'sample.sqlite');con.execute('CREATE TABLE observations(id INTEGER, note TEXT)');con.execute("INSERT INTO observations VALUES(1,'Synthetic practice only')");con.commit();con.close()
def main():
    p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--input');p.add_argument('--profile',choices=['Inventory','ArtifactBatch','EventTimeline','FileTriage','SQLiteReview','Practice','BrowserProfile','AndroidArtifacts','iOSArtifacts','OfflineTriage','CollectEventLogs','ExecutableAssessment','MetadataAssessment','NetworkAssessment','GoSymbols','IncidentTimeline','SuspiciousAssessment','BulkFeatures'],required=True);a=p.parse_args()
    root=pathlib.Path(a.toolkit).resolve();case=pathlib.Path(a.case).resolve();reject_links(root);reject_links(case)
    if case==root or case.is_relative_to(root):raise ValueError('Case output must be outside toolkit')
    raw=case/'raw';raw.mkdir(exist_ok=True);source=pathlib.Path(a.input).absolute() if a.input else None
    if source:reject_links(source);source=source.resolve()
    if a.profile=='CollectEventLogs':
        if os.name!='nt':raise ValueError('Native Windows event export requires Windows')
        results=[];env=os.environ.copy();exe=pathlib.Path(os.environ['SystemRoot'])/'System32/wevtutil.exe'
        for channel in ['System','Application','Security']:
            out=raw/channel;out.mkdir()
            query='*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]'
            cmd=[str(exe),'epl',channel,str(out/(channel+'.evtx')),'/q:'+query,'/ow:false']
            result=run_process(cmd,str(raw),out,env);result['id']='export-'+channel;results.append(result)
        status='COMPLETE' if all(r['status']=='collected' for r in results) else 'PARTIAL'
        (raw/'analysis-plan.json').write_text(json.dumps({'live_collection':True,'channels':['System','Application','Security'],'window_hours':24,'repairs':False,'uploads':False},indent=2),encoding='utf-8')
        (raw/'analysis-result.json').write_text(json.dumps({'status':status,'results':results,'limitations':['Owner-authorized local live export; normal execution artifacts','Host clock unverified; last 24 hours only','Security export may be access denied']},indent=2),encoding='utf-8')
        return 0 if status=='COMPLETE' else 2
    if a.profile=='Practice':source=case/'synthetic-input';practice(source)
    if not source or not source.is_dir():raise ValueError('Select an existing acquired working folder')
    if a.profile!='Practice' and (source==case or source.is_relative_to(case) or case.is_relative_to(source) or source==root or source.is_relative_to(root)):raise ValueError('Input, case and toolkit must be separate trees')
    files=inventory(source);(raw/'input-inventory.json').write_text(json.dumps(files,indent=2),encoding='utf-8')
    env=os.environ.copy();env['DOTNET_ROOT']=str(root/'COC/tools/windows/DotNet');env['DOTNET_MULTILEVEL_LOOKUP']='0';env['PYTHONDONTWRITEBYTECODE']='1';env['APPDATA']=str(raw/'runtime-cache');pathlib.Path(env['APPDATA']).mkdir(exist_ok=True)
    steps=plan(root,files,a.profile,raw)
    if len(steps)>MAX_STEPS:raise ValueError('Analysis plan exceeds 100 steps; select a smaller acquired working set')
    if a.profile=='Practice':steps=plan(root,files,'ArtifactBatch',raw/'ArtifactBatch')+plan(root,files,'FileTriage',raw/'FileTriage')+plan(root,files,'SQLiteReview',raw/'SQLiteReview')
    (raw/'analysis-plan.json').write_text(json.dumps({'profile':a.profile,'steps':steps,'max_seconds':MAX_SECONDS,'shell':False,'live_collection':False},indent=2),encoding='utf-8')
    results=[];started=time.monotonic()
    if not steps and a.profile!='Inventory':results.append(dict(id='coverage',status='unsupported',reason='No eligible inputs for the selected profile'))
    for step in steps:
        out=pathlib.Path(step['output']);out.mkdir(parents=True,exist_ok=True)
        if time.monotonic()-started>MAX_SECONDS or sum(q.stat().st_size for q in raw.rglob('*') if q.is_file())>MAX_OUTPUT:result=dict(status='skipped',reason='profile-budget')
        else:
            try:
                if step.get('internal')=='sqlite':sqlite_review(pathlib.Path(step['source']),out);result=dict(status='collected',reason='working-copy-schema-review')
                elif step.get('internal')=='metadata':
                    (out/'file-metadata.json').write_text(json.dumps(dict(file=step['source'],scope='Filesystem metadata and file identification only; no EXIF/document-property extraction'),indent=2),encoding='utf-8');result=dict(status='collected',reason='basic-file-metadata-only')
                elif step.get('internal')=='unsupported':result=dict(status='unsupported',reason=step['reason'])
                else:result=run_process(step['cmd'],step['cwd'],out,env,min(120,max(1,int(MAX_SECONDS-(time.monotonic()-started)))))
            except Exception as e:result=dict(status='failed',reason=str(e))
        result['id']=step['id'];results.append(result);print(json.dumps(result),flush=True)
    correlation=merge_csvs(raw,raw/'correlation.csv')
    after=inventory(source)
    unchanged={i['relative']:(i['bytes'],i['sha256']) for i in files}=={i['relative']:(i['bytes'],i['sha256']) for i in after}
    summary=dict(profile=a.profile,inputs=len(files),results=results,source_hashes_unchanged=unchanged,correlation=correlation,status='COMPLETE' if unchanged and all(r['status']=='collected' for r in results) else 'PARTIAL')
    (raw/'analysis-result.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    return 0 if summary['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
