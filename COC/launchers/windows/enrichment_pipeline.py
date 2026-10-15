"""Bounded enrichment of acquired working copies with fixed parser arguments."""
import argparse,importlib.util,json,os,pathlib,time

def load(name):
    spec=importlib.util.spec_from_file_location('coc_'+name,pathlib.Path(__file__).with_name(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
dfir=load('dfir_pipeline');field=load('field_operations')
PROFILES=['URLs','MSG','Decode','ExecutionReview','LateralReview','CloudAudit','RansomwareTriage','Coverage']

def main():
    p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--input',required=True);p.add_argument('--profile',choices=PROFILES,required=True);a=p.parse_args()
    root=pathlib.Path(a.toolkit).absolute();case=pathlib.Path(a.case).absolute();source=pathlib.Path(a.input).absolute()
    for path in [root,case,source]:dfir.reject_links(path)
    root=root.resolve();case=case.resolve();source=source.resolve();field.separate(source,case,root)
    raw=case/'raw';raw.mkdir(exist_ok=True)
    result=dict(status='PARTIAL',profile=a.profile)
    try:
        files=dfir.inventory(source);(raw/'input-inventory.json').write_text(json.dumps(files,indent=2))
        if a.profile=='Coverage':
            candidates={}
            for item in files:
                suffix=pathlib.Path(item['path']).suffix.lower()
                group='event logs' if item['kind']=='evtx' else 'memory candidate' if suffix in {'.mem','.raw','.lime','.dmp'} else 'mail candidate' if suffix in {'.eml','.msg','.pst','.ost'} else 'network capture candidate' if suffix in {'.pcap','.pcapng','.cap'} else 'SQLite candidate' if item['kind']=='sqlite' else 'structured exports' if suffix in {'.csv','.json','.jsonl'} else 'other'
                candidates.setdefault(group,[]).append(item['relative'])
            coverage=dict(candidate_groups=candidates,not_observed=[g for g in ['event logs','memory candidate','mail candidate','network capture candidate','SQLite candidate','structured exports'] if g not in candidates],limitations=['Presence is inferred from file signatures or names, not parser acceptance. Missing categories may be irrelevant to the incident.','This report inventories the supplied folder only; it does not establish that all incident evidence was acquired.'])
            (raw/'coverage.json').write_text(json.dumps(coverage,indent=2));unchanged=field.identities(files)==field.identities(dfir.inventory(source))
            result.update(status='COMPLETE' if unchanged else 'PARTIAL',source_hashes_unchanged=unchanged,inputs=len(files));(raw/'analysis-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result));return 0 if unchanged else 2
        extensions={'URLs':{'.txt','.urls'},'MSG':{'.msg'},'Decode':{'.txt','.b64','.hex'},'ExecutionReview':{'.csv','.json','.jsonl'},'LateralReview':{'.csv','.json','.jsonl'},'CloudAudit':{'.csv','.json','.jsonl'}}
        eligible=files if a.profile=='RansomwareTriage' else [f for f in files if pathlib.Path(f['path']).suffix.lower() in extensions[a.profile]]
        if not eligible or len(eligible)>20:raise ValueError('Select 1-20 eligible files; URL/decode text or MSG')
        steps=[];started=time.monotonic()
        for index,item in enumerate(eligible):
            cap={'URLs':128*1024,'Decode':1024**2,'MSG':16*1024**2,'RansomwareTriage':16*1024**2}.get(a.profile,2*1024**2)
            if item['bytes']>cap:raise ValueError('Input exceeds selected parser limit')
            if time.monotonic()-started>900:raise ValueError('Batch time limit reached')
            out=raw/f'item-{index:03d}'
            env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','PATH','TEMP','TMP','COMSPEC','PATHEXT'}}
            env['PYTHONIOENCODING']='utf-8';env['UNFURL_REMOTE_LOOKUPS']='false'
            cmd=[str(root/'COC/tools/windows/Python/python.exe'),'-B',str(pathlib.Path(__file__).with_name('enrichment_worker.py')),'--toolkit',str(root),'--profile',a.profile,'--source',item['path'],'--output',str(out)]
            step=dict(source=item['relative'],**dfir.run_process(cmd,str(raw),out,env,120));steps.append(step)
        unchanged=field.identities(files)==field.identities(dfir.inventory(source))
        result.update(status='COMPLETE' if unchanged and all(s['status']=='collected' for s in steps) else 'PARTIAL',source_hashes_unchanged=unchanged,parser_results=steps,excluded_files=[f['relative'] for f in files if f not in eligible])
    except Exception as e:result['error']=str(e)
    (raw/'analysis-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result));return 0 if result['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
