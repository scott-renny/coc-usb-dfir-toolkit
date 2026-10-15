"""Offline case workflows. No evidence execution, host collection or network access."""
import argparse, datetime, hashlib, html, json, os, pathlib, shutil, importlib.util
# The portable embedded Python runtime intentionally omits the script directory
# from sys.path. Load this packaged sibling explicitly, never an input-folder module.
_spec=importlib.util.spec_from_file_location('coc_packaged_dfir',pathlib.Path(__file__).with_name('dfir_pipeline.py'))
_dfir=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_dfir)
inventory,reject_links,digest,merge_csvs=_dfir.inventory,_dfir.reject_links,_dfir.digest,_dfir.merge_csvs

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')

def separate(source, destination, toolkit):
    for p in (source, destination, toolkit):reject_links(p)
    if not source.is_dir() or not destination.is_dir():raise ValueError('Existing source and case folders required')
    for a,b in ((source,destination),(source,toolkit),(destination,toolkit)):
        if a==b or a.is_relative_to(b) or b.is_relative_to(a):raise ValueError('Source, case and toolkit must be separate trees')

def identities(files):return {f['relative']:(f['bytes'],f['sha256']) for f in files}

def transfer(source, case, toolkit):
    separate(source,case,toolkit)
    before=inventory(source)
    if not before:raise ValueError('Empty source; no transfer performed')
    target=case/'raw'/'verified-copy'
    if target.exists():raise ValueError('Transfer destination already exists; refusing overwrite')
    total=sum(f['bytes'] for f in before)
    if shutil.disk_usage(case).free < total+1024**3:raise ValueError('Insufficient destination space plus 1 GiB reserve')
    target.mkdir(parents=True)
    # Exclusive creation protects against replacement of existing output files.
    for f in before:
        src=source/f['relative'];dest=target/f['relative'];reject_links(src);reject_links(dest)
        dest.parent.mkdir(parents=True,exist_ok=True)
        with src.open('rb') as inp,dest.open('xb') as out:
            remaining=f['bytes']
            while remaining:
                chunk=inp.read(min(1024*1024,remaining))
                if not chunk:raise ValueError('Source shortened during transfer')
                out.write(chunk);remaining-=len(chunk)
            if inp.read(1):raise ValueError('Source grew during transfer; partial output retained')
        if digest(dest)!=f['sha256']:raise ValueError('Transfer read-back mismatch: '+f['relative'])
    after=inventory(source);copied=inventory(target)
    if identities(before)!=identities(after) or identities(before)!=identities(copied):raise ValueError('Source changed or transfer mismatch; retain partial output')
    result=dict(status='COMPLETE',files=len(before),bytes=total,source=str(source),destination=str(target),source_hashes_unchanged=True,read_back_verified=True,limitations=['File-content copy; not a forensic disk image. NTFS streams, ACLs and original filesystem metadata are not preserved.','Host clock unverified. Custody identity and output encryption are operator attestations.'])
    write_json(case/'raw'/'transfer-inventory.json',before)
    return result

def verify_case(source):
    reject_links(source)
    manifest=source/'artifact-manifest.json';reject_links(manifest)
    if manifest.stat().st_size>16*1024**2:raise ValueError('Manifest too large')
    d=json.loads(manifest.read_text(encoding='utf-8-sig'));entries=d['files']
    if not entries or len(entries)>50000:raise ValueError('Invalid case manifest scope')
    seen=set();total=0
    for e in entries:
        rel=e['path'];p=source/rel
        if pathlib.PureWindowsPath(rel).drive or pathlib.PurePosixPath(rel).is_absolute() or '..' in pathlib.PurePosixPath(rel.replace('\\','/')).parts:raise ValueError('Unsafe artifact path')
        key=rel.replace('\\','/').casefold()
        if key in seen:raise ValueError('Duplicate artifact path')
        seen.add(key);reject_links(p)
        if not p.resolve().is_relative_to(source.resolve()) or not p.is_file():raise ValueError('Missing or unsafe artifact')
        total+=p.stat().st_size
        if total>16*1024**3:raise ValueError('Case closeout exceeds 16 GiB verification scope')
        if p.stat().st_size!=e['bytes'] or digest(p)!=e['sha256']:raise ValueError('Artifact mismatch: '+rel)
    actual=set()
    for base,dirs,names in os.walk(source,followlinks=False):
        for name in dirs:reject_links(pathlib.Path(base)/name)
        for name in names:
            p=pathlib.Path(base)/name;reject_links(p)
            if p!=manifest:actual.add(p.relative_to(source).as_posix().casefold())
    if actual!=seen:raise ValueError('Unmanifested or missing case files; preserve original and review')
    return dict(files=len(entries),manifest_sha256=digest(manifest),trust='Local integrity only; compare manifest digest with independently retained reference')

def closeout(source,case,toolkit,notes):
    separate(source,case,toolkit)
    verified=verify_case(source);run=json.loads((source/'run.json').read_text(encoding='utf-8-sig'))
    raw=case/'raw'
    write_json(raw/'review-record.json',dict(source_case=str(source),source_run=run,verification=verified,analyst_notes=notes,review='Analyst interpretation and custody review required'))
    # Merge only CSVs from the original raw outputs; retain file and row provenance.
    correlation=merge_csvs(source/'raw',raw/'combined-timeline.csv')
    body='<h1>COC Case Review</h1><p>Integrity verification passed against the local case manifest. This does not authenticate evidence provenance.</p><h2>Original run</h2><pre>'+html.escape(json.dumps(run,indent=2))+'</pre><h2>Analyst notes</h2><pre>'+html.escape(notes)+'</pre><p>combined-timeline.csv preserves source CSV and row references. Naive timestamps are not assigned a timezone.</p>'
    (raw/'case-review.html').write_text('<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;"><title>COC Case Review</title>'+body,encoding='utf-8')
    if verify_case(source)!=verified:raise ValueError('Original case changed during review')
    return dict(status='COMPLETE',original_status=run.get('status','unknown'),verification=verified,correlation=correlation,interpretation='Closeout verification completed; original collection failures are retained in review-record.json and are not cleared.')

def health(toolkit,case):
    manifest=toolkit/'COC/manifests/release.json';reject_links(manifest)
    data=json.loads(manifest.read_text(encoding='utf-8-sig'));results=[]
    for e in data['files']:
        rel=e['path'];p=toolkit/rel
        if pathlib.PureWindowsPath(rel).drive or '..' in pathlib.PurePosixPath(rel.replace('\\','/')).parts or not p.resolve().is_relative_to(toolkit.resolve()):raise ValueError('Unsafe toolkit manifest path')
        reject_links(p)
        status='missing' if not p.is_file() else 'matched' if digest(p)==e['sha256'] else 'mismatch'
        results.append(dict(path=rel,status=status))
    readiness=json.loads((toolkit/'COC/manifests/field-readiness.json').read_text(encoding='utf-8-sig'))
    write_json(case/'raw'/'toolkit-health.json',dict(release=data['release'],manifest_sha256=digest(manifest),files=results,readiness=readiness,executed_tools=False,trust='Unsigned local manifest; compare independently retained trusted digest'))
    rows=''.join('<tr><td>'+html.escape(r['name'])+'</td><td>'+html.escape(r['status'])+'</td><td>'+html.escape(r.get('note',''))+'</td></tr>' for r in readiness)
    (case/'raw'/'readiness.html').write_text('<!doctype html><meta charset="utf-8"><title>COC Readiness</title><h1>Tool readiness</h1><p>Integrity checks do not establish operational readiness.</p><table><tr><th>Tool</th><th>Status</th><th>Notes</th></tr>'+rows+'</table>',encoding='utf-8')
    return dict(status='COMPLETE' if all(r['status']=='matched' for r in results) else 'PARTIAL',files=len(results),mismatches=sum(r['status']!='matched' for r in results),readiness='See toolkit-health.json and readiness.html; pending and blocked tools remain explicit',executed_tools=False)

def main():
    p=argparse.ArgumentParser();p.add_argument('--profile',choices=['Transfer','Closeout','Health'],required=True);p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--input');p.add_argument('--notes',default='No analyst notes supplied');a=p.parse_args()
    # Reject unresolved junctions before canonicalizing paths.
    root=pathlib.Path(a.toolkit).absolute();case=pathlib.Path(a.case).absolute()
    for path in (root,case):reject_links(path)
    root=root.resolve();case=case.resolve()
    if case==root or case.is_relative_to(root) or root.is_relative_to(case):raise ValueError('Case must be outside toolkit')
    (case/'raw').mkdir(exist_ok=True)
    try:
        if a.profile=='Health':result=health(root,case)
        else:
            if not a.input:raise ValueError('Input required')
            source=pathlib.Path(a.input).absolute();reject_links(source);source=source.resolve()
            result=transfer(source,case,root) if a.profile=='Transfer' else closeout(source,case,root,a.notes)
    except Exception as e:
        write_json(case/'raw'/'analysis-result.json',dict(status='PARTIAL',error=str(e),profile=a.profile));raise
    write_json(case/'raw'/'analysis-result.json',result)
    print(json.dumps(result));return 0 if result['status']=='COMPLETE' else 2
if __name__=='__main__':raise SystemExit(main())
