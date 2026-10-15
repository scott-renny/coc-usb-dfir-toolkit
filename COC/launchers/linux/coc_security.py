#!/usr/bin/env python3
"""COC field collection. Standard-library runtime; fixed commands, no shell execution."""
import argparse
import datetime as dt
import hashlib
import html
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
MAX_OUTPUT = 16 * 1024 * 1024

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding='utf-8')

def safe_path(root, relative):
    root = Path(root).resolve()
    rel = Path(relative)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('Unsafe manifest path')
    candidate = root / rel
    for part in [candidate, *candidate.parents]:
        if part == root.parent:
            break
        if part.is_symlink():
            raise ValueError('Symlink paths are not allowed')
    candidate.resolve().relative_to(root)
    return candidate

def verify_manifest(root, manifest_path, images=False):
    manifest = json.loads(Path(manifest_path).read_text(encoding='utf-8-sig'))
    count = 0
    for item in manifest['files']:
        if not images and item['path'].startswith('ISO/'):
            continue
        path = safe_path(root, item['path'])
        if sha256(path) != item['sha256']:
            raise ValueError('Integrity mismatch: ' + item['path'])
        count += 1
    return {'files': count, 'status': 'matched-local-manifest', 'trust': 'Unsigned reference: compare manifest digest on trusted workstation.'}

def validate_targets(raw_targets, raw_allowed, excluded=()):
    allowed = [ipaddress.ip_network(v, strict=True) for v in raw_allowed]
    excludes = [ipaddress.ip_network(v, strict=False) for v in excluded]
    if not allowed or any(net.num_addresses > 256 for net in allowed):
        raise ValueError('Each approved CIDR must contain at most 256 addresses')
    targets = []
    for raw in raw_targets:
        address = ipaddress.ip_address(raw)
        if address.is_multicast or address.is_unspecified or address.is_loopback or address.is_link_local:
            raise ValueError('Multicast, unspecified, loopback and link-local targets are excluded')
        if not any(address.version == net.version and address in net for net in allowed):
            raise ValueError('Target is outside approved scope: ' + raw)
        if any(address.version == net.version and address in net for net in excludes):
            raise ValueError('Target is excluded: ' + raw)
        value = str(address)
        if value not in targets:
            targets.append(value)
    if not targets or len(targets) > 10:
        raise ValueError('Select 1-10 explicit IP addresses; hostnames and subnet sweeps are not enabled')
    if len({ipaddress.ip_address(v).version for v in targets}) > 1:
        raise ValueError('Use separate runs for IPv4 and IPv6')
    return targets

def validate_ports(raw):
    values = [int(value) for value in raw.split(',')]
    if not values or len(values) > 20 or any(not 1 <= value <= 65535 for value in values):
        raise ValueError('Specify 1-20 TCP ports in the range 1-65535')
    return ','.join(str(v) for v in sorted(set(values)))

class Run:
    def __init__(self, output, case_id, authority, profile, protected=False, synthetic=False):
        import re
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', case_id):
            raise ValueError('Invalid case ID')
        if not authority.strip():
            raise ValueError('Authorization reference is required')
        if not protected and not synthetic:
            raise ValueError('Protected output acknowledgment required; no plaintext fallback')
        original = Path(output).absolute()
        for part in [original, *original.parents]:
            if part.is_symlink():
                raise ValueError('Symlink output paths are not allowed')
        output = original.resolve(strict=True)
        if not output.is_dir() or output == ROOT or ROOT in output.parents:
            raise ValueError('Use an existing output directory outside executable toolkit')
        if shutil.disk_usage(output).free < 1024**3:
            raise ValueError('Output needs at least 1 GiB free')
        import fcntl
        self.lock = (output / '.coc-session.lock').open('a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            self.lock.close()
            raise RuntimeError('Another collection holds the output lock')
        try:
            self.path = output / (case_id + '-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
            self.path.mkdir(exist_ok=False)
            (self.path / 'raw').mkdir()
            self.start = time.monotonic()
            self.metadata = dict(schema_version=1, case_id=case_id, authority_reference=authority, profile=profile, status='RUNNING', started_utc=utc(), clock_confidence='Host clock unverified', output_protection='Operator attestation; not automatically verified', modules=[], synthetic=synthetic,
                                 limitations=['Live collection changes system state.', 'Negative findings do not prove absence of compromise.', 'This workflow does not acquire RAM or automatically image disks.'])
            self.save()
            (self.path/'errors.log').write_text('',encoding='utf-8')
            self.log_event('run.started','INFO','Started '+profile+'; host clock unverified.')
        except Exception:
            self.lock.close()
            raise

    def save(self):
        write_json(self.path / 'run.json', self.metadata)

    def log_event(self,event,level,message,detail=None):
        record=dict(time_utc=utc(),elapsed_seconds=round(time.monotonic()-self.start,3),event=event,level=level,message=message,detail=detail)
        with (self.path/'events.jsonl').open('a',encoding='utf-8') as events:events.write(json.dumps(record)+'\n')
        clean=message.replace('\n',' ').replace('\r',' ').replace('\t',' ')
        line=record['time_utc']+' ['+level+'] '+event+': '+clean+'\n'
        with (self.path/'activity.log').open('a',encoding='utf-8') as log:log.write(line)
        if level=='ERROR':
            with (self.path/'errors.log').open('a',encoding='utf-8') as errors:errors.write(line)

    def record(self, name, status, detail, artifact, started, elapsed, arguments=None):
        record = dict(name=name, status=status, detail=detail, artifact=artifact, started_utc=started, ended_utc=utc(), elapsed_seconds=round(elapsed, 3), arguments=arguments or [])
        self.metadata['modules'].append(record)
        self.save()
        level='ERROR' if status in ['failed','timed_out'] else 'WARNING' if status!='collected' else 'INFO'
        self.log_event('module.finished',level,name+': '+status+'; '+detail,record)
        print(name + ': ' + status)

    def command(self, name, args, timeout=120, cap=MAX_OUTPUT):
        started, timer = utc(), time.monotonic()
        artifact = 'raw/' + name + '.txt'
        path = self.path / artifact
        status, detail, process = 'collected', '', None
        self.log_event('module.started','INFO',name)
        try:
            remaining=900-(time.monotonic()-self.start)
            if remaining<=0:
                status,detail='skipped','Profile exceeded its 15 minute budget'
                raise TimeoutError(detail)
            timeout=min(timeout,remaining)
            executable = shutil.which(args[0])
            if not executable:
                raise FileNotFoundError('Tool unavailable: ' + args[0])
            with path.open('wb') as out:
                process = subprocess.Popen([executable, *args[1:]], stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
                while process.poll() is None:
                    if time.monotonic() - timer > timeout:
                        status, detail = 'timed_out', 'Time limit reached'
                        break
                    if path.stat().st_size > cap:
                        status, detail = 'failed', 'Output cap reached; retained partial raw output'
                        break
                    time.sleep(0.1)
                if process.poll() is None:
                    import signal
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                elif process.returncode != 0:
                    status, detail = 'failed', 'Exit code ' + str(process.returncode)
                if path.stat().st_size > cap:
                    status, detail = 'failed', 'Output cap exceeded; retained partial output'
        except FileNotFoundError as error:
            status, detail = 'unsupported', str(error)
        except PermissionError as error:
            status, detail = 'access_denied', str(error)
        except TimeoutError as error:
            detail=str(error)
        except Exception as error:
            status, detail = 'failed', str(error)
        finally:
            if process is not None and process.poll() is None:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if not path.exists():
            path.write_text(detail, encoding='utf-8')
        self.record(name, status, detail, artifact, started, time.monotonic() - timer, args)

    def finalize(self, forced=None):
        try:
            self.log_event('run.finalizing','INFO','Generating reports and integrity manifest.')
            self.metadata['status'] = forced or ('PARTIAL' if any(m['status'] != 'collected' for m in self.metadata['modules']) else 'COMPLETE')
            self.metadata.update(ended_utc=utc(), elapsed_seconds=round(time.monotonic()-self.start, 3))
            self.save()
            states=['collected','skipped','access_denied','unsupported','timed_out','cancelled','failed']
            write_json(self.path/'summary.json',dict(schema_version=1,case_id=self.metadata['case_id'],profile=self.metadata.get('profile','test'),status=self.metadata['status'],counts={state:sum(m['status']==state for m in self.metadata['modules']) for state in states},review_required=[m['name'] for m in self.metadata['modules'] if m['status']!='collected'],interpretation='Collection status, not a security verdict.'))
            (self.path/'READ-ME-FIRST.txt').write_text('Open report.html for the readable report. Review raw/ for observations.\nactivity.log is the human-readable timeline; events.jsonl contains structured events.\nerrors.log records failures/timeouts. summary.json and coverage.csv record outcomes.\nVerify artifact-manifest.json on a trusted workstation before transfer or analysis.\nPreserve its digest independently. COMPLETE is not a security verdict.\nAn unfinished run or missing manifest indicates interrupted collection.\n',encoding='utf-8')
            rows = ''.join('<tr>' + ''.join('<td>' + html.escape(str(m[k])) + '</td>' for k in ['name', 'status', 'detail', 'artifact']) + '</tr>' for m in self.metadata['modules'])
            observations=[]
            for module in self.metadata['modules']:
                path=self.path/module['artifact']
                if path.is_file():
                    with path.open('r',encoding='utf-8',errors='replace') as raw:
                        preview=raw.read(24001)
                    if len(preview)>24000:preview=preview[:24000]+'\n[Report preview truncated; complete raw artifact retained.]'
                    observations.append('<details><summary>'+html.escape(module['name'])+'</summary><pre style="white-space:pre-wrap">'+html.escape(preview)+'</pre></details>')
            report = '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;"><title>COC Security Report</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px}td,th{padding:10px;border:1px solid #aaa}table{border-collapse:collapse}</style><h1>COC Security Report</h1><p>Case: '+html.escape(self.metadata['case_id'])+'</p><p>Authority: '+html.escape(self.metadata['authority_reference'])+'</p><p>Status: '+self.metadata['status']+'</p><p>Coverage report. Review raw artifacts before drawing conclusions. Clock and output protection are operator supplied, not independently verified.</p><table><tr><th>Module</th><th>Status</th><th>Notes</th><th>Evidence</th></tr>'+rows+'</table><ul>'+''.join('<li>'+html.escape(v)+'</li>' for v in self.metadata['limitations'])+'</ul></html>'
            report=report.replace('</html>','<h2>Collected observations</h2>'+''.join(observations)+'</html>')
            (self.path/'report.html').write_text(report, encoding='utf-8')
            (self.path/'report.md').write_text('# COC Security Collection Report\n\nCase: '+self.metadata['case_id']+'\n\nStatus: '+self.metadata['status']+'\n\n'+ '\n'.join('- '+m['name']+': '+m['status']+'; '+m['artifact'] for m in self.metadata['modules'])+'\n\n'+'\n'.join(self.metadata['limitations']), encoding='utf-8')
            import csv
            with (self.path/'coverage.csv').open('w', newline='', encoding='utf-8') as output:
                writer=csv.DictWriter(output, fieldnames=['name','status','detail','artifact'], extrasaction='ignore')
                writer.writeheader();writer.writerows(self.metadata['modules'])
            self.log_event('run.finished','INFO','Collection '+self.metadata['status']+'; report generation complete.')
            files = [dict(path=p.relative_to(self.path).as_posix(), bytes=p.stat().st_size, sha256=sha256(p)) for p in sorted(self.path.rglob('*')) if p.is_file()]
            temp = self.path/'artifact-manifest.json.tmp'
            write_json(temp,dict(schema_version=1,files=files,trust='Unsigned; verify and sign on trusted receiving workstation'))
            temp.rename(self.path/'artifact-manifest.json')
            return self.path
        finally:
            self.lock.close()

def main():
    import sys
    if len(sys.argv) == 1:
        menu = {'1':'verify','2':'host','3':'network','4':'capture','5':'yara','6':'acquisition-preflight','7':'verify-case','8':'playbook'}
        print('COC USB #2 — Security Field Operations\n1 Verify release and images\n2 Local host inventory\n3 Scoped TCP exposure check\n4 Bounded packet capture\n5 Selected file synthetic YARA check\n6 Acquisition preparation inventory\n7 Verify a case\n8 Automated local-host playbook\n0 Exit')
        choice=input('Select: ').strip()
        if choice=='0':return
        if choice not in menu:raise ValueError('Invalid choice')
        profile=menu[choice];extra=[profile]
        if profile=='verify':extra+=['--images']
        elif profile=='verify-case':extra+=['--run',input('Case run directory: ').strip()]
        else:
            extra+=['--case',input('Case ID: ').strip(),'--authority',input('Owner authorization reference: ').strip(),'--output',input('Existing protected output directory: ').strip()]
            if profile in ['network','capture']:
                extra+=['--interface',input('Approved interface name: ').strip(),'--allow',*input('Approved CIDRs, separated by spaces: ').split()]
                if profile=='network':extra+=['--targets',*input('Selected IPs (max 10), separated by spaces: ').split(),'--ports',input('TCP ports (comma separated): ').strip()]
                else:extra+=['--capture-host',input('Approved capture host IP: ').strip()]
            if profile=='yara':extra+=['--file',input('Selected file path: ').strip()]
            print('Selected profile:',profile,'\nHost effects and privacy limits apply. Do not unlock a shared vault on a suspect host.')
            if input('Confirm authority, scope and protected output: type RUN: ')!='RUN':return
            extra+=['--authorized','--protected-output']
        sys.argv+=extra
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('profile',choices=['verify','host','network','capture','yara','acquisition-preflight','verify-case','playbook'])
    parser.add_argument('--images',action='store_true')
    parser.add_argument('--output');parser.add_argument('--case');parser.add_argument('--authority')
    parser.add_argument('--authorized',action='store_true');parser.add_argument('--protected-output',action='store_true')
    parser.add_argument('--targets',nargs='+');parser.add_argument('--allow',nargs='+');parser.add_argument('--exclude',nargs='*',default=[])
    parser.add_argument('--ports',default='22,80,443,445,3389')
    parser.add_argument('--interface');parser.add_argument('--capture-host');parser.add_argument('--file');parser.add_argument('--run')
    args = parser.parse_args()
    if args.profile == 'verify-case':
        print(verify_manifest(args.run,Path(args.run)/'artifact-manifest.json',True));return
    print(verify_manifest(ROOT,ROOT/'COC/manifests/release.json',args.images))
    if args.profile == 'verify':return
    if not args.authorized or not all([args.output,args.case,args.authority]):
        parser.error('Explicit authority, case, output and --authorized are required')
    targets,ports,capture_filter = None,None,None
    if args.profile=='network':
        targets=validate_targets(args.targets or [],args.allow or [],args.exclude)
        ports=validate_ports(args.ports)
        if not args.interface or args.interface not in os.listdir('/sys/class/net'):
            parser.error('Select an existing network interface explicitly')
    if args.profile=='capture':
        targets=validate_targets([args.capture_host] if args.capture_host else [],args.allow or [],args.exclude)
        if not args.interface or args.interface not in os.listdir('/sys/class/net'):
            parser.error('Select an existing interface explicitly')
        capture_filter='host '+targets[0]
    selected=None
    if args.profile=='yara':
        selected=Path(args.file or '')
        if selected.is_symlink() or not selected.is_file() or selected.stat().st_size>1024**3:
            parser.error('Select one ordinary file of at most 1 GiB')
        selected=selected.resolve()
    run = Run(args.output,args.case,args.authority,args.profile,args.protected_output)
    run.metadata['toolkit_manifest_sha256']=sha256(ROOT/'COC/manifests/release.json')
    run.metadata['collector_runtime']=sys.version
    forced=None
    try:
        if args.profile in ['host','playbook']:
            plan=[('os',['uname','-a']),('addresses',['ip','-json','address']),('routes',['ip','-json','route']),('listeners',['ss','-lntup']),('processes',['ps','-eo','pid,ppid,user,comm'])]
            if args.profile=='playbook':
                plan += [('block-devices',['lsblk','--json','-b','-o','NAME,PATH,SIZE,MODEL,SERIAL,RO,TYPE,MOUNTPOINTS']),('mounts',['findmnt','--json']),('swap',['swapon','--show','--json'])]
                write_json(run.path/'playbook-plan.json',dict(schema_version=1,version='1.0',scope='Local host only; no active remote probes',modules=[name for name,_ in plan],profile_budget_seconds=900,automatic_repairs=False,automatic_uploads=False,memory_capture=False,disk_imaging=False))
                run.metadata['limitations'].append('Block-device inventory does not establish write blocking or constitute forensic acquisition.')
            for index,(name,command) in enumerate(plan,1):
                print('Step '+str(index)+'/'+str(len(plan))+': '+name)
                run.command(name,command)
        elif args.profile=='network':
            run.command('nmap-version',['nmap','--version'])
            write_json(run.path/'scope.json',dict(targets=targets,allow=args.allow,exclude=args.exclude,ports=ports,interface=args.interface,probe_rate=10,service_probes=False))
            for index,target in enumerate(targets):
                xml=run.path/'raw'/('nmap-'+str(index)+'.xml')
                command=['nmap','-n','-Pn','-sT','-p',ports,'--max-rate','10','--max-retries','1','--host-timeout','120s','-e',args.interface,'-oX',str(xml)]
                if ipaddress.ip_address(target).version==6:command.append('-6')
                run.command('nmap-'+str(index),command+[target],timeout=150)
                text=(run.path/'raw'/('nmap-'+str(index)+'.txt')).read_text(encoding='utf-8',errors='replace')
                if 'host timeout' in text.lower() or 'skipping host' in text.lower():
                    run.metadata['modules'][-1]['status']='timed_out'
                    run.metadata['modules'][-1]['detail']='Nmap reported incomplete host coverage'
                    run.save()
        elif args.profile=='capture':
            run.command('dumpcap-version',['dumpcap','--version'])
            write_json(run.path/'scope.json',dict(interface=args.interface,filter=capture_filter,duration_seconds=300,size_kib=256000,snaplen=256,visibility='Selected interface only; not full switched-network visibility'))
            run.command('capture',['dumpcap','-i',args.interface,'-p','-n','-f',capture_filter,'-s','256','-a','duration:300','-a','filesize:256000','-w',str(run.path/'raw/capture.pcapng')],timeout=320)
        elif args.profile=='yara':
            run.command('yara-version',['yara','--version'])
            rules=ROOT/'COC/rules/yara/coc-demo.yar'
            write_json(run.path/'selected-file.json',dict(name=selected.name,bytes=selected.stat().st_size,sha256=sha256(selected),rule_scope='Synthetic demonstration rule only; no malware detection coverage claimed'))
            run.command('yara',['yara','-a','30',str(rules),str(selected)],timeout=40)
        elif args.profile=='acquisition-preflight':
            run.metadata['limitations'].append('Inventory only. Protection has not been established. Imaging requires a validated blocker, separate destination and the acquisition runbook.')
            for name,command in [('block-devices',['lsblk','--json','-b','-o','NAME,PATH,SIZE,MODEL,SERIAL,RO,TYPE,MOUNTPOINTS']),('mounts',['findmnt','--json']),('swap',['swapon','--show','--json'])]:
                run.command(name,command)
            run.metadata['modules'].append(dict(name='acquisition',status='skipped',detail='Manual supervised acquisition only after hardware validation',artifact='COC/docs/ACQUISITION.md'))
    except KeyboardInterrupt:
        forced='CANCELLED'
    except Exception:
        forced='FAILED'
        raise
    finally:
        case_path=run.finalize(forced)
        print(verify_manifest(case_path,case_path/'artifact-manifest.json',True))
        print('Case saved:',case_path)

if __name__=='__main__':
    main()
