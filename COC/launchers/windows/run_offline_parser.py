"""Fixed offline parser plans; no shell, live collection or arbitrary arguments."""
import argparse,json,os,pathlib,subprocess,time
TOOLS={'MFTECmd','EvtxECmd','AmcacheParser','PECmd','LECmd','JLECmd','RBCmd','AppCompatCacheParser'}
def main():
    p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--tool',choices=sorted(TOOLS),required=True);p.add_argument('--input',required=True);p.add_argument('--case',required=True);a=p.parse_args()
    root=pathlib.Path(a.toolkit).resolve();case=pathlib.Path(a.case).resolve();source=pathlib.Path(a.input).resolve()
    if case==root or case.is_relative_to(root) or not source.is_file() or source.stat().st_size>4*1024**3:raise ValueError('Invalid source or case location')
    executables=list((root/'COC/tools/windows/Zimmerman'/a.tool).rglob(a.tool+'.exe'))
    if len(executables)!=1:raise ValueError('Ambiguous parser executable')
    raw=case/'raw';raw.mkdir(exist_ok=True);analysis=raw/'analysis';analysis.mkdir(exist_ok=True)
    args=[str(executables[0]),'-f',str(source),'--csv',str(analysis)]
    env=os.environ.copy();env['DOTNET_ROOT']=str(root/'COC/tools/windows/DotNet');env['DOTNET_MULTILEVEL_LOOKUP']='0'
    # Arguments are a list and shell execution remains disabled.
    (raw/'parser-plan.json').write_text(json.dumps({'tool':a.tool,'arguments':args[1:],'timeout_seconds':300,'shell':False},indent=2),encoding='utf-8')
    with (raw/'parser-stdout.log').open('wb') as out,(raw/'parser-stderr.log').open('wb') as err:
        proc=subprocess.Popen(args,env=env,stdout=out,stderr=err,shell=False,cwd=str(executables[0].parent))
        start=time.monotonic();reason='completed'
        while proc.poll() is None:
            if time.monotonic()-start>300 or sum(f.stat().st_size for f in raw.rglob('*') if f.is_file())>256*1024**2:
                reason='timeout-or-output-budget';proc.kill();proc.wait();break
            time.sleep(0.25)
    code=proc.returncode if reason=='completed' else 124
    (raw/'parser-result.json').write_text(json.dumps({'tool':a.tool,'exit_code':code,'reason':reason,'elapsed_seconds':round(time.monotonic()-start,3)},indent=2),encoding='utf-8')
    return code
if __name__=='__main__':raise SystemExit(main())
