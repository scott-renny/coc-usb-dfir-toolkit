"""One explicitly selected PID, report-only. Never scans all processes or dumps memory."""
import argparse,pathlib,json,os,sys
from dfir_pipeline import one,run_process,reject_links
def command(root,tool,pid):
    if not 1<=pid<=4294967295:raise ValueError('Select a positive Windows PID')
    folder='PE-sieve' if tool=='PE-sieve' else 'HollowsHunter'
    pattern='pe-sieve64.exe' if tool=='PE-sieve' else 'hollows_hunter64.exe'
    exe=one(root/'COC/tools/windows'/folder,pattern)
    return [str(exe),'/pid',str(pid),'/ofilter','2','/json','/quiet']
def main():
    p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--case',required=True);p.add_argument('--pid',type=int,required=True);p.add_argument('--tool',choices=['PE-sieve','HollowsHunter'],required=True);a=p.parse_args()
    root=pathlib.Path(a.toolkit).resolve();case=pathlib.Path(a.case).resolve();reject_links(root);reject_links(case)
    if case==root or case.is_relative_to(root):raise ValueError('Output must be outside toolkit')
    cmd=command(root,a.tool,a.pid);raw=case/'raw';out=raw/'process-check'
    (raw/'process-plan.json').write_text(json.dumps(dict(command=cmd,pid=a.pid,dumps=False,live_collection=True,timeout_seconds=120),indent=2))
    try:result=run_process(cmd,str(out.parent),out,os.environ.copy(),timeout=120)
    except Exception as e:result=dict(status='failed',reason=str(e))
    result.update(tool=a.tool,pid=a.pid,verdict='analyst-review-required',dumps_requested=False)
    (raw/'process-result.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))
    return 0 if result['status']=='collected' else 2
if __name__=='__main__':raise SystemExit(main())
