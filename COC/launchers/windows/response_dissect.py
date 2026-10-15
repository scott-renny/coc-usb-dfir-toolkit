"""Fixed acquired-container query. No live target URI or arbitrary plugins."""
import argparse,pathlib,sys,json,logging,os,types
logging.basicConfig(level=logging.WARNING)
os.environ['USERPROFILE']=str(pathlib.Path.cwd())
p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--input',required=True);a=p.parse_args();root=pathlib.Path(a.toolkit)
sys.path.insert(0,str(root/'COC/tools/windows/InvestigationPackages'))
sys.path.append(str(root/'COC/apps/pyx'))
from dissect.target import Target
from dissect.target.helpers import config
# Fixed queries do not accept case-adjacent or host configuration overrides.
config.load=lambda paths:types.ModuleType('config')
count=0
for target in Target.open_all([pathlib.Path(a.input)]):
 for record in target.users():
  if count>=5000:raise ValueError('5000 user-record cap exceeded')
  print(json.dumps(record._asdict(),default=str));count+=1
if not count:raise ValueError('No user records; compatible container OS coverage not established')
