"""Fixed static parsers. Does not load input as Python or execute extracted content."""
import argparse,hashlib,importlib.util,json,pathlib,re,sys
def configure(root):
 sys.path.insert(0,str(root/'COC/apps/pyx'))
 def deny(event,args):
  if event.startswith('socket.') or event in {'subprocess.Popen','os.system','os.startfile'}:raise PermissionError('Network and execution disabled in static worker')
 sys.addaudithook(deny)
def config(data,out):
 import platformdirs
 # MWCP asks for a user configuration directory at import. Explicitly supply
 # this run's directory instead of consulting Windows profile locations.
 for name in ['user_config_dir','user_data_dir','user_cache_dir']:
  setattr(platformdirs,name,lambda *args,**kwargs:str(out/'runtime'))
 import malduck,mwcp
 class StaticConfig(mwcp.Parser):
  DESCRIPTION='COC bounded plaintext configuration indicators'
  @classmethod
  def identify(cls,file_object):return True
  def run(self):
   values=re.findall(rb'https?://[\x21-\x7e]{1,2048}',self.file_object.data)[:100]
   for url in sorted(set(values)):self.report.add(mwcp.metadata.URL(url.decode('ascii')))
   self.report.add(mwcp.metadata.Other('coc_scope','Plaintext URLs only; no family-specific decryption or emulation'))
 report=mwcp.run(StaticConfig,data=data,recursive=False,include_file_data=False,include_logs=False)
 if report.errors:raise ValueError('MWCP parser reported errors')
 result=dict(mwcp=json.loads(report.as_json()),malduck_sha256=malduck.sha256(data).hex())
 if data.startswith(b'MZ'):
  pe=malduck.pe(data);result['pe']=dict(machine=pe.file_header.Machine,sections=[s.Name.rstrip(b'\0').decode('ascii',errors='replace') for s in pe.sections[:96]],image_base=pe.optional_header.ImageBase)
 result['limitations']=['Plaintext configuration indicators and optional PE structure only. Family-specific extraction, decoding and emulation are not implemented. URLs remain untrusted text.']
 return result
def signatures(root,source):
 import yara
 rules=root/'COC/rules/YARA-Forge/packages/full/yara-rules-full.yar'
 compiled=yara.compile(filepath=str(rules));matches=compiled.match(str(source),timeout=60)
 if len(matches)>200:raise ValueError('More than 200 rule matches; bounded result unavailable')
 return dict(rules_sha256=hashlib.sha256(rules.read_bytes()).hexdigest(),matches=[dict(rule=m.rule,namespace=m.namespace,tags=m.tags,metadata=m.meta) for m in matches],limitations=['A signature match is a review lead, not proof of maliciousness. No match does not establish safety. Rule strings are not dumped.'])
def reference(root,query):
 if not query or len(query)>128:raise ValueError('Search phrase must contain 1-128 characters')
 q=query.casefold();results=[]
 attack=root/'COC/reference/ATTACK/enterprise-attack/enterprise-attack.json'
 for row in json.loads(attack.read_text(encoding='utf-8'))['objects']:
  if row.get('type')!='attack-pattern' or row.get('revoked') or row.get('x_mitre_deprecated'):continue
  if q in (row.get('name','')+' '+row.get('description','')+' '+json.dumps(row.get('external_references',[]))).casefold():
   results.append(dict(source='ATTACK',name=row.get('name'),description_excerpt=row.get('description','')[:4096],references=row.get('external_references',[])))
 for p in (root/'COC/reference/LOLBAS/yml').rglob('*.yml'):
  text=p.read_text(encoding='utf-8-sig')
  if q in text.casefold():results.append(dict(source='LOLBAS',record=p.relative_to(root).as_posix(),name=p.stem,text_excerpt=text[:4096]))
 return dict(query=query,total_matches=len(results),records=results[:100],truncated=len(results)>100,limitations=['Pinned offline reference data. Examples are inert text; no command is executed and no URL is visited. Known techniques and legitimate binaries are not proof of compromise.'])
def main():
 p=argparse.ArgumentParser();p.add_argument('--toolkit',required=True);p.add_argument('--profile',choices=['Config','YaraFull','Reference'],required=True);p.add_argument('--source');p.add_argument('--query',default='');p.add_argument('--output',required=True);a=p.parse_args()
 root=pathlib.Path(a.toolkit).resolve();out=pathlib.Path(a.output);configure(root)
 if a.profile=='Reference':result=reference(root,a.query)
 else:
  source=pathlib.Path(a.source)
  if source.stat().st_size>16*1024**2:raise ValueError('Static input exceeds 16 MiB')
  result=config(source.read_bytes(),out) if a.profile=='Config' else signatures(root,source)
 value=json.dumps(result,indent=2,ensure_ascii=False)
 if len(value.encode())>4*1024**2:raise ValueError('Result exceeds 4 MiB')
 (out/'result.json').write_text(value,encoding='utf-8');return 0
if __name__=='__main__':raise SystemExit(main())
