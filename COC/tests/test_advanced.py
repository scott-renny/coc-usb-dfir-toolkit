import importlib.util,json,pathlib,shutil,subprocess,tempfile,unittest,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[2];LAUNCH=ROOT/'COC/launchers/windows';FIX=ROOT/'COC/practice/advanced';PY=ROOT/'COC/tools/windows/Python/python.exe'
s=importlib.util.spec_from_file_location('advanced',LAUNCH/'advanced_pipeline.py');advanced=importlib.util.module_from_spec(s);s.loader.exec_module(advanced)
class AdvancedTests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.tmp.name);self.source=self.base/'input';self.source.mkdir();self.case=self.base/'case';self.case.mkdir()
 def tearDown(self):self.tmp.cleanup()
 def run_profile(self,profile,names=(),query=None):
  for name in names:shutil.copyfile(FIX/name,self.source/name)
  before=advanced.dfir.inventory(self.source)
  args=[str(PY),'-B',str(LAUNCH/'advanced_pipeline.py'),'--toolkit',str(ROOT),'--case',str(self.case),'--profile',profile]
  if query:args+=['--query',query]
  else:args+=['--input',str(self.source)]
  r=subprocess.run(args,capture_output=True,timeout=180);self.assertEqual(advanced.field.identities(before),advanced.field.identities(advanced.dfir.inventory(self.source)));return r
 def test_apk_binary_manifest(self):
  r=self.run_profile('APK',['compiled-synthetic.apk']);self.assertEqual(r.returncode,0,r.stdout.decode()+r.stderr.decode(errors='replace'));data=json.loads((self.case/'raw/apk-summary.json').read_text());self.assertEqual(data[0]['package'],'invalid.example.coc');self.assertIn('android.permission.INTERNET',data[0]['permissions'])
 def test_apk_traversal_refused(self):
  p=self.source/'bad.apk'
  with zipfile.ZipFile(p,'w') as z:z.writestr('AndroidManifest.xml','x');z.writestr('../outside','x')
  self.assertRaises(ValueError,advanced.apk_check,p)
 def test_apk_duplicate_refused(self):
  import warnings
  p=self.source/'bad.apk'
  with warnings.catch_warnings():
   warnings.simplefilter('ignore')
   with zipfile.ZipFile(p,'w') as z:z.writestr('AndroidManifest.xml','x');z.writestr('AndroidManifest.xml','x')
  self.assertRaises(ValueError,advanced.apk_check,p)
 def test_apk_compression_bomb_refused(self):
  p=self.source/'bad.apk'
  with zipfile.ZipFile(p,'w',compression=zipfile.ZIP_DEFLATED) as z:z.writestr('AndroidManifest.xml','x');z.writestr('assets/bomb',bytes(2*1024**2))
  self.assertRaises(ValueError,advanced.apk_check,p)
 def test_apk_without_manifest_refused(self):
  p=self.source/'bad.apk'
  with zipfile.ZipFile(p,'w') as z:z.writestr('other','x')
  self.assertRaises(ValueError,advanced.apk_check,p)
 def test_config_fixed_parser(self):
  r=self.run_profile('Config',['config.txt']);self.assertEqual(r.returncode,0,r.stdout.decode()+r.stderr.decode(errors='replace'));self.assertIn('example.invalid',json.dumps(json.loads((self.case/'raw/item-0/result.json').read_text())))
 def test_full_rules_compile_scan(self):
  r=self.run_profile('YaraFull',['config.txt']);self.assertEqual(r.returncode,0,r.stdout.decode()+r.stderr.decode(errors='replace'));self.assertIn('rules_sha256',json.loads((self.case/'raw/item-0/result.json').read_text()))
 def test_similarity_identical_and_changed(self):
  r=self.run_profile('Similarity',['similarity-a.bin','similarity-b.bin','similarity-c.bin']);self.assertEqual(r.returncode,0,r.stdout.decode());lines=(self.case/'raw/similarity/stdout.log').read_text().splitlines();self.assertIn('DIFF\t0\t1\t0',lines);self.assertTrue(any(l.startswith('DIFF\t0\t2\t') and not l.endswith('\t0') for l in lines))
 def test_reference_search(self):
  r=self.run_profile('Reference',query='certutil');self.assertEqual(r.returncode,0,r.stdout.decode());data=json.loads((self.case/'raw/reference/result.json').read_text());self.assertTrue(any(v['source']=='LOLBAS' for v in data['records']))
 def test_incomplete_apple_archive_refused(self):
  (self.source/'fake.tracev3').write_bytes(b'bad');r=self.run_profile('AppleLogs');self.assertNotEqual(r.returncode,0);self.assertIn('companions',r.stdout.decode())
 def test_carve_non_image_refused(self):
  r=self.run_profile('Carve',['config.txt']);self.assertNotEqual(r.returncode,0);self.assertIn('RAW image',r.stdout.decode())
 def test_overlap_refused(self):
  r=subprocess.run([str(PY),'-B',str(LAUNCH/'advanced_pipeline.py'),'--toolkit',str(ROOT),'--case',str(self.source/'case'),'--input',str(self.source),'--profile','Config'],capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0)
 def test_jadx_decompiles_known_class(self):
  out=self.base/'jadx';env=advanced.environment(self.base);r=advanced.dfir.run_process([str(advanced.java(ROOT)),'-Xmx512m','-cp',str(advanced.dfir.one(ROOT/'COC/apps/jadx','*.jar')),'jadx.cli.JadxCLI','-j','2','-d',str(self.base/'code'),str(FIX/'synthetic.jar')],str(self.base),out,env,120);self.assertEqual(r['status'],'collected');self.assertTrue(any('COC_SYNTHETIC' in p.read_text() for p in (self.base/'code').rglob('*.java')))
if __name__=='__main__':unittest.main()
