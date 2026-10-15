import importlib.util,json,pathlib,struct,tempfile,unittest,zlib
W=pathlib.Path(__file__).resolve().parents[1]/'launchers/windows';s=importlib.util.spec_from_file_location('response',W/'response_pipeline.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def archive(name='hello.txt',payload=b'harmless fixture\n',packed=False,kind=b'x'):
 data=zlib.compress(payload) if packed else payload;nm=name.encode()+b'\0';toc=struct.pack('!IIIIBc',18+len(nm),0,len(data),len(payload),int(packed),kind)+nm
 return b'MZ-synthetic-nonexecuting'+data+toc+struct.pack('!8sIIII',b'MEI\014\013\012\013\016',len(data)+len(toc)+24,len(data),len(toc),312)
class Response(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def extract(self,data):
  src=self.base/'fixture.bin';src.write_bytes(data);return m.extract_carchive(src,self.base/'members')
 def test_extract(self):
  self.assertEqual(self.extract(archive()),1);self.assertEqual((self.base/'members/0000.bin').read_bytes(),b'harmless fixture\n')
 def test_compressed(self):self.assertEqual(self.extract(archive(packed=True)),1)
 def test_nested_pyz_preserved(self):
  self.extract(archive(payload=b'PYZ\0opaque',kind=b'z'));self.assertFalse(json.loads((self.base/'members/members.json').read_text())[0]['nested_PYZ_decoded'])
 def test_traversal(self):
  with self.assertRaises(ValueError):self.extract(archive('../escape'))
 def test_absolute(self):
  with self.assertRaises(ValueError):self.extract(archive('/escape'))
 def test_ads(self):
  with self.assertRaises(ValueError):self.extract(archive('x:stream'))
 def test_windows_reserved(self):
  with self.assertRaises(ValueError):self.extract(archive('CON.txt'))
 def test_symlink_kind(self):
  with self.assertRaises(ValueError):self.extract(archive(kind=b'n'))
 def test_missing_cookie(self):
  with self.assertRaises(ValueError):self.extract(b'harmless no archive')
 def test_corrupt_bounds(self):
  data=bytearray(archive());data[-16:-12]=struct.pack('!I',0xffffffff)
  with self.assertRaises(ValueError):self.extract(data)
 def test_utc(self):self.assertEqual(m.utc('2026-10-14T12:00:00-04:00'),'2026-10-14T16:00:00+00:00')
 def test_naive_time(self):self.assertIsNone(m.utc('2026-10-14 12:00:00'))
 def test_invalid_time(self):self.assertIsNone(m.utc('unknown'))
 def logs(self,text):
  p=self.base/'access.log';p.write_text(text);out=self.base/'out';out.mkdir();return m.server_logs([dict(path=str(p),relative=p.name,sha256=m.dfir.digest(p),bytes=p.stat().st_size)],out)
 def test_iis(self):
  self.assertEqual(self.logs('#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-14 12:01:02 192.0.2.1 GET /example 200\n'),1)
 def test_combined(self):
  self.assertEqual(self.logs('192.0.2.1 - - [14/Oct/2026:12:01:02 -0400] "GET /example HTTP/1.1" 200 12 "-" "COC practice"\n'),1)
 def test_unsupported_log(self):
  with self.assertRaises(ValueError):self.logs('not an access log\n')
 def test_partial_log(self):
  with self.assertRaises(ValueError):self.logs('#Fields: date time c-ip cs-method cs-uri-stem sc-status\n2026-10-14 12:01:02 192.0.2.1 GET /example 200\nmalformed\n')
 def test_queries_readonly_fixed(self):
  self.assertEqual(len(m.QUERIES),8)
  for q in m.QUERIES.values():self.assertTrue(q.startswith('SELECT '));self.assertIn('LIMIT ',q);self.assertEqual(q.count(';'),1)
 def test_live_requires_consent(self):self.assertIn("if not a.live_authorized",pathlib.Path(m.__file__).read_text())
 def test_lab_network_disabled(self):
  lab=W.parents[1]/'lab/Offline-Analysis/coc-lab-analyze.py';spec=importlib.util.spec_from_file_location('lab',lab);l=importlib.util.module_from_spec(spec);spec.loader.exec_module(l)
  # Planning only; never launches a container or accesses the host.
  old=getattr(l.os,'getuid',None);oldg=getattr(l.os,'getgid',None);l.os.getuid=lambda:1000;l.os.getgid=lambda:1000
  try:
   cmd=l.command('podman','sha256:fixed','zeek',self.base/'in.pcap',self.base/'out');self.assertIn('--network=none',cmd);self.assertIn('--cap-drop=ALL',cmd);self.assertIn('--read-only',cmd);self.assertNotIn('--privileged',cmd);self.assertIn('-r',cmd)
  finally:
   if old is not None:l.os.getuid=old
   else:del l.os.getuid
   if oldg is not None:l.os.getgid=oldg
   else:del l.os.getgid
if __name__=='__main__':unittest.main()
