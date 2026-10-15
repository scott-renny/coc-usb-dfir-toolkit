import hashlib,importlib.util,json,pathlib,subprocess,tempfile,unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]
PYTHON=ROOT/'COC/tools/windows/Python/python.exe'
WORKER=ROOT/'COC/launchers/windows/enrichment_worker.py'
PIPELINE=WORKER.with_name('enrichment_pipeline.py')
spec=importlib.util.spec_from_file_location('case_review',WORKER.with_name('case_review.py'));review=importlib.util.module_from_spec(spec);spec.loader.exec_module(review)

class EnrichmentTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def worker(self,profile,name,data):
        source=self.base/name;source.write_bytes(data);out=self.base/'out';out.mkdir()
        before=hashlib.sha256(data).hexdigest()
        result=subprocess.run([str(PYTHON),'-B',str(WORKER),'--toolkit',str(ROOT),'--profile',profile,'--source',str(source),'--output',str(out)],capture_output=True,timeout=120)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),before)
        return result,out
    def test_url_offline_interpretation(self):
        r,out=self.worker('URLs','urls.txt',b'https://example.invalid/search?q=COC%20synthetic')
        self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
        result=json.loads((out/'result.json').read_text());self.assertFalse(result['remote_lookups']);self.assertIn('example.invalid',json.dumps(result))
    def test_url_count_refusal(self):
        r,_=self.worker('URLs','urls.txt',b'http://example.invalid/\n'*21);self.assertNotEqual(r.returncode,0)
    def test_non_url_refusal(self):
        r,_=self.worker('URLs','urls.txt',b'file:///C:/Windows/win.ini');self.assertNotEqual(r.returncode,0)
    def test_base64(self):
        r,out=self.worker('Decode','encoded.b64',b'Q09DIFNZTlRIRVRJQw==');self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual((out/'base64-decoded.bin').read_bytes(),b'COC SYNTHETIC')
    def test_hex(self):
        r,out=self.worker('Decode','encoded.hex',b'43 4f 43');self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertEqual((out/'hex-decoded.bin').read_bytes(),b'COC')
    def test_invalid_encoding(self):
        r,_=self.worker('Decode','bad.txt',b'not!encoded');self.assertNotEqual(r.returncode,0)
    def test_invalid_msg(self):
        r,_=self.worker('MSG','bad.msg',b'not an Outlook message');self.assertNotEqual(r.returncode,0)
    def test_input_output_overlap_refusal(self):
        r=subprocess.run([str(PYTHON),'-B',str(PIPELINE),'--toolkit',str(ROOT),'--profile','Decode','--input',str(self.base),'--case',str(self.base/'case')],capture_output=True,timeout=20);self.assertNotEqual(r.returncode,0)
    def test_network_and_execution_hooks(self):
        code="import importlib.util,socket,subprocess; s=importlib.util.spec_from_file_location('worker',r'"+str(WORKER)+"');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.configure(__import__('pathlib').Path(r'"+str(ROOT)+"')); blocked=0\nfor fn in [lambda:socket.getaddrinfo('example.invalid',443),lambda:subprocess.run(['nonexistent'])]:\n try:fn()\n except PermissionError:blocked+=1\nassert blocked==2"
        r=subprocess.run([str(PYTHON),'-B','-c',code],capture_output=True,timeout=20);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
    def test_execution_event(self):
        p=self.base/'events.json';p.write_text(json.dumps([{'EventID':4688,'Timestamp':'2026-01-01T00:00:00Z','Image':'synthetic.exe'}]));r=review.review(p,'ExecutionReview');self.assertEqual(len(r['leads']),1);self.assertEqual(r['leads'][0]['row'],1)
    def test_event_one_requires_sysmon(self):
        p=self.base/'events.json';p.write_text(json.dumps([{'EventID':1,'Channel':'OtherLog'}]));self.assertEqual(review.review(p,'ExecutionReview')['leads'],[])
    def test_lateral_lead(self):
        p=self.base/'events.csv';p.write_text('EventID,Computer\n4624,SYNTHETIC\n9999,SYNTHETIC\n');r=review.review(p,'LateralReview');self.assertEqual(len(r['leads']),1);self.assertEqual(r['records_examined'],2)
    def test_cloudtrail_and_entra(self):
        for name,data in [('aws',{'Records':[{'eventSource':'iam.amazonaws.com','eventName':'CreateUser','eventTime':'2026-01-01T00:00:00Z'}]}),('entra',{'value':[{'createdDateTime':'2026-01-01T00:00:00Z','userPrincipalName':'synthetic@example.invalid'}]})]:
            p=self.base/(name+'.json');p.write_text(json.dumps(data));self.assertEqual(len(review.review(p,'CloudAudit')['leads']),1)
    def test_unknown_cloud_schema(self):
        p=self.base/'unknown.json';p.write_text('{"foo":"bar"}');self.assertRaises(ValueError,review.review,p,'CloudAudit')
    def test_ransomware_is_descriptive(self):
        p=self.base/'README_RECOVER.txt';p.write_text('SYNTHETIC benign note');r=review.ransomware(p,self.base);self.assertTrue(r['possible_note_filename']);self.assertIn('not ransomware detection',' '.join(r['limitations']))
    def test_no_note_name_no_note_excerpt(self):
        p=self.base/'normal.bin';p.write_bytes(bytes(range(256)));r=review.ransomware(p,self.base);self.assertFalse(r['possible_note_filename']);self.assertIsNone(r['note_text_excerpt'])
    def test_record_cap(self):
        p=self.base/'large.json';p.write_text(json.dumps([{'EventID':4688}]*5001));self.assertRaises(ValueError,review.review,p,'ExecutionReview')

if __name__=='__main__':unittest.main()
