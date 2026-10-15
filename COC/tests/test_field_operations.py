import sys,pathlib,tempfile,unittest,json,hashlib,unittest.mock
LAUNCH=pathlib.Path(__file__).resolve().parents[1]/'launchers/windows'
sys.path.insert(0,str(LAUNCH))
import field_operations as field
import dfir_pipeline as dfir

class FieldTests(unittest.TestCase):
    def setup_tree(self,base):
        root=pathlib.Path(base);source=root/'input';case=root/'case';kit=root/'kit'
        for p in (source,case,kit):p.mkdir()
        (case/'raw').mkdir();return source,case,kit
    def test_transfer_readback_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);(source/'file.txt').write_bytes(b'benign evidence')
            result=field.transfer(source,case,kit);self.assertTrue(result['read_back_verified'])
            self.assertEqual((source/'file.txt').read_bytes(),(case/'raw/verified-copy/file.txt').read_bytes())
            with self.assertRaises(ValueError):field.transfer(source,case,kit)
    def test_nested_input_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);nested=source/'output';nested.mkdir()
            with self.assertRaises(ValueError):field.transfer(source,nested,kit)
    def test_changed_source_detected(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);(source/'file.txt').write_bytes(b'original')
            original=field.inventory;calls=[0]
            def mutate(p):
                calls[0]+=1
                if calls[0]==2:(source/'file.txt').write_bytes(b'changed')
                return original(p)
            with unittest.mock.patch.object(field,'inventory',side_effect=mutate):
                with self.assertRaises(ValueError):field.transfer(source,case,kit)
    def fixture_case(self,source):
        (source/'raw').mkdir();(source/'run.json').write_text(json.dumps({'status':'PARTIAL','case_id':'TEST'}))
        (source/'raw/events.csv').write_text('Timestamp,Note\n2026-10-14T12:00:00Z,benign\n')
        files=[dict(path=p.relative_to(source).as_posix(),bytes=p.stat().st_size,sha256=field.digest(p)) for p in source.rglob('*') if p.is_file()]
        (source/'artifact-manifest.json').write_text(json.dumps({'files':files}))
    def test_closeout_preserves_partial_and_escapes_notes(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);self.fixture_case(source);before=field.verify_case(source)
            result=field.closeout(source,case,kit,'<script>bad()</script>')
            self.assertEqual(result['original_status'],'PARTIAL');self.assertEqual(before,field.verify_case(source))
            text=(case/'raw/case-review.html').read_text();self.assertIn('&lt;script&gt;',text);self.assertNotIn('<script>',text)
    def test_tampered_case_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);self.fixture_case(source);(source/'run.json').write_text('{}')
            with self.assertRaises(ValueError):field.verify_case(source)
    def test_unmanifested_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);self.fixture_case(source);(source/'extra.txt').write_text('extra')
            with self.assertRaises(ValueError):field.verify_case(source)
    def test_manifest_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d)
            (source/'artifact-manifest.json').write_text(json.dumps({'files':[dict(path='../outside',bytes=0,sha256='0'*64)]}))
            with self.assertRaises(ValueError):field.verify_case(source)
    def test_health_reports_missing_without_launching(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);m=kit/'COC/manifests';m.mkdir(parents=True)
            (m/'release.json').write_text(json.dumps({'release':'test','files':[dict(path='missing',sha256='0'*64)]}))
            (m/'field-readiness.json').write_text(json.dumps([dict(name='test',status='pending')]))
            result=field.health(kit,case);self.assertEqual(result['status'],'PARTIAL');self.assertFalse(result['executed_tools'])
    def test_bulk_plan_only_reads_working_file(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.setup_tree(d);sample=source/'image.dd';sample.write_bytes(b'benign')
            exe=kit/'COC/tools/windows/bulk_extractor/bulk_extractor64.exe';exe.parent.mkdir(parents=True);exe.write_bytes(b'fixture')
            step=dfir.plan(kit,dfir.inventory(source),'BulkFeatures',case/'raw')[0]
            self.assertEqual(step['cmd'][0],str(exe));self.assertEqual(step['cmd'][-1],str(sample));self.assertIn('email',step['cmd'])
if __name__=='__main__':unittest.main()
