import pathlib,sys,tempfile,unittest,json,email.message,unittest.mock
LAUNCH=pathlib.Path(__file__).resolve().parents[1]/'launchers/windows';sys.path.insert(0,str(LAUNCH))
import investigation_pipeline as inv
class InvestigationTests(unittest.TestCase):
    def tree(self,d):
        r=pathlib.Path(d);source=r/'input';case=r/'case';kit=r/'kit'
        for p in [source,case,kit]:p.mkdir()
        (case/'raw').mkdir();return source,case,kit
    def test_eml_attachment_cannot_escape_and_url_not_visited(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);msg=email.message.EmailMessage();msg['From']='sender@example.invalid';msg['Subject']='<script>test</script>';msg.set_content('https://example.invalid/phish');msg.add_attachment(b'benign',maintype='application',subtype='octet-stream',filename='../../escape.exe');(source/'sample.eml').write_bytes(msg.as_bytes())
            before=inv.dfir.inventory(source);rows,gaps=inv.email_review(before,case/'raw')
            self.assertFalse(gaps);self.assertEqual(len(rows),1);self.assertTrue((case/'raw/attachments/attachment-1.exe').exists());self.assertFalse((pathlib.Path(d)/'escape.exe').exists())
            self.assertIn('&lt;script&gt;',(case/'raw/findings.html').read_text());self.assertEqual(inv.field.identities(before),inv.field.identities(inv.dfir.inventory(source)))
    def test_empty_eml_is_not_successful_coverage(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);(source/'empty.eml').write_bytes(b'');rows,gaps=inv.email_review(inv.dfir.inventory(source),case/'raw');self.assertFalse(rows);self.assertTrue(gaps)
    def test_linux_binary_journal_explicit_gap(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);(source/'system.journal').write_bytes(b'LPKSHHRH\x00binary');rows,gaps=inv.linux_review(inv.dfir.inventory(source),case/'raw');self.assertFalse(rows);self.assertTrue(gaps)
    def test_persistence_binary_hive_not_misrepresented(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);(source/'SYSTEM').write_bytes(b'regf');rows,gaps=inv.persistence_review(inv.dfir.inventory(source),case/'raw');self.assertFalse(rows);self.assertTrue(gaps)
    def test_resume_skips_verified_and_preserves_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);dest=pathlib.Path(d)/'staging';dest.mkdir();(source/'benign.txt').write_text('known')
            first=inv.resume_transfer(source,dest,case,kit);second=inv.resume_transfer(source,dest,case,kit)
            self.assertEqual(first['copied'],1);self.assertEqual(second['previously_verified'],1)
            (dest/'benign.txt').write_text('owner edit')
            with self.assertRaises(ValueError):inv.resume_transfer(source,dest,case,kit)
            self.assertEqual((dest/'benign.txt').read_text(),'owner edit');self.assertFalse((dest/'.coc-transfer.lock').exists())
    def test_resume_rejects_scope_change(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);dest=pathlib.Path(d)/'staging';dest.mkdir();(source/'benign.txt').write_text('known');inv.resume_transfer(source,dest,case,kit);(source/'added.txt').write_text('new')
            with self.assertRaises(ValueError):inv.resume_transfer(source,dest,case,kit)
            self.assertFalse((dest/'added.txt').exists())
    def test_existing_nonempty_staging_never_adopted(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);dest=pathlib.Path(d)/'staging';dest.mkdir();(dest/'owner.txt').write_text('preserve');(source/'a').write_text('a')
            with self.assertRaises(ValueError):inv.resume_transfer(source,dest,case,kit)
            self.assertEqual((dest/'owner.txt').read_text(),'preserve')
    def test_reserved_source_control_names_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);dest=pathlib.Path(d)/'staging';dest.mkdir();(source/'.coc-transfer.lock').write_text('')
            with self.assertRaises(ValueError):inv.resume_transfer(source,dest,case,kit)
            self.assertFalse((dest/'.coc-transfer-state.json').exists())
    def test_stale_transfer_lock_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);dest=pathlib.Path(d)/'staging';dest.mkdir();(source/'a').write_text('a');lock=dest/'.coc-transfer.lock';lock.write_text('owner lock')
            with self.assertRaises(FileExistsError):inv.resume_transfer(source,dest,case,kit)
            self.assertEqual(lock.read_text(),'owner lock')
    def test_wrong_takajo_schema_rejected_before_empty_success(self):
        with tempfile.TemporaryDirectory() as d:
            path=pathlib.Path(d)/'bad.jsonl';path.write_text(json.dumps(dict(Computer='SYNTHETIC'))+'\n')
            with self.assertRaises(ValueError):inv.validate_hayabusa(path)
    def case_fixture(self,path,status='PARTIAL'):
        path.mkdir();(path/'raw').mkdir();(path/'run.json').write_text(json.dumps(dict(status=status)));(path/'raw/indicators.json').write_text(json.dumps([dict(value='https://example.invalid/shared')]))
        files=[dict(path=p.relative_to(path).as_posix(),bytes=p.stat().st_size,sha256=inv.dfir.digest(p)) for p in path.rglob('*') if p.is_file()];inv.dump(path/'artifact-manifest.json',dict(files=files))
    def test_case_export_preserves_original_partial(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);original=source/'original';self.case_fixture(original);before=inv.field.verify_case(original)
            result=inv.export_case(original,case/'raw');self.assertEqual(result['original_status'],'PARTIAL');self.assertFalse(result['evidence_copied']);self.assertEqual(inv.field.verify_case(original),before)
    def test_cross_case_matches_keep_both_sources(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);self.case_fixture(source/'case-a');self.case_fixture(source/'case-b');result=inv.compare_cases(source,case/'raw');self.assertEqual(result['matches'],2)
            rows=json.loads((case/'raw/findings.json').read_text())['records'];self.assertEqual(rows[0]['cases'],['case-a','case-b']);self.assertEqual(len(rows[0]['references']),2)
    def test_tampered_case_cannot_be_exported(self):
        with tempfile.TemporaryDirectory() as d:
            source,case,kit=self.tree(d);original=source/'original';self.case_fixture(original);(original/'run.json').write_text('{}')
            with self.assertRaises(ValueError):inv.export_case(original,case/'raw')
    def test_indicator_strings_are_typed_and_invalid_ip_rejected(self):
        rows=inv.indicators('https://example.invalid/a sender@example.invalid 192.0.2.1 999.2.3.4','fixture')
        self.assertEqual({r['type'] for r in rows},{'url','domain','email','ipv4'});self.assertFalse(any(r['value']=='999.2.3.4' for r in rows))
if __name__=='__main__':unittest.main()
