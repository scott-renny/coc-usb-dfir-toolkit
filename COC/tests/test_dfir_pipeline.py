import csv,importlib.util,json,os,pathlib,sqlite3,sys,tempfile,unittest
PATH=pathlib.Path(__file__).resolve().parents[1]/'launchers/windows/dfir_pipeline.py'
spec=importlib.util.spec_from_file_location('dfir_pipeline',PATH);dfir=importlib.util.module_from_spec(spec);spec.loader.exec_module(dfir)
class PipelineTests(unittest.TestCase):
    def test_inventory_hash_and_kind(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);p=root/'test.pdf';p.write_bytes(b'%PDF-1.4 benign')
            rows=dfir.inventory(root);self.assertEqual(rows[0]['kind'],'pdf');self.assertEqual(rows[0]['sha256'],dfir.digest(p))
    def test_file_count_bound(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            for i in range(201):(root/str(i)).write_text('benign')
            with self.assertRaises(ValueError):dfir.inventory(root)
    def test_sqlite_analysis_preserves_source(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);p=root/'input.db';con=sqlite3.connect(p);con.execute('CREATE TABLE evidence(id INTEGER)');con.commit();con.close();before=dfir.digest(p)
            dfir.sqlite_review(p,root/'analysis');self.assertEqual(before,dfir.digest(p));self.assertEqual(json.loads((root/'analysis/schema.json').read_text())[0]['name'],'evidence')
    def test_timezone_and_formula_safety(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            with (root/'input.csv').open('w',newline='') as f:
                w=csv.writer(f);w.writerow(['Timestamp','Note']);w.writerows([['2026-10-13T08:00:00-04:00','first'],['2026-10-13 08:00:00','unknown zone'],['=1+1','formula']])
            result=dfir.merge_csvs(root,root/'correlation.csv');self.assertEqual(result['rows'],3)
            with (root/'correlation.csv').open() as f:rows=list(csv.DictReader(f))
            self.assertEqual(rows[0]['timestamp_utc'],'2026-10-13T12:00:00+00:00');self.assertEqual(rows[1]['timestamp_utc'],'');self.assertEqual(rows[2]['timestamp_original'],"'=1+1")
    def test_empty_eligible_plan(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);p=root/'note.txt';p.write_text('benign');self.assertEqual(dfir.plan(root,dfir.inventory(root),'ArtifactBatch',root/'out'),[])
    def test_command_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);result=dfir.run_process([sys.executable,'-c','import time; time.sleep(5)'],str(root),root/'out',os.environ.copy(),timeout=1)
            self.assertEqual(result['reason'],'timeout-or-output-cap');self.assertEqual(result['status'],'failed')
    def test_practice_is_benign(self):
        with tempfile.TemporaryDirectory() as d:
            folder=pathlib.Path(d)/'fixtures';dfir.practice(folder);self.assertEqual(len(dfir.inventory(folder)),3);self.assertEqual((folder/'sample.lnk').stat().st_size,80)
if __name__=='__main__':unittest.main()
