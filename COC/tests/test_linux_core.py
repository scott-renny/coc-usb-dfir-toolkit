import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest

MODULE=Path(__file__).resolve().parents[1]/'launchers/linux/coc_security.py'
spec=importlib.util.spec_from_file_location('coc_security',MODULE)
coc=importlib.util.module_from_spec(spec);spec.loader.exec_module(coc)

class ScopeTests(unittest.TestCase):
    def test_allowlisted_host(self):
        self.assertEqual(coc.validate_targets(['192.0.2.10'],['192.0.2.0/24']),['192.0.2.10'])
    def test_outside_scope(self):
        with self.assertRaises(ValueError):coc.validate_targets(['198.51.100.2'],['192.0.2.0/24'])
    def test_exclusion(self):
        with self.assertRaises(ValueError):coc.validate_targets(['192.0.2.10'],['192.0.2.0/24'],['192.0.2.10/32'])
    def test_large_scope(self):
        with self.assertRaises(ValueError):coc.validate_targets(['192.0.2.1'],['192.0.0.0/16'])
    def test_hostnames_not_resolved(self):
        with self.assertRaises(ValueError):coc.validate_targets(['example.com'],['192.0.2.0/24'])
    def test_multicast_and_loopback(self):
        for host,net in [('224.0.0.1','224.0.0.0/24'),('127.0.0.1','127.0.0.0/24')]:
            with self.assertRaises(ValueError):coc.validate_targets([host],[net])
    def test_ipv6_allowed(self):
        self.assertEqual(coc.validate_targets(['2001:db8::10'],['2001:db8::/120']),['2001:db8::10'])
    def test_target_cap(self):
        with self.assertRaises(ValueError):coc.validate_targets(['192.0.2.'+str(i) for i in range(1,12)],['192.0.2.0/24'])
    def test_ports(self):
        self.assertEqual(coc.validate_ports('443,22,443'),'22,443')
        for raw in ['0','65536','22;rm','-1','']:
            with self.assertRaises(ValueError):coc.validate_ports(raw)
    def test_manifest_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);f=root/'data.txt';f.write_text('original')
            manifest=root/'manifest.json';coc.write_json(manifest,dict(files=[dict(path='data.txt',sha256=coc.sha256(f))]))
            self.assertEqual(coc.verify_manifest(root,manifest)['files'],1)
            f.write_text('changed')
            with self.assertRaises(ValueError):coc.verify_manifest(root,manifest)
    def test_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):coc.safe_path(d,'../escape')
    def test_absolute(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):coc.safe_path(d,str(Path(d)/'absolute'))
    def make_run(self,root):
        run=object.__new__(coc.Run);run.path=root;run.start=time.monotonic();run.lock=(root/'lock-test').open('w')
        (root/'raw').mkdir();run.metadata=dict(case_id='TEST',authority_reference='<script>alert(1)</script>',modules=[],limitations=['Synthetic test'],status='RUNNING')
        return run
    def test_report_escapes_authority_and_raw(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);run=self.make_run(root)
            (root/'raw/injection.txt').write_text('<img src=x onerror=alert(1)>',encoding='utf-8')
            run.record('injection','collected','','raw/injection.txt',coc.utc(),0)
            run.finalize();report=(root/'report.html').read_text(encoding='utf-8')
            self.assertNotIn('<script>alert',report);self.assertNotIn('<img src=x',report)
            self.assertIn('&lt;script&gt;',report);self.assertIn('&lt;img',report)
            self.assertEqual(coc.verify_manifest(root,root/'artifact-manifest.json',True)['status'],'matched-local-manifest')
    def test_missing_tool_is_unsupported_and_partial(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);run=self.make_run(root)
            run.command('missing',['coc-deliberately-missing-test-command-2026'])
            self.assertEqual(run.metadata['modules'][0]['status'],'unsupported')
            run.finalize();self.assertEqual(run.metadata['status'],'PARTIAL')
    def test_budget_expiration_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);run=self.make_run(root);run.start=time.monotonic()-901
            run.command('budget',['coc-deliberately-missing-test-command-2026'])
            self.assertEqual(run.metadata['modules'][0]['status'],'skipped')
            run.finalize();self.assertEqual(run.metadata['status'],'PARTIAL')
    def test_logging_summary_and_documentation(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);run=self.make_run(root)
            (root/'raw/failure.txt').write_text('Synthetic failure',encoding='utf-8')
            run.record('failure','failed','Synthetic failure','raw/failure.txt',coc.utc(),0)
            run.finalize()
            self.assertIn('failure: failed',(root/'errors.log').read_text(encoding='utf-8'))
            self.assertEqual(json.loads((root/'summary.json').read_text())['counts']['failed'],1)
            self.assertTrue((root/'READ-ME-FIRST.txt').is_file())
            events=[json.loads(line)['event'] for line in (root/'events.jsonl').read_text().splitlines()]
            self.assertEqual(events[-2:],['run.finalizing','run.finished'])
            paths=[v['path'] for v in json.loads((root/'artifact-manifest.json').read_text())['files']]
            for name in ['activity.log','errors.log','events.jsonl','summary.json','READ-ME-FIRST.txt']:self.assertIn(name,paths)
    def test_human_log_prevents_line_injection(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);run=self.make_run(root)
            run.log_event('test.message','INFO','First line\nFORGED LINE')
            self.assertNotIn('\nFORGED LINE',(root/'activity.log').read_text(encoding='utf-8'))
            run.lock.close()

if __name__=='__main__':unittest.main()
