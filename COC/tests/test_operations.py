import importlib.util,json,pathlib,tempfile,unittest,zipfile,datetime
from unittest import mock
W=pathlib.Path(__file__).resolve().parents[1]/'launchers/windows';s=importlib.util.spec_from_file_location('ops',W/'operations_manager.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
K=W.parents[2]
class Operations(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.temp.name);self.source=self.base/'original/case';self.source.mkdir(parents=True);self.case=self.base/'maintenance/run';(self.case/'raw').mkdir(parents=True);self.archives=self.base/'archives';self.archives.mkdir();self.kit=self.base/'kit';self.kit.mkdir()
  (self.source/'raw/parser').mkdir(parents=True);(self.source/'raw/verified-copy').mkdir()
  values={'run.json':json.dumps(dict(schema_version=1,case_id='TEST',run_id='synthetic',profile='Response-ServerLogs',authority_reference='Harmless test',status='COMPLETE',ended_utc='2026-10-14T00:00:00Z')),'activity.log':'generated activity','errors.log':'generated errors','events.jsonl':'{"event":"synthetic"}\n','raw/parser/stdout.log':'synthetic parser output','raw/parser/stderr.log':'synthetic parser diagnostic','raw/access.log':'ACQUIRED SYSTEM LOG — PRESERVE','raw/verified-copy/stdout.log':'ACQUIRED FILE — PRESERVE','report.html':'harmless report'}
  for rel,value in values.items():(self.source/rel).write_text(value)
  self.manifest()
 def manifest(self):
  entries=[dict(path=p.relative_to(self.source).as_posix(),bytes=p.stat().st_size,sha256=m.dfir.digest(p)) for p in self.source.rglob('*') if p.is_file() and p.name!='artifact-manifest.json'];m.dump(self.source/'artifact-manifest.json',dict(schema_version=1,files=entries))
 def tearDown(self):self.temp.cleanup()
 def retain(self,mode='LogsClean',selection='ALL',confirm=None):
  plan=m.log_plan(self.source);return m.retain(self.source,self.case,self.kit,mode,self.archives,selection,confirm if confirm is not None else 'DELETE '+plan['plan_id'],'Synthetic retention test')
 def test_plan_only_generated(self):
  plan=m.log_plan(self.source);self.assertEqual(len(plan['files']),5);self.assertNotIn('raw/access.log',[e['path'] for e in plan['files']]);self.assertNotIn('raw/verified-copy/stdout.log',[e['path'] for e in plan['files']])
 def test_preview_changes_no_case(self):
  before=m.dfir.digest(self.source/'artifact-manifest.json');self.retain('LogsPreview');self.assertEqual(before,m.dfir.digest(self.source/'artifact-manifest.json'));m.field.verify_case(self.source)
 def test_archive_only_keeps_logs(self):
  result=self.retain('LogsArchive');self.assertTrue((self.source/'activity.log').exists());self.assertTrue(result['archive']['read_back_verified']);m.field.verify_case(self.source)
 def test_cleanup_selected(self):
  plan=m.log_plan(self.source);index=next(i+1 for i,e in enumerate(plan['files']) if e['path']=='activity.log');before=plan['source_manifest_sha256'];result=self.retain(selection=str(index));self.assertEqual(result['deleted_files'],1);self.assertFalse((self.source/'activity.log').exists());self.assertTrue((self.source/'errors.log').exists());m.field.verify_case(self.source)
  copies=list((self.source/'retention').rglob('artifact-manifest.before.json'));self.assertEqual(m.dfir.digest(copies[0]),before)
  with zipfile.ZipFile(result['archive']['path']) as z:self.assertEqual(z.read('activity.log'),b'generated activity')
 def test_cleanup_preserves_evidence(self):
  self.retain();self.assertEqual((self.source/'raw/access.log').read_text(),'ACQUIRED SYSTEM LOG — PRESERVE');self.assertEqual((self.source/'raw/verified-copy/stdout.log').read_text(),'ACQUIRED FILE — PRESERVE');m.field.verify_case(self.source)
 def test_wrong_confirmation(self):
  with self.assertRaises(ValueError):self.retain(confirm='DELETE wrong')
  self.assertFalse(list(self.archives.iterdir()));m.field.verify_case(self.source)
 def test_stale_preview_after_documented_change(self):
  old=m.log_plan(self.source);(self.source/'errors.log').write_text('new generated diagnostic');self.manifest()
  with self.assertRaises(ValueError):self.retain(confirm='DELETE '+old['plan_id'])
  self.assertFalse(list(self.archives.iterdir()));m.field.verify_case(self.source)
 def test_archive_tampered_before_delete(self):
  original=m.archive_case
  def tamper(*args):
   result=original(*args)
   with pathlib.Path(result['path']).open('ab') as f:f.write(b'changed')
   return result
  with mock.patch.object(m,'archive_case',tamper):
   with self.assertRaises(ValueError):self.retain()
  self.assertTrue((self.source/'activity.log').exists());m.field.verify_case(self.source)
 def test_missing_reason(self):
  plan=m.log_plan(self.source)
  with self.assertRaises(ValueError):m.retain(self.source,self.case,self.kit,'LogsClean',self.archives,'ALL','DELETE '+plan['plan_id'],'')
 def test_modified_case_refused(self):
  (self.source/'activity.log').write_text('owner edit')
  with self.assertRaises(ValueError):self.retain()
  self.assertEqual((self.source/'activity.log').read_text(),'owner edit')
 def test_untracked_file_refused(self):
  (self.source/'untracked.log').write_text('owner file')
  with self.assertRaises(ValueError):self.retain()
 def test_active_case_refused(self):
  run=m.read(self.source/'run.json');run['status']='RUNNING';m.dump(self.source/'run.json',run);self.manifest()
  with self.assertRaises(ValueError):self.retain()
 def test_duplicate_selection(self):
  with self.assertRaises(ValueError):self.retain(selection='1,1')
 def test_out_of_range_selection(self):
  with self.assertRaises(ValueError):self.retain(selection='999')
 def test_invalid_selection(self):
  with self.assertRaises(ValueError):self.retain(selection='../*')
 def test_source_overlap_refused(self):
  with self.assertRaises(ValueError):m.retain(self.source,self.case,self.kit,'LogsArchive',self.source)
 def test_archive_failure_keeps_logs(self):
  with mock.patch.object(m,'archive_case',side_effect=ValueError('synthetic read-back failure')):
   with self.assertRaises(ValueError):self.retain()
  m.field.verify_case(self.source);self.assertTrue((self.source/'activity.log').exists())
 def test_mid_cleanup_recovers_missing_originals(self):
  original=pathlib.Path.unlink;calls=[]
  def fail_second(p,*args,**kwargs):
   if p.is_relative_to(self.source):
    calls.append(p)
    if len(calls)==2:raise OSError('synthetic interruption')
   return original(p,*args,**kwargs)
  with mock.patch.object(pathlib.Path,'unlink',fail_second):
   with self.assertRaises(OSError):self.retain()
  self.assertTrue((self.source/'activity.log').exists());self.assertTrue((self.case/'raw/cleanup-interrupted.json').exists());self.assertTrue(list(self.source.rglob('artifact-manifest.before.json')))
 def test_competing_manager_lock(self):
  with m.source_lock(self.source,self.case):
   with self.assertRaises((OSError,BlockingIOError)):
    with m.source_lock(self.source,self.case):pass
 def test_same_parent_refused(self):
  same=self.source.parent/'maintenance';(same/'raw').mkdir(parents=True)
  with self.assertRaises(ValueError):m.retain(self.source,same,self.kit,'LogsPreview')
 def test_guides_fixed(self):
  for name in m.GUIDES:
   plan=m.guide(name);self.assertTrue(plan['analyst_review'])
   for step in plan['steps']:self.assertTrue((W/step['launcher']).is_file());self.assertEqual(step['status'],'planned');self.assertNotEqual(step['profile'],'LiveSnapshot')
 def test_unknown_guide(self):
  with self.assertRaises(ValueError):m.guide('arbitrary-command')
 def test_freshness_no_network(self):
  m.freshness(K,self.case/'raw',datetime.datetime(2026,10,15,tzinfo=datetime.timezone.utc));report=m.read(self.case/'raw/freshness.json');self.assertFalse(report['network_checks']);self.assertEqual(report['rule_snapshot_age_days'],1);self.assertTrue(all(t['current_upstream_version'] is None for t in report['tools']))
 def test_freshness_negative_age_unknown(self):
  m.freshness(K,self.case/'raw',datetime.datetime(2020,1,1,tzinfo=datetime.timezone.utc));self.assertIsNone(m.read(self.case/'raw/freshness.json')['rule_snapshot_age_days'])
 def test_handoff_preserves_case(self):
  before=m.dfir.digest(self.source/'artifact-manifest.json');m.handoff(self.source,self.case/'raw','Synthetic unresolved note');self.assertEqual(m.dfir.digest(self.source/'artifact-manifest.json'),before);self.assertEqual(m.read(self.case/'raw/handoff.json')['custody_transfer']['status'],'NOT TRANSFERRED');m.field.verify_case(self.source)
if __name__=='__main__':unittest.main()
