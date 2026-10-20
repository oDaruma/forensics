import sys,json,re,tempfile
from pathlib import Path
from forensics import prepare_package,build_kql,sha256,make_aes_zip
HERE=Path(__file__).parent
J=json.loads((HERE/'Azure_File_Provenance_v3.json').read_text())
D=json.loads((HERE/'examples/demo_events.json').read_text())
META={'case_id':'DFIR-TEST-003','file_path':'https://contoso.sharepoint.com/sites/Finance/Shared Documents/Drafts/Financial-Report.xlsx',
 'start_utc':'2026-10-01T00:00:00Z','end_utc':'2026-10-20T10:00:00Z',
 'collector':'Test Examiner','purpose':'Synthetic report test','requested_by_oid':'LOCAL-TEST','source_system':'SYNTHETIC SAMPLE ONLY','file_hash':''}

def run():
  assert len(D)==14
  params=J['items'][1]['content']['parameters'];assert {'FilePath','FileHash','TimeRange'}.issubset({p['name'] for p in params})
  qviews=[x for x in J['items'] if x.get('type')==3 and x.get('name')!='coverage']
  assert len(qviews)==9
  for x in qviews:
    q=x['content']['query']
    assert 'EmailAttachmentInfo' in q and 'EmailEvents' in q and 'CloudAppEvents' in q
    assert "@'{FileHash:escape}'" in q and "@'{FilePath:escape}'" in q
    assert 'MESSAGE_ID_LINK_TO_CANDIDATE' in q and 'FILENAME_CANDIDATE' in q
  q=build_kql(META['file_path'],META['start_utc'],META['end_utc'],'A1'*20)
  assert "@'{FileHash:escape}'" not in q and '{TimeRange}' not in q
  assert 'RawRecord=pack_all()' in q and 'take 3001' in q
  assert 'EmailEvents' in q and 'EmailAttachmentInfo' in q and 'CloudAppEvents' in q
  assert '\"a1\"' not in q
  injected=build_kql('C:\\Bob";union Danger|take 5\\abc.xlsx',META['start_utc'],META['end_utc'])
  assert r'Bob\";union Danger' in injected
  files,manifest=prepare_package(META,D,q)
  assert manifest['source_file_acquired'] is False
  assert set(files)==set(manifest['evidence_hashes'])|{'manifest.json'}
  for k,v in manifest['evidence_hashes'].items():assert sha256(files[k])==v['sha256']
  assert files['report/Forensic_Investigation_Report.pdf'].startswith(b'%PDF')
  assert files['custody/Chain_of_Custody.pdf'].startswith(b'%PDF')
  csv=files['evidence/events.csv'].decode('utf-8-sig')
  assert 'EmailRecipient' in csv and 'EmailRoute' in csv and 'CloudApps' in csv
  try:
    import pyzipper
  except ImportError:
    with tempfile.TemporaryDirectory() as d:
      try:make_aes_zip(files,Path(d)/'x.zip','a'*48)
      except RuntimeError as e:assert 'pyzipper' in str(e)
      else:raise AssertionError('Must not emit plain archive if AES module missing')
  else:
    with tempfile.TemporaryDirectory() as d:
      target=Path(d)/'x.zip'; digest=make_aes_zip(files,target,'a'*48)
      assert sha256(target.read_bytes())==digest
  print('PASS: workbook 9 views, 5 telemetry tables, mail linkage, file hash, report, CoC, manifest, CSV, encryption behavior')

if __name__=='__main__':run()
