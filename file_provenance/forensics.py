"""File Provenance Preservation v3.0 - audit-log/email/cloud transfer snapshot and reports.

Not a forensic disk-image acquisition. Does not infer descendant copies.
Does not assert WORM or chain-of-custody completion without recorded evidence.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import io
import json
import os
import re
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, PageBreak
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Polygon

HERE = Path(__file__).resolve().parent
MAX_EVENTS = 3000
CASE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$')
UTC = timezone.utc


def utc_now():
    return datetime.now(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z')


def iso_utc(s):
    dt = datetime.fromisoformat(s.replace('Z','+00:00'))
    if dt.tzinfo is None:
        raise ValueError('Timestamps must have UTC timezone')
    return dt.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def check_request(metadata):
    case_id = metadata.get('case_id','')
    if not CASE_RE.fullmatch(case_id):
        raise ValueError('case_id must have 3-64 safe characters (letters/digits/._-)')
    p = metadata.get('file_path','')
    if len(p) < 5 or len(p)>2048 or not ('/' in p or '\\' in p):
        raise ValueError('An actual full file path/URL is required')
    st = datetime.fromisoformat(iso_utc(metadata['start_utc']).replace('Z','+00:00'))
    en = datetime.fromisoformat(iso_utc(metadata['end_utc']).replace('Z','+00:00'))
    if en <= st or (en-st).days > 180 or en > datetime.now(UTC) + timedelta(days=1):
        raise ValueError('Date interval must be positive and at most 180 days')
    if metadata.get('file_hash') and not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}',metadata['file_hash']):
        raise ValueError('Optional hash must be a 40- or 64-character hex string')
    if not metadata.get('collector') or not metadata.get('purpose'):
        raise ValueError('Collector and forensic purpose must be supplied')


def sha256(data: bytes):
    return hashlib.sha256(data).hexdigest()


def json_bytes(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=str)+'\n').encode('utf-8')


def build_kql(file_path, start_utc, end_utc, file_hash=''):
    # JSON double-quoted string literals prevent KQL injection via path/hash.
    source=(HERE/'common.kql').read_text(encoding='utf-8').split('// END COMMON')[0]
    assert "@'{FilePath:escape}'" in source and "@'{FileHash:escape}'" in source and '{TimeRange}' in source
    source=source.replace("@'{FilePath:escape}'",json.dumps(file_path,ensure_ascii=True))
    source=source.replace("@'{FileHash:escape}'",json.dumps(file_hash,ensure_ascii=True))
    period=f'between (datetime({iso_utc(start_utc)}) .. datetime({iso_utc(end_utc)}))'
    source=source.replace('{TimeRange}',period)
    # Preserve native source fields captured by pack_all() inside each source block.
    return source+'\nevents\n| order by TimeGenerated asc\n| take 3001\n'

def query_azure(workspace_id, query):
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient, LogsQueryStatus
    response = LogsQueryClient(DefaultAzureCredential()).query_workspace(workspace_id, query, timespan=timedelta(days=181))
    if response.status != LogsQueryStatus.SUCCESS:
        raise RuntimeError('Partial query / query failure; forensic preservation aborted')
    rows = []
    for table in response.tables:
        fields = [col.name for col in table.columns]
        for row in table.rows:
            rows.append(dict(zip(fields, row)))
    if len(rows) > MAX_EVENTS:
        raise RuntimeError('Over 3000 matching events; shorten date range (no incomplete preservation created)')
    return rows


def event_csv(events):
    cols = ['TimeGenerated','EventGroup','Operation','Actor','Telemetry','Device','SourcePath','DestinationPath',
            'ObservedPath','MatchBasis','EvidenceStrength','FileName','FileId','FileSHA1','FileSHA256','NetworkAddress',
            'EmailSender','EmailRecipient','MessageId','DeliveryStatus','TransferDirection','Application','FileSize','EvidenceId']
    fp = io.StringIO(newline='')
    writer=csv.DictWriter(fp, fieldnames=cols, extrasaction='ignore')
    writer.writeheader()
    for ev in events:
        writer.writerow({k:str(ev.get(k,'') or '') for k in cols})
    return fp.getvalue().encode('utf-8-sig')


def styles():
    st=getSampleStyleSheet()
    st.add(ParagraphStyle(name='ReportTitle2', parent=st['Title'], fontName='Helvetica-Bold', fontSize=17, leading=21, textColor=colors.HexColor('#15253B'), spaceAfter=12))
    st.add(ParagraphStyle(name='ReportH2', parent=st['Heading2'], fontName='Helvetica-Bold', fontSize=10.5, leading=14, textColor=colors.HexColor('#1B3F62'), spaceBefore=12, spaceAfter=5))
    st.add(ParagraphStyle(name='TinyReport',parent=st['BodyText'],fontSize=7.5,leading=10,spaceAfter=3))
    st.add(ParagraphStyle(name='SmallReport',parent=st['BodyText'],fontSize=9,leading=13,spaceAfter=6))
    st.add(ParagraphStyle(name='BoxHead',parent=st['BodyText'],fontName='Helvetica-Bold',fontSize=8,leading=11,textColor=colors.white))
    return st


def P(s, st, name='SmallReport'):
    return Paragraph(escape(str(s)).replace('\n','<br/>'), st[name])


def make_table(rows, widths, st, header=True):
    table=Table([[P(c,st,'TinyReport') for c in r] for r in rows], colWidths=widths, repeatRows=1 if header else 0, hAlign='LEFT')
    cmd=[('VALIGN',(0,0),(-1,-1),'TOP'), ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
         ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('GRID',(0,0),(-1,-1),.3,colors.HexColor('#CAD5E0'))]
    if header: cmd += [('BACKGROUND',(0,0),(-1,0),colors.HexColor('#DCE9F3'))]
    table.setStyle(TableStyle(cmd))
    return table


def pdf_bytes(elements, title, st):
    buf=io.BytesIO()
    doc=SimpleDocTemplate(buf, pagesize=(210*mm,297*mm), rightMargin=16*mm, leftMargin=16*mm, topMargin=18*mm, bottomMargin=16*mm, title=title)
    def page(canvas, document):
        canvas.saveState(); w,h=document.pagesize
        canvas.setStrokeColor(colors.HexColor('#C9D5E1'));canvas.line(16*mm,14*mm,w-16*mm,14*mm)
        canvas.setFont('Helvetica',7);canvas.setFillColor(colors.HexColor('#617183'))
        canvas.drawString(16*mm,9*mm,'FILE PROVENANCE | INVESTIGATION EVIDENCE')
        canvas.drawRightString(w-16*mm,9*mm,f'Page {document.page}')
        canvas.restoreState()
    doc.build(elements,onFirstPage=page,onLaterPages=page)
    return buf.getvalue()


def movement_diagram(moves):
    """Draw explicit observed movement links; no inferred lineage."""
    from urllib.parse import urlparse
    edge_subset=moves[:5]
    if not edge_subset: return None
    def short_path(p):
        txt=str(p).replace('\\','/')
        parts=[x for x in txt.split('/') if x]
        return ('.../'+'/'.join(parts[-2:]))[:48] if len(parts)>2 else txt[:48]
    d=Drawing(500, len(edge_subset)*54 + 10)
    for i,e in enumerate(edge_subset):
        y=len(edge_subset)*54-i*54-50
        for x,path,fill in [(6,e.get('SourcePath',''),'#E7F0FB'),(282,e.get('DestinationPath',''),'#E6F4F0')]:
            d.add(Rect(x,y,210,39,rx=6,ry=6,fillColor=colors.HexColor(fill),strokeColor=colors.HexColor('#91AAC6')))
            d.add(String(x+8,y+22,short_path(path),fontName='Helvetica',fontSize=8))
            d.add(String(x+8,y+8,'Source' if x==6 else 'Reported destination',fontSize=7,fillColor=colors.HexColor('#546577')))
        d.add(Line(217,y+19,278,y+19,strokeColor=colors.HexColor('#47729D'),strokeWidth=1.5))
        d.add(Polygon([278,y+19,272,y+23,272,y+15],fillColor=colors.HexColor('#47729D'),strokeColor=None))
        d.add(String(221,y+29,str(e.get('EventGroup',''))[:14],fontSize=7,fillColor=colors.HexColor('#394E65')))
    return d


def build_report(meta, events, artifacts):
    st=styles(); elems=[]
    elems.append(Paragraph('Digital Forensic Investigation Report',st['ReportTitle2']))
    elems.append(P('Report status: AUTOMATIC DRAFT - requires examiner review and sign-off',st))
    fields=[['Case ID',meta['case_id']],['Target file path / URL',meta['file_path']],
            ['Optional supplied content hash',meta.get('file_hash') or 'NOT PROVIDED'],['Investigator / collector',meta['collector']],
            ['Preservation requested by',meta.get('requested_by_oid','Not supplied')],['Purpose',meta['purpose']],
            ['UTC investigation window',f"{meta['start_utc']} to {meta['end_utc']}"],['Snapshot collected UTC',meta['collected_utc']],
            ['Events exported',str(len(events))],['Source system',meta['source_system']],
            ['Original source file acquired','NO - LOG SNAPSHOT ONLY'],['Data cap status','Within collection limit; coverage not assured']]
    elems.append(make_table(fields,[43*mm,135*mm],st,False))
    elems.append(Paragraph('1. Scope and methodology',st['ReportH2']))
    elems.append(P('The collector exported matching audit and endpoint activity events. The report presents observations recorded in those sources; it does not assert comprehensive history, full content lineage, or live file-location verification. The underlying Log Analytics source data were not forensically imaged.',st))
    elems.append(Paragraph('2. Findings summary',st['ReportH2']))
    actors=sorted({str(e.get('Actor') or '') for e in events if e.get('Actor')})
    moves=[e for e in events if e.get('EventGroup') in ('Movement','Copy') and e.get('DestinationPath')]
    emails=[e for e in events if e.get('EventGroup') in ('EmailAttachment','EmailRoute')]
    transfers=[e for e in events if e.get('EventGroup') in ('Upload','Download')]
    candidate_count=sum(1 for e in events if e.get('EvidenceStrength') in ('CANDIDATE_ONLY','MESSAGE_LINK_NOT_FILE_LINEAGE'))
    elems.append(P(f"{len(events)} matching log events; {len(actors)} logged principals; {len(moves)} recorded moves/copies; {len(emails)} email rows; {len(transfers)} upload/download rows; {candidate_count} filename/message candidates. These counts do not prove every access or descendant copy.",st))
    elems.append(P('Accounts observed: '+(', '.join(actors[:20]) or 'No matching identities')+(' (truncated)' if len(actors)>20 else ''),st))
    locs=[]
    for e in events:
        val=e.get('ObservedPath') or e.get('DestinationPath')
        if val: locs.append((str(e.get('TimeGenerated','')),str(val)))
    if locs:
        latest=max(locs,key=lambda x:x[0])
        elems.append(P(f'Last recorded location: {latest[1]} (event timestamp {latest[0]}). This is NOT a verified current location.',st))
    elems.append(Paragraph('3. Chronological evidence (sample of preserved events)',st['ReportH2']))
    rows=[['Event time UTC','Operation','Recorded account','Location / evidence ID']]
    for e in events[:35]:
        rows.append([str(e.get('TimeGenerated',''))[:25],str(e.get('Operation',''))[:24],str(e.get('Actor',''))[:28],
            str(e.get('DestinationPath') or e.get('SourcePath') or '')[:90]+'\nID: '+str(e.get('EvidenceId',''))[:65]])
    if len(rows)==1: rows.append(['No events','—','—','No matching telemetry in supplied dataset'])
    elems.append(make_table(rows,[31*mm,29*mm,34*mm,84*mm],st))
    if len(events)>35: elems.append(P(f'Only the first 35 of {len(events)} events are printed. All returned records are preserved in evidence/events.json and evidence/events.csv.',st))
    elems.append(Paragraph('4. Recorded movement links',st['ReportH2']))
    if moves:
        elems.append(P('Graph shows explicit logged move/copy edges only; destination existence is not independently confirmed.',st,'TinyReport'))
        elems.append(movement_diagram(moves))
        for e in moves[:15]:
            elems.append(P(f"{e.get('TimeGenerated','')} | {e.get('Operation','')} | {e.get('Actor','')} | {e.get('SourcePath','')} --> {e.get('DestinationPath','')}",st,'TinyReport'))
    else: elems.append(P('No explicit source-to-destination movement edges in the exported records.',st))
    elems.append(Paragraph('5. Email attachments, mail delivery, uploads and downloads',st['ReportH2']))
    elems.append(P('Email attachment processing does not demonstrate delivery. EmailEvents entries with the same NetworkMessageId describe message routing/delivery, not a proven causal transfer of the investigated original file. A filename match is a candidate; even equal hashes alone cannot prove the transfer path. SMTP delivery status does not prove the recipient opened or saved the file.',st))
    trows=[['UTC timestamp','Event / status','Sender or actor','Recipient / location','Match basis']]
    for e in (emails+transfers)[:55]:
        trows.append([str(e.get('TimeGenerated',''))[:22],
            (str(e.get('EventGroup',''))+' / '+str(e.get('DeliveryStatus','')))[:44],
            str(e.get('EmailSender') or e.get('Actor') or '')[:36],
            str(e.get('EmailRecipient') or e.get('DestinationPath') or e.get('SourcePath') or '')[:55],
            str(e.get('MatchBasis') or 'NOT SPECIFIED')[:42]])
    if len(trows)==1: trows.append(['No evidence','—','—','—','—'])
    elems.append(make_table(trows,[29*mm,37*mm,37*mm,43*mm,32*mm],st))
    if len(emails)+len(transfers)>55:elems.append(P('Additional email and transfer records are present in events.json / events.csv; printed table is abbreviated.',st))
    elems.append(Paragraph('6. Exhibits and integrity control',st['ReportH2']))
    for name,digest in sorted(artifacts.items()):
        elems.append(P(f'{name}: SHA-256 {digest}',st,'TinyReport'))
    elems.append(Paragraph('7. Evidential limitations',st['ReportH2']))
    elems.append(P('Log-only acquisition; incomplete reads possible; throttled M365 audit events; workspace retention limitations; matching filename/path does not prove identity across copies; an account is not conclusive human attribution; encrypted packaging alone does not establish legal admissibility. Reconcile original Microsoft 365 audit records and Graph item IDs independently before conclusions.',st))
    elems.append(Paragraph('8. Examiner review and sign-off',st['ReportH2']))
    elems.append(P('Reviewed by: ______________________________________    UTC date/time: __________________',st))
    elems.append(P('Findings approved / corrections / additional acquisition required: __________________________________',st))
    return pdf_bytes(elems,'File Provenance Investigation',st)


def build_coc(meta, evidence_hashes):
    st=styles(); elems=[]
    elems.append(Paragraph('Chain of Custody - Evidence Record',st['ReportTitle2']))
    elems.append(P('Status: INITIAL COMPUTER-GENERATED RECORD. Further transfers must be recorded when they occur.',st))
    rows=[['Case ID',meta['case_id']], ['Evidence item ID',f"{meta['case_id']}-LOG-001"],
          ['Evidence description','Search-result snapshot from M365 and endpoint telemetry'],
          ['Source queried',meta['source_system']],['Target path',meta['file_path']], ['Optional content hash',meta.get('file_hash') or 'NOT PROVIDED'],
          ['Collection time (UTC)',meta['collected_utc']],['Collector',meta['collector']],
          ['Requesting authenticated principal',meta.get('requested_by_oid','Not recorded')],
          ['Acquisition method','Log Analytics API query - normalized rows and originating raw telemetry records when returned'],
          ['Original file seized/acquired','NO'],['Evidence seal', 'SHA-256 per content file and separate archive SHA-256 receipt']]
    elems.append(make_table(rows,[54*mm,124*mm],st,False))
    elems.append(Paragraph('A. Integrity ledger',st['ReportH2']))
    for name,sha in sorted(evidence_hashes.items()):
        elems.append(P(f'{name}\nSHA-256: {sha}',st,'TinyReport'))
    elems.append(Paragraph('B. Events recorded at preparation',st['ReportH2']))
    items=[['UTC time','Custodian','Action performed','From / To'],
           [meta['collected_utc'],meta['collector'],'Exported query results; prepared log snapshot',meta['source_system']+' / preservation process']]
    elems.append(make_table(items,[31*mm,30*mm,56*mm,61*mm],st))
    elems.append(P('Archive creation and later transfer to Azure Storage must be independently recorded after successful completion. These future actions have deliberately NOT been pre-signed or represented as completed.',st))
    elems.append(Paragraph('C. Subsequent custody transfers - complete upon occurrence',st['ReportH2']))
    elems.append(make_table([['Date/time (UTC)','Released by','Received by','Purpose / destination','Signatures / receipt']]+[['','','','',''] for i in range(4)],
                            [33*mm,29*mm,29*mm,46*mm,41*mm],st))
    elems.append(Paragraph('D. Verification and examination',st['ReportH2']))
    elems.append(P('Before analysis or transfer, verify the SHA-256 hashes in manifest.json after extracting the encrypted ZIP. Compare the package ZIP hash against the independently retained storage receipt. Any discrepancy requires escalation and documentation.',st))
    return pdf_bytes(elems,'Evidence Chain of Custody',st)


def prepare_package(meta, events, query):
    check_request(meta)
    if len(events)>MAX_EVENTS: raise ValueError('Evidence result cap exceeded; narrow the query')
    meta={**meta,'collected_utc':meta.get('collected_utc') or utc_now(),
          'source_system':meta.get('source_system') or 'Microsoft Sentinel / Log Analytics',
          'original_file_acquired':False,'collection_type':'LOG_SNAPSHOT_ONLY', 'event_count':len(events)}
    files={
        'evidence/events.json':json_bytes({'collection':meta,'events':events}),
        'evidence/events.csv':event_csv(events),
        'evidence/query.kql':query.encode('utf-8'),
    }
    evidence_hashes={p:sha256(content) for p,content in files.items()}
    files['report/Forensic_Investigation_Report.pdf']=build_report(meta,events,evidence_hashes)
    files['custody/Chain_of_Custody.pdf']=build_coc(meta,evidence_hashes)
    manifest={'schema':'com.example.fileprovenance.manifest.v1','case_id':meta['case_id'],
              'created_utc':meta['collected_utc'],'preservation_scope':'LOG_SNAPSHOT_ONLY',
              'source_file_acquired':False,'hash_algorithm':'SHA-256',
              'evidence_hashes':{p:{'sha256':sha256(b),'bytes':len(b)} for p,b in sorted(files.items())},
              'limitations':['audit retention/collection gaps','no verification of live current file location',
                             'different file instances can share a path','email attachment filename matches do not prove original file provenance',
                             'mail processing does not imply message delivery','download may not expose receiving endpoint','no original source-file acquisition']}
    files['manifest.json']=json_bytes(manifest)
    return files,manifest


def make_aes_zip(files, path, password):
    if not password or len(password)<32:
        raise ValueError('ZIP password must have at least 32 characters; use a generated high-entropy secret')
    # pyzipper creates WinZip AES-256 (not legacy weak ZIP encryption).
    # PBKDF2 iterations are constrained by the ZIP AES standard, so use random high-entropy passwords.
    try:
        import pyzipper
    except ImportError as exc:
        raise RuntimeError('pyzipper must be installed; never fall back to legacy ZIP encryption') from exc
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    try:
        with pyzipper.AESZipFile(path,'w',compression=pyzipper.ZIP_DEFLATED,encryption=pyzipper.WZ_AES,allowZip64=True) as z:
            z.setpassword(password.encode('utf-8'))
            z.setencryption(pyzipper.WZ_AES, nbits=256)
            for name,payload in sorted(files.items()): z.writestr(name,payload)
        # Read back every encrypted entry and compare against source bytes.
        with pyzipper.AESZipFile(path) as z:
            z.setpassword(password.encode('utf-8'))
            for name,payload in files.items():
                if z.read(name)!=payload: raise RuntimeError('Post-encryption ZIP readback check failed')
        return sha256(path.read_bytes())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def upload_encrypted_archive(path, account_url, container, blob_name):
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobClient, ContentSettings
    client=BlobClient(account_url=account_url,container_name=container,blob_name=blob_name, credential=DefaultAzureCredential())
    with Path(path).open('rb') as fp:
        result=client.upload_blob(fp, overwrite=False, content_settings=ContentSettings(content_type='application/zip'),
                                  metadata={'preservation':'logsnapshot','sha256':sha256(Path(path).read_bytes())})
    # Upload success ≠ verification of container's immutability policy.
    return {'blob_name':blob_name,'blob_url':client.url,'etag':str(result.get('etag')),
            'uploaded_utc':utc_now(),'worm_policy_verified':False}


def store_keyvault_password(vault_url, case_id, password):
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    secret_name=('file-evidence-'+case_id.lower().replace('.','-').replace('_','-'))
    client=SecretClient(vault_url=vault_url,credential=DefaultAzureCredential())
    result=client.set_secret(secret_name,password,tags={'caseId':case_id,'purpose':'evidence-archive'})
    return {'secret_id':result.id,'secret_name':secret_name}


def save_demo_artifacts(meta, events, output_dir):
    output_dir=Path(output_dir);output_dir.mkdir(parents=True,exist_ok=True)
    query=build_kql(meta['file_path'],meta['start_utc'],meta['end_utc'],meta.get('file_hash',''))
    files,manifest=prepare_package(meta,events,query)
    for name in ('report/Forensic_Investigation_Report.pdf','custody/Chain_of_Custody.pdf','manifest.json'):
        target=output_dir/Path(name).name;target.write_bytes(files[name])
    return files,manifest


def main():
    p=argparse.ArgumentParser(description='Forensic log snapshot and encrypted evidence package (NOT source file acquisition)')
    p.add_argument('--events-json',required=True,help='Local sample data (an array of events)')
    p.add_argument('--case-id',required=True);p.add_argument('--file-path',required=True)
    p.add_argument('--collector',required=True);p.add_argument('--purpose',required=True)
    p.add_argument('--file-hash',default='',help='Optional SHA1/SHA256 to corroborate content')
    p.add_argument('--start-utc',required=True);p.add_argument('--end-utc',required=True)
    p.add_argument('--output-dir',required=True);p.add_argument('--demo-documents-only',action='store_true')
    args=p.parse_args()
    meta={'case_id':args.case_id,'file_path':args.file_path,'collector':args.collector,'purpose':args.purpose,
          'start_utc':args.start_utc,'end_utc':args.end_utc,'file_hash':args.file_hash,'requested_by_oid':'LOCAL_DEMO_NOT_AUTHENTICATED',
          'source_system':'SYNTHETIC TEST INPUT (NOT LIVE EVIDENCE)'}
    events=json.loads(Path(args.events_json).read_text())
    files,manifest=save_demo_artifacts(meta,events,args.output_dir)
    if args.demo_documents_only:
        print('Demo reports and manifest generated; NO ENCRYPTED ARCHIVE produced.')
    else:
        password=os.environ.get('EVIDENCE_ZIP_PASSWORD')
        if not password: raise SystemExit('Set EVIDENCE_ZIP_PASSWORD in environment (not as CLI argument)')
        zpath=Path(args.output_dir)/(args.case_id+'-evidence-aes256.zip')
        zh=make_aes_zip(files,zpath,password)
        print(f'Encrypted ZIP created and verified: {zpath}; SHA-256 {zh}')
    print('All sample data are synthetic; no live Microsoft source was accessed.')

if __name__=='__main__': main()
