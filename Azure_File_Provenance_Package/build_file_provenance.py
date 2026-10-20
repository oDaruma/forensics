import json, uuid, pathlib, zipfile, re
OUT=pathlib.Path('/mnt/data'); OUT.mkdir(exist_ok=True)

BASE=r'''// File Provenance Workbook — observed event correlation, not full content lineage.
// Workbooks expand parameters before KQL is evaluated. :escape quotes text safely.
let inputPath = trim(' ', @'{FilePath:escape}');
let wanted = tolower(replace_string(inputPath, @'\', '/'));
let hasValidPath = strlen(wanted) >= 4 and wanted contains '/';
let allEvents = materialize(
    union isfuzzy=true
    (
        OfficeActivity
        | where TimeGenerated {TimeRange}
        | where OfficeWorkload in~ ('SharePoint', 'OneDrive')
        | extend src = iff(isnotempty(OfficeObjectId), tostring(OfficeObjectId), strcat(tostring(Site_Url), '/', tostring(SourceRelativeUrl), '/', tostring(SourceFileName)))
        | extend dest = iff(isnotempty(DestinationFileName), strcat(tostring(Site_Url), '/', tostring(DestinationRelativeUrl), '/', tostring(DestinationFileName)), '')
        | extend grp = case(Operation contains 'Cop', 'Copy', Operation contains 'Mov' or Operation contains 'Renam', 'Movement', Operation contains 'Access' or Operation contains 'Preview' or Operation contains 'SyncDownloaded', 'Access', Operation contains 'Download', 'Download', Operation contains 'Modif' or Operation contains 'Upload' or Operation contains 'CheckIn', 'Modified', Operation contains 'Creat', 'Created', Operation contains 'Shar' or Operation contains 'AnonymousLink' or Operation contains 'SecureLink', 'Sharing', Operation contains 'Delet' or Operation contains 'Recycl', 'Deleted', 'Other')
        | project TimeGenerated, Telemetry='M365/Purview', Operation=tostring(Operation), EventGroup=grp,
                  Actor=tostring(UserId), Device='', SourcePath=src, DestinationPath=dest,
                  ObservedPath=iff(isnotempty(dest) and grp in ('Copy','Movement'), dest, src),
                  FileName=tostring(SourceFileName), FileId=iff(isnotempty(ListItemUniqueId), strcat(tostring(Site_Url), '|', tostring(ListItemUniqueId)), ''),
                  FileSHA1='', FileSHA256='', NetworkAddress=tostring(ClientIP),
                  EvidenceId=tostring(OfficeId), IdentityId='', Process='', Notes=tostring(ResultStatus)
    ),
    (
        DeviceFileEvents
        | where TimeGenerated {TimeRange}
        | extend fn = tostring(FileName), pf = iff(isnotempty(PreviousFileName), tostring(PreviousFileName), tostring(FileName))
        | extend currentPath = iff(FolderPath endswith strcat(@'\', fn) or FolderPath endswith strcat('/', fn), tostring(FolderPath), strcat(tostring(FolderPath), @'\', fn))
        | extend oldPath = iff(isempty(PreviousFolderPath), '', iff(PreviousFolderPath endswith strcat(@'\', pf) or PreviousFolderPath endswith strcat('/', pf), tostring(PreviousFolderPath), strcat(tostring(PreviousFolderPath), @'\', pf)))
        | extend grp = case(ActionType contains 'Renam' or ActionType contains 'Mov', 'Movement', ActionType contains 'Cop', 'Copy', ActionType contains 'Creat', 'Created', ActionType contains 'Modif', 'Modified', ActionType contains 'Delet', 'Deleted', 'Other')
        | extend user = iff(isnotempty(InitiatingProcessAccountUpn), tostring(InitiatingProcessAccountUpn), strcat(tostring(InitiatingProcessAccountDomain), @'\', tostring(InitiatingProcessAccountName)))
        | project TimeGenerated, Telemetry='MDE/Endpoint', Operation=tostring(ActionType), EventGroup=grp,
                  Actor=user, Device=tostring(DeviceName), SourcePath=iff(isnotempty(oldPath), oldPath, currentPath),
                  DestinationPath=iff(isnotempty(oldPath) and grp in ('Movement','Copy'), currentPath, ''),
                  ObservedPath=currentPath, FileName=fn, FileId='', FileSHA1=tostring(SHA1), FileSHA256=tostring(SHA256),
                  NetworkAddress=tostring(RequestSourceIP), EvidenceId=strcat(tostring(DeviceId), ':', tostring(ReportId), ':', format_datetime(TimeGenerated, 'yyyyMMddHHmmssfff')),
                  IdentityId=tostring(InitiatingProcessAccountObjectId), Process=tostring(InitiatingProcessFileName), Notes=tostring(RequestProtocol)
    )
);
let normalized = materialize(
    allEvents
    | extend NormSrc = tolower(replace_string(SourcePath, @'\', '/')),
             NormDst = tolower(replace_string(DestinationPath, @'\', '/')),
             NormSeen = tolower(replace_string(ObservedPath, @'\', '/'))
    | extend IsDirectMatch = hasValidPath and
        (NormSrc == wanted or NormDst == wanted or NormSeen == wanted
        or (NormSrc endswith wanted and strlen(NormSrc) > strlen(wanted))
        or (NormDst endswith wanted and strlen(NormDst) > strlen(wanted))
        or (NormSeen endswith wanted and strlen(NormSeen) > strlen(wanted)))
);
// A matching M365 list-item ID can connect old/new URLs for the *same item*.
// Does not bridge a copied file to its new item ID, or link endpoints by hash.
let seedIds = normalized | where IsDirectMatch and isnotempty(FileId) | distinct FileId;
let events = materialize(
    normalized
    | where IsDirectMatch or (isnotempty(FileId) and FileId in (seedIds))
    | extend MatchBasis = iff(IsDirectMatch, 'PATH_MATCH', 'SAME_M365_ITEM_ID')
    | project-away NormSrc, NormDst, NormSeen, IsDirectMatch
);
'''

queries = {
  'summary': BASE + '''events
| summarize EventCount=count(), FirstObserved=min(TimeGenerated), LastObserved=max(TimeGenerated),
            Actors=dcountif(Actor,isnotempty(Actor)), Devices=dcountif(Device,isnotempty(Device)),
            M365Events=countif(Telemetry == 'M365/Purview'), EndpointEvents=countif(Telemetry == 'MDE/Endpoint')
| extend Scope='Observed events only — NOT proof of current location or complete lineage'
''',
  'latest': BASE + '''events
| where isnotempty(ObservedPath)
| summarize arg_max(TimeGenerated, Operation, Actor, Device, Telemetry, EventGroup, MatchBasis) by ObservedPath
| project LastSeen=TimeGenerated, ObservedPath, Operation, Actor, Device, Telemetry, EventGroup, MatchBasis
| top 35 by LastSeen desc
''',
  'trend': BASE + '''events
| summarize Created=countif(EventGroup=='Created'), Accessed=countif(EventGroup=='Access'),
            Modified=countif(EventGroup=='Modified'), Movement=countif(EventGroup=='Movement'),
            Copied=countif(EventGroup=='Copy'), Downloaded=countif(EventGroup=='Download'),
            Sharing=countif(EventGroup=='Sharing'), Other=countif(EventGroup !in ('Created','Access','Modified','Movement','Copy','Download','Sharing'))
    by bin(TimeGenerated, 1d)
| order by TimeGenerated asc
''',
  'timeline': BASE + '''events
| top 2500 by TimeGenerated desc
| project TimeGenerated, EventGroup, Operation, Actor, Telemetry, Device, SourcePath,
          DestinationPath, ObservedPath, MatchBasis, FileName, FileId,
          FileSHA1, FileSHA256, NetworkAddress, Process, EvidenceId, IdentityId, Notes
| order by TimeGenerated asc
''',
  'actors': BASE + '''events
| where isnotempty(Actor)
| summarize EventCount=count(), FirstObserved=min(TimeGenerated), LastObserved=max(TimeGenerated),
           Operations=make_set(Operation, 12), Locations=dcount(ObservedPath)
  by Actor, Telemetry
| order by EventCount desc
''',
  'moves': BASE + '''events
| where EventGroup in ('Movement','Copy') and isnotempty(SourcePath) and isnotempty(DestinationPath)
| where tolower(SourcePath) != tolower(DestinationPath)
| project TimeGenerated, Relationship=EventGroup, Actor, SourcePath, DestinationPath,
          Device, Telemetry, EvidenceId, FileId, MatchBasis
| order by TimeGenerated asc
''',
  'graph': BASE + '''let paths = materialize(
    union
       (events | project Path=SourcePath),
       (events | project Path=DestinationPath),
       (events | project Path=ObservedPath)
    | where isnotempty(Path)
    | summarize Calls=count() by Path
    | top 65 by Calls desc
);
let locationNodes = paths
| project Id=strcat('loc:',tolower(Path)), Name=iff(strlen(Path)>52, strcat('...',substring(Path,strlen(Path)-49)),Path),
          Kind='LOCATION', Calls, SourceId='', TargetId='', EdgeLabel='';
let actorNodes = events
| where isnotempty(Actor)
| summarize Calls=count() by Actor
| top 30 by Calls desc
| project Id=strcat('user:',tolower(Actor)), Name=Actor, Kind='IDENTITY', Calls, SourceId='', TargetId='', EdgeLabel='';
let movementEdges = events
| where EventGroup in ('Copy','Movement') and isnotempty(SourcePath) and isnotempty(DestinationPath)
| where tolower(SourcePath) != tolower(DestinationPath)
| where SourcePath in (paths | project Path) and DestinationPath in (paths | project Path)
| summarize Calls=count() by SourcePath, DestinationPath, EventGroup
| project Id='', Name='', Kind='', Calls, SourceId=strcat('loc:',tolower(SourcePath)),
          TargetId=strcat('loc:',tolower(DestinationPath)), EdgeLabel=EventGroup;
let activityEdges = events
| where isnotempty(Actor) and isnotempty(ObservedPath)
| where Actor in (actorNodes | project Name) and ObservedPath in (paths | project Path)
| summarize Calls=count() by Actor, ObservedPath, EventGroup
| top 160 by Calls desc
| project Id='', Name='', Kind='', Calls, SourceId=strcat('user:',tolower(Actor)),
          TargetId=strcat('loc:',tolower(ObservedPath)), EdgeLabel=EventGroup;
union locationNodes, actorNodes, movementEdges, activityEdges
''',
  'sources': '''union isfuzzy=true
(OfficeActivity | where TimeGenerated {TimeRange} | summarize Records=count() | extend Table='OfficeActivity'),
(DeviceFileEvents | where TimeGenerated {TimeRange} | summarize Records=count() | extend Table='DeviceFileEvents')
| project Table, Records
''',
}

def new_id(): return str(uuid.uuid4())
def md(label,text):
 return {'type':1,'content':{'json':text},'name':label}
def kql(label,title,filename,viz='grid',size=0):
 content={'version':'KqlItem/1.0','query':queries[filename],'size':size,'title':title,
          'timeContext':{'durationMs':0},'timeContextFromParameter':'TimeRange',
          'queryType':0,'resourceType':'microsoft.operationalinsights/workspaces',
          'crossComponentResources':['{Workspace}'],'visualization':viz}
 if viz=='grid':
  content['gridSettings']={'filter': True,'rowLimit':2500, 'formatters': []}
  content['exportToExcelOptions']='visible'
 if viz=='graph':
  content['graphSettings']={
    'type':0,'topContent':{'columnMatch':'Name','formatter':1,'formatOptions':{}},
    'centerContent':{'columnMatch':'Calls','formatter':12,'formatOptions':{},'numberFormat':{'unit':17,'options':{'style':'decimal','maximumFractionDigits':0}}},
    'bottomContent':{'columnMatch':'Kind','formatter':1,'formatOptions':{}},
    'nodeIdField':'Id','sourceIdField':'SourceId','targetIdField':'TargetId',
    'edgeLabel':'EdgeLabel','edgeSize':'Calls', 'nodeSize':None,'staticNodeSize':110,
    'colorSettings':{'type':1,'nodeColorField':'Kind','colorPalette':'pastel'},'hivesMargin':5}
 if viz=='linechart': content['graphSettings']={'type':0}
 return {'type':3,'content':content,'name':label}

params=[
    {'id':new_id(),'version':'KqlParameterItem/1.0','name':'Subscription','label':'Subscription','type':6,'isRequired':True,'value':'','typeSettings':{'additionalResourceOptions':[],'includeAll':False}},
    {'id':new_id(),'version':'KqlParameterItem/1.0','name':'Workspace','label':'Log Analytics workspace','type':5,'isRequired':True,
     'query':'resources | where type =~ "microsoft.operationalinsights/workspaces" | order by name asc | project id, name, group=resourceGroup',
     'crossComponentResources':['{Subscription}'],'value':'',
     'typeSettings':{'resourceTypeFilter':{'microsoft.operationalinsights/workspaces':True},'additionalResourceOptions':[]},
     'queryType':1,'resourceType':'microsoft.resourcegraph/resources'},
    {'id':new_id(),'version':'KqlParameterItem/1.0','name':'FilePath','label':'Exact file path or SharePoint URL','description':'Provide at least a folder and filename; full URL or C:\\...\\file.ext. No wildcard.','type':1,'isRequired':True,'value':''},
    {'id':new_id(),'version':'KqlParameterItem/1.0','name':'TimeRange','label':'Lookback','type':4,'isRequired':True,'value':{'durationMs':2592000000},'typeSettings':{'selectableValues':[{'durationMs':604800000},{'durationMs':1209600000},{'durationMs':2592000000},{'durationMs':5184000000},{'durationMs':7776000000},{'durationMs':15552000000}], 'allowCustom':True}}
]

items=[
md('intro','''# File Provenance | Microsoft 365 + Endpoint\n**Investigate a single file path:** observed identity activity, audit chronology, explicit file movements, and a relationship graph.\n\nSelect a **Subscription**, **Log Analytics workspace**, enter an **exact full path/URL**, and set a **Lookback**. All times are UTC. **No evidence does not mean no activity.**'''),
{'type':9,'content':{'version':'KqlParameterItem/1.0','parameters':params,'style':'above','queryType':0,'resourceType':'microsoft.operationalinsights/workspaces'},'name':'File investigation inputs'},
md('caveats','''> **Investigation scope:** Read-only. Uses `OfficeActivity` (SharePoint/OneDrive audit) and `DeviceFileEvents` (Sentinel-ingested Defender for Endpoint). Follows a *matching Microsoft 365 list item* across observed renames/moves where its identifier is populated; **does not prove descendant copies, track file contents, or verify current location**. Matching a historical path can return different file instances over time. The graph distinguishes observed movement edges from actor/activity edges.'''),
kql('coverage','Telemetry availability','sources'),
kql('summary','File investigation overview','summary'),
md('movement-title','''## 1. Movement and access relationship graph\n**Blue/other location nodes** represent observed file paths; **identity nodes** represent accounts. Edges are either recorded file moves/copies or account activities. A graph edge does **not** imply the latest/current location without a fresh inventory check. The graph limits high-volume data to keep it readable.'''),
kql('graph','Identity / file-location relationship graph','graph','graph',4),
md('latest-title','''## 2. Last observed locations\nThese are the latest appearances of each location in the searched logs, **not** an authoritative inventory of existing copies.'''),
kql('latest','Last seen file paths','latest','grid',0),
md('time-title','''## 3. Activity trend and detailed chronological timeline\nTrend shows counts per day, including audit operations such as accesses and modifications. Grid below lists **events from oldest to newest** (up to 2,500 most recent matching records). Some access events may be throttled or omitted by the telemetry source.'''),
kql('trend','File activity volume over time','trend','linechart',2),
kql('timeline','Chronological file activity and evidence (UTC)','timeline','grid',1),
md('move-title','''## 4. Explicit movement and copy records\nOnly source-to-destination transitions **present in recorded telemetry** are included. Download does not establish an endpoint destination. A rename is not a new content copy.'''),
kql('moves','Recorded moves and copies','moves','grid',0),
md('actor-title','''## 5. Accounts involved\nAn account in the log is the **recorded principal**, not conclusive human attribution. Entra sign-in enrichment is not joined in this v1 view.'''),
kql('actors','Actor overview','actors','grid',0),
md('notes','''---\n### Interpretive guidance\n- `PATH_MATCH`: event relates directly to the path/URL supplied. `SAME_M365_ITEM_ID`: the Microsoft 365 item identifier links an event to a directly matched event.\n- **File path is not a globally stable ID.** Different files can occupy the same path at different times. Copies often get new IDs; hashes are supporting evidence, not provenance proof.\n- **MDE does not guarantee a read/open event for every access**. Audit collection, permissions, licences, connectors and retention determine visibility.\n- The evidence table retains event references for checking each transition in the source systems.\n- **Operational improvement:** enrich this read-only workbook with Microsoft Graph `driveId/itemId`, version history, current item metadata, endpoint inventory, and Entra sign-in context via a separate evidence-correlation pipeline.\n\nSource documentation: Microsoft Learn `OfficeActivity`, `DeviceFileEvents`, and Azure Workbook graph visualisations.''')
]
workbook={'version':'Notebook/1.0','items':items,'isLocked':False,'$schema':'https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json'}
p=(OUT/'Azure_File_Provenance.workbook')
p.write_text(json.dumps(workbook,ensure_ascii=False,indent=2),encoding='utf-8')
(OUT/'Azure_File_Provenance.json').write_text(json.dumps(workbook,ensure_ascii=False,indent=2),encoding='utf-8')
for n,q in queries.items(): (OUT/f'FileProvenance_{n}.kql').write_text(q,encoding='utf-8')
readme='''# Azure File Provenance Workbook (v1.0)\n\n## Files\n- `Azure_File_Provenance.workbook` / `.json`: Same native **Azure Monitor Workbook gallery JSON** for Advanced Editor import (not an ARM deployment template).\n- `FileProvenance_*.kql`: Individual editable query sources.\n\n## Import\n1. Open **Azure portal > Microsoft Sentinel > [workspace] > Workbooks > Add workbook** (or Azure Monitor > Workbooks > New).\n2. Click **Edit > Advanced Editor**, replace the JSON with `Azure_File_Provenance.json`. Choose the **Gallery Template** / serialized **workbook JSON** editor rather than ARM template deployment. Apply, save.\n3. Select Subscription and Log Analytics workspace from the workbook picker; enter full source file path/SharePoint URL and time range.\n4. Verify that **OfficeActivity** and/or **DeviceFileEvents** exists in the selected workspace. For each desired table, enable the appropriate data connectors/ingestion. Run `OfficeActivity | take 5` and `DeviceFileEvents | take 5` separately from Logs to verify access.\n\n## Example inputs\n- `https://contoso.sharepoint.com/sites/Finance/Shared Documents/Q4.xlsx`\n- `C:\\Users\\analyst\\Documents\\Q4.xlsx`\n- `C:\\Files\\Reports\\report.pdf`\n\n## Scope and constraints\n- Works on events already collected into one selected Sentinel/Log Analytics workspace. The workbook does not retrieve Microsoft Graph file metadata or call Entra APIs directly.\n- `PATH_MATCH` searches provided full path, URL, and suffix matches for hosted relative paths. Requires folder + file, not basename alone. A filename or content hash is **not** assumed to prove file lineage.\n- `SAME_M365_ITEM_ID` follows an M365 list-item key when the source event contains it; new copies with new IDs are **not followed automatically** beyond an explicit recorded move/copy edge. Moves/copies show reported destinations, not verified live inventory.\n- MDE events can contain the prior path in `PreviousFolderPath`, but this is not assured for all events; it does not track endpoint file identity across every rename.\n- Some M365 `FileAccessed` audit events are suppressed/deduplicated; MDE does not record all read accesses; missing events and retention gaps remain.\n- All times UTC and raw audit properties are displayed; no write/delete/response action.\n- Graph displays up to 65 location nodes, 30 identity nodes and 160 actor/activity edges. Movement edges outside selected nodes will be omitted from graph but retained in movement grid.\n- Advanced Editor and Graph Settings may differ across tenants. If the Graph is blank despite matching results, open its **Graph Settings** and confirm Node ID=`Id`, Source ID=`SourceId`, Target ID=`TargetId`, edge label=`EdgeLabel`, Node color=`Kind`.\n- `union isfuzzy=true` tolerates one absent table (assuming at least one table resolves). If neither table exists, queries fail until telemetry is configured.\n- **Not live-tenant tested**: JSON structure and expected columns were statically validated only.\n\n## Security and performance\n- Limit workspace visibility to authorised analysts: file names, URL paths, actors and IP addresses may be sensitive.\n- Keep time range narrow where possible. Searches across large OfficeActivity tables are expensive; for production use indexed normalized provenance events and stable object IDs.\n- Workbooks expand parameter placeholders at query time. The query uses `{FilePath:escape}` to escape quote characters for KQL; do not strip this qualifier.\n\n## Sources\n- https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-graph-visualizations\n- https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-parameters\n- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity\n- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicefileevents\n'''
(OUT/'README_Azure_File_Provenance.md').write_text(readme,encoding='utf-8')
with zipfile.ZipFile(OUT/'Azure_File_Provenance_Package.zip','w',compression=zipfile.ZIP_DEFLATED) as z:
 for x in [p,OUT/'Azure_File_Provenance.json',OUT/'README_Azure_File_Provenance.md',OUT/'build_file_provenance.py',*[OUT/f'FileProvenance_{n}.kql' for n in queries]]:
  z.write(x,x.name)
# Static validation / sanity
check=json.loads(p.read_text())
assert check['version']=='Notebook/1.0'
assert sum(it['type']==3 for it in check['items'])==len(queries)
assert set(re.findall(r'\{(\w+):escape\}',BASE))=={'FilePath'}
assert all(it['content'].get('crossComponentResources')==['{Workspace}'] for it in check['items'] if it['type']==3)
assert all(it['content'].get('visualization') in ('grid','graph','linechart') for it in check['items'] if it['type']==3)
assert all('union isfuzzy=true' in q or name=='sources' for name,q in queries.items())
print('Workbook items:',len(items),'queries:',len(queries),'size:',p.stat().st_size)
for x in [p, OUT/'Azure_File_Provenance_Package.zip', OUT/'README_Azure_File_Provenance.md']:
 print(x.name, x.stat().st_size)
