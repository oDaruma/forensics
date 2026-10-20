# Azure File Provenance Workbook (v1.0)

## Files
- `Azure_File_Provenance.workbook` / `.json`: Same native **Azure Monitor Workbook gallery JSON** for Advanced Editor import (not an ARM deployment template).
- `FileProvenance_*.kql`: Individual editable query sources.

## Import
1. Open **Azure portal > Microsoft Sentinel > [workspace] > Workbooks > Add workbook** (or Azure Monitor > Workbooks > New).
2. Click **Edit > Advanced Editor**, replace the JSON with `Azure_File_Provenance.json`. Choose the **Gallery Template** / serialized **workbook JSON** editor rather than ARM template deployment. Apply, save.
3. Select Subscription and Log Analytics workspace from the workbook picker; enter full source file path/SharePoint URL and time range.
4. Verify that **OfficeActivity** and/or **DeviceFileEvents** exists in the selected workspace. For each desired table, enable the appropriate data connectors/ingestion. Run `OfficeActivity | take 5` and `DeviceFileEvents | take 5` separately from Logs to verify access.

## Example inputs
- `https://contoso.sharepoint.com/sites/Finance/Shared Documents/Q4.xlsx`
- `C:\Users\analyst\Documents\Q4.xlsx`
- `C:\Files\Reports\report.pdf`

## Scope and constraints
- Works on events already collected into one selected Sentinel/Log Analytics workspace. The workbook does not retrieve Microsoft Graph file metadata or call Entra APIs directly.
- `PATH_MATCH` searches provided full path, URL, and suffix matches for hosted relative paths. Requires folder + file, not basename alone. A filename or content hash is **not** assumed to prove file lineage.
- `SAME_M365_ITEM_ID` follows an M365 list-item key when the source event contains it; new copies with new IDs are **not followed automatically** beyond an explicit recorded move/copy edge. Moves/copies show reported destinations, not verified live inventory.
- MDE events can contain the prior path in `PreviousFolderPath`, but this is not assured for all events; it does not track endpoint file identity across every rename.
- Some M365 `FileAccessed` audit events are suppressed/deduplicated; MDE does not record all read accesses; missing events and retention gaps remain.
- All times UTC and raw audit properties are displayed; no write/delete/response action.
- Graph displays up to 65 location nodes, 30 identity nodes and 160 actor/activity edges. Movement edges outside selected nodes will be omitted from graph but retained in movement grid.
- Advanced Editor and Graph Settings may differ across tenants. If the Graph is blank despite matching results, open its **Graph Settings** and confirm Node ID=`Id`, Source ID=`SourceId`, Target ID=`TargetId`, edge label=`EdgeLabel`, Node color=`Kind`.
- `union isfuzzy=true` tolerates one absent table (assuming at least one table resolves). If neither table exists, queries fail until telemetry is configured.
- **Not live-tenant tested**: JSON structure and expected columns were statically validated only.

## Security and performance
- Limit workspace visibility to authorised analysts: file names, URL paths, actors and IP addresses may be sensitive.
- Keep time range narrow where possible. Searches across large OfficeActivity tables are expensive; for production use indexed normalized provenance events and stable object IDs.
- Workbooks expand parameter placeholders at query time. The query uses `{FilePath:escape}` to escape quote characters for KQL; do not strip this qualifier.

## Sources
- https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-graph-visualizations
- https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-parameters
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/devicefileevents
