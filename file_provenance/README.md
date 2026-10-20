# File Provenance Workbook v3 — Email and File Transfers

**Status: Tested offline with synthetic telemetry; NOT live-validated against a Microsoft 365 tenant or Sentinel workspace.**

This extends v2 Preserve Evidence with **email attachment observations, mail routing and delivery status, cloud application uploads/downloads, and endpoint file-origin/download activity**.

## Deliverables

- `Azure_File_Provenance_v3.json` / `.workbook` — importable Azure Monitor / Microsoft Sentinel workbook format.
- `FileProvenance_v3_*.kql` — 9 standalone investigation queries, all using the same normalization and matching logic.
- `common.kql` — exact shared KQL prefix used by both the workbook and the evidence backend.
- `forensics.py`, `portal.py`, `requirements.txt` — v3 Entra-protected evidence-preservation workflow, PDFs, SHA-256 manifest, AES-256 ZIP (pyzipper) + Key Vault + Blob upload (as in v2).
- `examples/demo_events.json` and `examples/preview` — synthetic demonstration only.
- `tests.py` — offline code and report checks.

## New data sources and interpretation

| Log Analytics table | Feature | What it proves | What it does not prove |
|---|---|---|---|
| `OfficeActivity` | SharePoint/OneDrive file move/copy/upload/download | Operation recorded on service item | Endpoint the user downloaded to; all future copies |
| `DeviceFileEvents` | Local file creation, rename, modification, and origin URL on supported events | An endpoint file operation, sometimes recorded URL-of-origin | Every browser upload or every file read |
| `CloudAppEvents` | MDCA observed file upload/download | An activity recorded by connected cloud-app provider | Exact bytes/recipient unless corroborated; off-network transfers |
| `EmailAttachmentInfo` | Attachment name, size, message ID and sometimes hash | Attachment processed by Microsoft Defender for Office 365 | Message delivery, opening, or attachment's source file identity |
| `EmailEvents` | Direction, mail sender/recipient, mail delivery disposition | Message routing/delivery reported by the service | Recipient opened/saved attachment; source document lineage |

See the Microsoft Defender XDR data connector instructions for these five tables. They must actually be **streamed to the same Log Analytics workspace** as the workbook. Availability in the Defender advanced-hunting portal alone **does not** make the data available to the workbook automatically.

If a table is missing, the `union isfuzzy=true` data queries may warn/ignore that branch; review the **Telemetry availability** view and independently confirm ingestion. If all target sources are absent, a query can fail.

### Correlation methodology

1. Enter **full file path or SharePoint/OneDrive URL** in `FilePath` and select a time range.
2. Optionally enter a **40-hex SHA-1 / 64-hex SHA-256** in `FileHash` to corroborate matching content where the source provides a digest.
3. The workbook finds records matching the exact path, SharePoint item ID, or optional hash. For `EmailAttachmentInfo` and `CloudAppEvents` it also discovers **filename-only candidates** (not confirmed matches).
4. `EmailEvents` are linked to attachment candidates by `NetworkMessageId` — message-level correlation, **not** proof the email attachment was derived from the original SharePoint document.
5. Delivery statuses (`Delivered`, `Blocked`, etc.) remain individual events. A processed attachment + blocked message is **not a successful transfer**. Even delivered mail does not prove the recipient opened or downloaded its attachment.
6. The relationship graph connects observed file move/copy/download edges and (separately labelled) selected message-routing edges. No fabricated endpoint destination is created for a cloud download without endpoint evidence.

**MatchBasis / EvidenceStrength definitions**

- `PATH_MATCH` / `OBSERVED_PATH`: observed activity refers to the target path.
- `SAME_M365_ITEM_ID` / `SAME_ITEM`: SharePoint/OneDrive same-list-item match within observed logs.
- `HASH_MATCH_CONTENT_ONLY` / `MATCHING_BYTES_NOT_LINEAGE`: recorded digest matches optional hash; origin and transfer are **not** proven by the digest alone.
- `FILENAME_CANDIDATE` / `CANDIDATE_ONLY`: a same-named email attachment or cloud file; could be unrelated.
- `MESSAGE_ID_LINK_TO_CANDIDATE` / `MESSAGE_LINK_NOT_FILE_LINEAGE`: email message record relates to a candidate attachment's `NetworkMessageId`.

**Avoid misclassification:** an identical filename, an approximate timestamp or even identical hashes cannot by themselves establish that one file was sent from a specific source path. Treat email and cloud events as **candidates pending confirmation**, unless additional acquisition and correlation evidence exists. Endpoint HTTP/network connection logs without file identity must not be translated into a particular file upload event.

## Workbook installation

1. Open **Microsoft Sentinel > Workbooks** in the appropriate portal experience (or Azure Monitor > Workbooks), add a workbook and choose **Edit → Advanced Editor**.
2. Paste the JSON from `Azure_File_Provenance_v3.json`; apply and save.
3. Select the subscription, **Log Analytics workspace**, file URL/path, optional hash and time range.
4. Run the `Telemetry availability` panel first. Next review **Relationship graph**, **Chronological events**, **Recorded movement**, **Email transfer investigations** and **Cloud/endpoint upload/download** grids.
5. If your deployment keeps Defender events in Defender XDR only, **enable the corresponding event streaming** to Sentinel's Log Analytics workspace; do not assume an Azure Workbook directly queries Defender hunting-only records.

## Preserve Evidence backend

The **Preserve Evidence** action continues to open a placeholder URL. Deploy the backend first and replace:

`https://REPLACE-WITH-YOUR-PROTECTED-PORTAL.example/preserve`

with your actual Entra-protected preservation portal URL, **not** a public anonymous endpoint. The review form accepts the same full file path and optional hash. It re-queries the configured Log Analytics workspace and preserves `RawRecord` plus normalized fields, `EmailSender`, `EmailRecipient`, `MessageId`, `DeliveryStatus`, `TransferDirection`, `Application`, `MatchBasis`, and `EvidenceStrength` in JSON/CSV. The updated forensic PDF includes a separate email/transfer findings section; the Chain of Custody PDF and SHA-256 manifest use the same v2 preservation model.

Required App Service environment settings, in addition to App Service Authentication with Entra:

- `ALLOWED_OPERATOR_OIDS` — authorized investigator Entra object IDs; blank = deny all.
- `PORTAL_CSRF_SECRET` — high-entropy CSRF signing secret (40+ chars).
- `EVIDENCE_WORKSPACE_ID` — Log Analytics workspace GUID.
- `EVIDENCE_ACCOUNT_URL` — `https://<storage>.blob.core.windows.net`.
- `EVIDENCE_CONTAINER` — restricted evidence container with separately confirmed retention/immutability policy.
- `EVIDENCE_KEYVAULT_URL` — private Key Vault URL.

Use least-privilege managed identities, TLS, private networking/ingress restrictions, storage immutability/legal hold where required, and separate authorization for vault secrets. The ZIP contains **log snapshots only**, not the original file content or mailbox message binary. **Do not assert original-file acquisition or a verified source-to-recipient file chain without separate evidence.**

The archival workflow relies on `pyzipper` for AES-256 WinZip encryption. If unavailable, it **fails closed** without generating a weak or unencrypted archive. The offline test does not demonstrate a successful AES ZIP here. In production, install `requirements.txt` and perform a real encrypted ZIP write/readback test before use.

To test locally using synthetic data (without Azure access):

```bash
python tests.py
python forensics.py \
  --events-json examples/demo_events.json \
  --case-id DFIR-DEMO-003 \
  --file-path 'https://contoso.sharepoint.com/sites/Finance/Shared Documents/Drafts/Financial-Report.xlsx' \
  --collector 'Demo Examiner' \
  --purpose 'Synthetic email/cloud transfer demonstration' \
  --start-utc '2026-10-01T00:00:00Z' \
  --end-utc '2026-10-20T10:00:00Z' \
  --output-dir examples/preview --demo-documents-only
```

Production readiness is **not** established by these offline tests. Validate table mappings/action values, workbook rendering, workspace permissions, event latency, audit licensing/retention, email delivery semantics, and Blob/Key Vault operations against your real environment. The automatic forensic PDF is an **examiner-review draft**, and Chain of Custody records actual collection and only subsequent documented transfers, not hypothetical or pre-signed events.

## Official references

- [Stream Microsoft Defender XDR events to Sentinel / Log Analytics](https://learn.microsoft.com/en-us/azure/sentinel/connect-microsoft-365-defender)
- [EmailAttachmentInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table)
- [EmailEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table)
- [CloudAppEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-cloudappevents-table)
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- [Purview audited file activities](https://learn.microsoft.com/en-us/purview/audit-log-activities)
- [Azure Workbooks link actions](https://learn.microsoft.com/en-us/azure/azure-monitor/visualize/workbooks-link-actions)
