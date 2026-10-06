# win11_file_forensics.py

Give the script a file path or a file name. It searches Windows 11 artifacts for every mention of that file. It writes three reports:

- `report.html`: findings grouped by artifact, plus a timeline.
- `report.json`: the full data, for use in a SIEM or SOAR tool.
- `timeline.csv`: a UTC timeline you can load into Timeline Explorer.

```powershell
pip install -r requirements.txt

# Live system. Run from an elevated prompt; without admin some artifacts are skipped.
python win11_file_forensics.py "C:\Users\max\Downloads\invoice.exe"
python win11_file_forensics.py invoice.exe                    # search by name only
python win11_file_forensics.py "C:\Users\max\Downloads\invoice.exe" --deep-registry

# Offline: a mounted image, KAPE output or triage copy. Give the path as it was on the original system.
python win11_file_forensics.py "C:\Users\max\Downloads\invoice.exe" --root F:\ --out case42

python win11_file_forensics.py --list-modules
python win11_file_forensics.py X --modules prefetch,amcache,eventlogs --skip usn
```

The script never changes the evidence. If a file is locked (registry hives, Amcache, browser databases, Windows.db), it copies the file to a temp folder first. When the file can't be read directly it uses a VSS snapshot (`esentutl /y /vss`). Use `--no-vss` to turn that off.

## What it checks

| Category | Module | Artifact | What it tells you |
|---|---|---|---|
| File system | `filesystem` | stat, MD5/SHA-1/SHA-256, file signature, PE header and version info, owner/ACL, Authenticode | Identity of the file. Flags an extension that doesn't match the content, and a renamed or disguised binary (OriginalFilename differs). |
| | `ads` | Alternate data streams, Zone.Identifier | Mark-of-the-Web: zone, HostUrl and ReferrerUrl show where it was downloaded from. |
| | `mft` | $MFT record (FSCTL_GET_NTFS_FILE_RECORD) | Compares $SI and $FN times to detect timestomping (SI earlier than FN, or whole-second times). Also lists hard links and streams. |
| | `usn` | $UsnJrnl:$J | History of creates, renames, overwrites and deletes. Follows the MFT entry across renames. |
| | `vss` | Volume Shadow Copies | Earlier versions of the file, with hashes compared against the current one. |
| Execution | `prefetch` | `C:\Windows\Prefetch\*.pf` (decompressed with ntdll) | Run count and last 8 run times. Also shows other programs that loaded the file. |
| | `pca` | `PcaAppLaunchDic.txt`, `PcaGeneralDb*.txt` (Windows 11 22H2 and later) | Launch times, including for files run from removable or deleted locations. |
| | `amcache` | Amcache.hve InventoryApplicationFile, DriverBinary, Shortcut | SHA-1, publisher, version, link date, first seen. Also matches by hash, so it finds the file even if it was renamed. |
| | `shimcache` | AppCompatCache | Proves the file existed, with its last-modified time and cache position. On Windows 10/11 this does not prove execution. |
| | `bam` | BAM/DAM UserSettings | Last execution time for each user SID. |
| | `userassist` | UserAssist (decoded from ROT13, known-folder GUIDs resolved) | GUI launches, run count, focus time, last run. |
| User activity | `mru` | RecentDocs, OpenSavePidlMRU / LastVisitedPidlMRU (paths rebuilt from PIDLs), Office File MRU, RunMRU, TypedPaths, WordWheelQuery, MuiCache, PCA Store, Layers, FeatureUsage, RDP | Opened, saved, searched for, or run by the user. |
| | `shellbags` | BagMRU in UsrClass and NTUSER | The user browsed the file's folder in Explorer. |
| | `lnk` | Recent, Office Recent, Desktop and Start Menu `.lnk` files | Target times and size, volume serial and label, network share, MachineID, MAC address (from the DROID). |
| | `jumplists` | AutomaticDestinations (DestList plus link streams), CustomDestinations | Which app opened the file, access count, pinned state, last access. |
| | `recyclebin` | `$Recycle.Bin\<SID>\$I*` | Original path, size, deletion time, and whether the `$R` copy can be recovered. |
| | `search` | Windows Search `Windows.db` (Windows 11 SQLite) | Every indexed property of the file. |
| | `timeline` | ActivitiesCache.db | Activity history (only if the database exists). |
| | `notepad` | Windows 11 Notepad TabState | Files open in Notepad tabs, including unsaved ones. |
| Origin | `browsers` | Chrome, Edge, Brave, Vivaldi, Opera downloads and redirect chain; `file://` history; Firefox downloads | Download URL, referrer, redirect chain, danger type, whether it was opened. |
| Logs | `eventlogs` | Sysmon 1/11/23…, Security 4688/4663/4698/5145, Defender 1116/1117, PowerShell 4104, System 7045, TaskScheduler, AppLocker, CodeIntegrity, BITS, WMI, Shell-Core, app crashes | Process creation, file creation and deletion, detections, script blocks, installs. |
| | `defender` | MPLog, DetectionHistory | Defender scans and detections. |
| Persistence | `persistence` | Run/RunOnce, services, IFEO/SilentProcessExit, Winlogon, AppInit, Active Setup, CLSID, scheduled task XML, Startup folders, WMI repository | Whether the file is set up to start automatically. |
| | `deepreg` (opt-in) | Every string in every registry hive | Catch-all search. Slow. |

Each finding is tagged with how it matched. **path** means the full path matched. **hash** means the SHA-1 matched in Amcache. **name** means only the file name matched, so it could be a different file with the same name.

## Requirements and limitations
- **Live mode:** needs Windows and Python 3.9 or later. Run as Administrator for $MFT, USN, VSS, the Security log, other users' profiles and locked files.
- **Offline mode on Linux or macOS:** works for every file-based module. Event logs need `python-evtx`. Windows 10/11 compressed prefetch needs `dissect.util`. The $MFT, USN, ADS and VSS modules need Windows; for an image, run MFTECmd on the image instead.
- **Testing so far:** the parsers and every file and registry module passed against a synthetic Windows 11 test tree (see `tests/`). The Win32 parts have **not** been run on a real Windows 11 machine yet: ctypes FSCTLs, OpenFileById, FindFirstStreamW, ntdll decompression, wevtutil, esentutl, and the PowerShell ACL and signature calls. Run it on a test VM before using it in a case.
- **Unconfirmed layouts:** the DestList v3/v4 offsets, the Windows.db schema and the two prefetch v30 variants follow public research, not Microsoft documentation. If a build changes them, the script logs an error and moves on.
- **Not covered:** SRUM (`SRUDB.dat`, an ESE database), $LogFile, $I30 slack, thumbcache, RDP bitmap cache, the Edge/Chrome cache, and decryption of Defender quarantine entries.
- **Registry transaction logs:** these are replayed with regipy when present. Without them, a hive copied from a running system may be slightly out of date.
