"""Build a fake Windows 11 triage tree that references C:\\Users\\max\\Downloads\\invoice.exe"""
import os, struct, sqlite3, uuid, json, sys
R = sys.argv[1]
def mk(*p): d=os.path.join(R,*p); os.makedirs(os.path.dirname(d), exist_ok=True); return d
FT = lambda y: int(((__import__('datetime').datetime(y,6,1,12,0,0)-__import__('datetime').datetime(1601,1,1)).total_seconds())*10**7)
T = r"C:\Users\max\Downloads\invoice.exe"

# the file itself
open(mk("Users","max","Downloads","invoice.exe"),"wb").write(b"MZ"+b"\0"*58+struct.pack("<I",64)+b"PE\0\0"+struct.pack("<HHI",0x8664,3,1700000000)+b"\0"*12+struct.pack("<H",0x22)+struct.pack("<H",0x20b)+b"\0"*66+struct.pack("<H",2)+b"\0"*400)

# prefetch v30 (uncompressed)
d=bytearray(0x400)
struct.pack_into("<I4s",d,0,30,b"SCCA"); d[0x10:0x10+22]="INVOICE.EXE".encode("utf-16le")
struct.pack_into("<I",d,0x4C,0x1A2B3C4D); struct.pack_into("<I",d,0x54,0x130)
for i in range(3): struct.pack_into("<Q",d,0x80+8*i,FT(2026-i))
struct.pack_into("<I",d,0xD0,7)
names="\\VOLUME{01d9}\\USERS\\MAX\\DOWNLOADS\\INVOICE.EXE\0\\VOLUME{01d9}\\WINDOWS\\SYSTEM32\\NTDLL.DLL\0".encode("utf-16le")
struct.pack_into("<II",d,0x64,0x200,len(names)); d[0x200:0x200+len(names)]=names
open(mk("Windows","Prefetch","INVOICE.EXE-1A2B3C4D.pf"),"wb").write(d)
# a second prefetch where another program loads the target
d2=bytearray(d); d2[0x10:0x10+60]=b"\0"*60; d2[0x10:0x10+12]="7Z.EXE".encode("utf-16le")
open(mk("Windows","Prefetch","7Z.EXE-11111111.pf"),"wb").write(d2)

# PCA
open(mk("Windows","appcompat","pca","PcaAppLaunchDic.txt"),"wb").write(("\ufeff"+T+"|2026-06-01 12:00:05.123\r\nC:\\Windows\\notepad.exe|2026-01-01 00:00:00.000\r\n").encode("utf-16le"))
open(mk("Windows","appcompat","pca","PcaGeneralDb0.txt"),"wb").write(("2026-06-01 12:00:06.000|2|%USERPROFILE%\\downloads\\invoice.exe|Invoice viewer|Evil Corp|1.0.0.0|0006abc|0\r\n").encode("utf-16le"))

# LNK with LinkInfo + string data + tracker
def lnk(target):
    flags=0x2|0x4|0x80
    hdr=struct.pack("<I16sII3QIIIH10x",0x4C,uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le,flags,0x20,FT(2026),FT(2026),FT(2026),12345,0,1,0)
    vol=struct.pack("<4I",16+5,3,0xDEADBEEF,16)+b"OS\0\0\0"
    lbp=target.encode()+b"\0"; cps=b"\0"
    hs=0x1C; vo=hs; lo=vo+len(vol); co=lo+len(lbp)
    li=struct.pack("<7I",0,hs,1,vo,lo,0,co)+vol+lbp+cps
    li=struct.pack("<I",len(li))+li[4:]
    name="Invoice"; sd=struct.pack("<H",len(name))+name.encode("utf-16le")
    fid=uuid.uuid1(node=0x0050569a1b2c)
    trk=struct.pack("<IIII",0x60,0xA0000003,0x58,0)+b"desktop-max01\0\0\0"+uuid.uuid4().bytes_le+fid.bytes_le+uuid.uuid4().bytes_le+fid.bytes_le
    return hdr+li+sd+trk+struct.pack("<I",0)
L=lnk(T)
open(mk("Users","max","AppData","Roaming","Microsoft","Windows","Recent","invoice.exe.lnk"),"wb").write(L)
open(mk("Users","max","AppData","Roaming","Microsoft","Windows","Recent","CustomDestinations","5d696d521de238c3.customDestinations-ms"),"wb").write(b"\x02\0\0\0junk"+L+b"\xab\xfb\xbf\xba")

# Recycle bin $I v2 for a deleted copy
nm=r"C:\Users\max\Desktop\invoice.exe"+"\0"
open(mk("$Recycle.Bin","S-1-5-21-1-2-3-1001","$IAB12CD.exe"),"wb").write(struct.pack("<QQQI",2,12345,FT(2026),len(nm))+nm.encode("utf-16le"))
open(mk("$Recycle.Bin","S-1-5-21-1-2-3-1001","$RAB12CD.exe"),"wb").write(b"MZ...")

# Chrome history
db=sqlite3.connect(mk("Users","max","AppData","Local","Google","Chrome","User Data","Default","History"))
db.executescript("""create table downloads(id integer, target_path text, current_path text, start_time int, end_time int, received_bytes int, total_bytes int, state int, danger_type int, interrupt_reason int, opened int, last_access_time int, referrer text, tab_url text, tab_referrer_url text, mime_type text, original_mime_type text, site_url text, by_ext_name text);
create table downloads_url_chains(id int, chain_index int, url text);
create table urls(id int, url text, title text, visit_count int, last_visit_time int);""")
wk=FT(2026)//10
db.execute("insert into downloads values(1,?,?,?,?,12345,12345,1,0,0,1,?,'https://mail.example.com/','https://mail.example.com/inbox','', 'application/x-msdownload','','https://evil.example','')",(T,T,wk,wk+5_000_000,wk+9_000_000))
db.execute("insert into downloads_url_chains values(1,0,'https://bit.ly/x'),(1,1,'https://evil.example/invoice.exe')".replace("),(","),(") if False else "insert into downloads_url_chains values(1,0,'https://evil.example/dl/invoice.exe')")
db.execute("insert into urls values(1,'file:///C:/Users/max/Downloads/invoice.exe','',1,?)",(wk,)); db.commit(); db.close()

# Firefox
db=sqlite3.connect(mk("Users","max","AppData","Roaming","Mozilla","Firefox","Profiles","abc.default","places.sqlite"))
db.executescript("create table moz_places(id int, url text, title text, visit_count int, last_visit_date int); create table moz_annos(id int, place_id int, anno_attribute_id int, content text, dateAdded int, lastModified int); create table moz_anno_attributes(id int, name text);")
db.execute("insert into moz_places values(1,'https://cdn.example/invoice.exe','',1,1780000000000000)")
db.execute("insert into moz_anno_attributes values(1,'downloads/destinationFileURI')")
db.execute("insert into moz_annos values(1,1,1,'file:///C:/Users/max/Downloads/invoice.exe',1780000000000000,0)"); db.commit(); db.close()

# ActivitiesCache
db=sqlite3.connect(mk("Users","max","AppData","Local","ConnectedDevicesPlatform","L.max","ActivitiesCache.db"))
db.execute("create table Activity(Id blob, AppId text, Payload blob, ActivityType int, StartTime int, EndTime int, LastModifiedTime int, PlatformDeviceId text)")
db.execute("insert into Activity values(x'00',?,?,5,1780000000,1780000100,1780000100,'dev')",(json.dumps([{"application":T,"platform":"x_exe_path"}]), json.dumps({"displayText":"invoice.exe","appDisplayName":"invoice.exe"}).encode()))
db.commit(); db.close()

# Windows.db search index
db=sqlite3.connect(mk("ProgramData","Microsoft","Search","Data","Applications","Windows","Windows.db"))
db.executescript("create table SystemIndex_1_PropertyStore_Metadata(Id int, UniqueKey text); create table SystemIndex_1_PropertyStore(WorkId int, ColumnId int, Value blob);")
db.executemany("insert into SystemIndex_1_PropertyStore_Metadata values(?,?)",[(1,"4-System_ItemPathDisplay"),(2,"5-System_DateModified"),(3,"6-System_Size")])
db.executemany("insert into SystemIndex_1_PropertyStore values(?,?,?)",[(77,1,T.encode("utf-16le")),(77,2,struct.pack("<Q",FT(2026))),(77,3,12345),(78,1,"C:\\other\\a.txt".encode("utf-16le"))])
db.commit(); db.close()

# Scheduled task (UTF-16)
open(mk("Windows","System32","Tasks","Updater"),"wb").write(('\ufeff<?xml version="1.0" encoding="UTF-16"?><Task><RegistrationInfo><Date>2026-06-01T12:01:00</Date><Author>max</Author><URI>\\Updater</URI></RegistrationInfo><Actions><Exec><Command>'+T+'</Command><Arguments>-silent</Arguments></Exec></Actions></Task>').encode("utf-16le"))

# Defender MPLog
open(mk("ProgramData","Microsoft","Windows Defender","Support","MPLog-20260101-000000.log"),"wb").write(("\ufeff2026-06-01T12:00:10.123Z DETECTION Trojan:Win32/Fake file:"+T+"\r\n2026-06-01T12:00:11Z unrelated\r\n").encode("utf-16le"))

# Notepad TabState
open(mk("Users","max","AppData","Local","Packages","Microsoft.WindowsNotepad_8wekyb3d8bbwe","LocalState","TabState","abc.bin"),"wb").write(b"NP\0\x01"+T.encode("utf-16le")+b"\0\0junk")
# startup lnk
open(mk("Users","max","AppData","Roaming","Microsoft","Windows","Start Menu","Programs","Startup","upd.lnk"),"wb").write(L)
print("fixture at", R)
