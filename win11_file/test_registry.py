import struct, sys, datetime as dt, json, types
sys.path.insert(0, '.')
import win11_file_forensics as w

FT = lambda y: int(((dt.datetime(y,6,1,12)-dt.datetime(1601,1,1)).total_seconds())*10**7)
class K:
    def __init__(s, path, vals=None, subs=None, lw=2026):
        s.path=path; s.name=path.split('\\')[-1]; s._v=vals or {}; s._s={}; s.lastwrite=w.ft2dt(FT(lw))
        for n,k in (subs or {}).items(): s.add(n,k)
    def add(s, n, k): k.path=s.path+'\\'+n; k.name=n; s._s[n.lower()]=k; [k.add(c.name,c) for c in list(k._s.values())]; return k
    def child(s, n): return s._s.get(n.lower())
    def subkeys(s): return iter(list(s._s.values()))
    def values(s):
        for n,v in s._v.items(): yield n, v, (3 if isinstance(v,bytes) else 1)
    def value(s,n): return s._v.get(n)
class R:
    def __init__(s, root, label): s.root=root; s.label=label
    def key(s, rel=''):
        k=s.root
        for p in [x for x in rel.split('\\') if x]:
            k=k.child(p)
            if not k: return None
        return k
def tree(spec):
    root=K('')
    for path,vals in spec.items():
        k=root
        for p in path.split('\\'):
            k = k.child(p) or k.add(p, K(p))
        k._v.update(vals)
    return root

T=r"C:\Users\max\Downloads\invoice.exe"
# ShimCache Win10 format
def shim(paths):
    b=bytearray(struct.pack('<I',0x34)+b'\0'*0x30)
    for p in paths:
        pb=p.encode('utf-16le'); ent=struct.pack('<H',len(pb))+pb+struct.pack('<QI',FT(2025),4)+struct.pack('<I',1)
        b+=b'10ts'+struct.pack('<II',0,len(ent))+ent
    return bytes(b)
system=R(tree({
 'Select':{'Current':1},
 r'ControlSet001\Control\Session Manager\AppCompatCache':{'AppCompatCache':shim([r'C:\Windows\notepad.exe',T])},
 r'ControlSet001\Services\bam\State\UserSettings\S-1-5-21-1-2-3-1001':{r'\Device\HarddiskVolume3\Users\max\Downloads\invoice.exe':struct.pack('<Q',FT(2026))+b'\0'*16,'Version':1},
 r'ControlSet001\Services\EvilSvc':{'ImagePath':T+' -svc'},
}),'SYSTEM')
software=R(tree({
 r'Microsoft\Windows\CurrentVersion\Run':{'Updater':'"'+T+'" /q'},
 r'Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-1-2-3-1001':{'ProfileImagePath':r'C:\Users\max'},
}),'SOFTWARE')

# shell items
def root_item(guid): import uuid; return struct.pack('<HBB',20,0x1F,0x50)+uuid.UUID(guid).bytes_le
def vol_item(s): b=s.encode()+b'\0'; b=b+b'\0'*(22-len(b)); return struct.pack('<HB',3+len(b),0x2F)+b
def file_item(name, t=0x31):
    short=(name.upper()[:8]).encode()+b'\0'
    if len(short)%2: short+=b'\0'
    ln=name.encode('utf-16le')+b'\0\0'
    ext=struct.pack('<HHI',0,9,0xBEEF0004)+b'\0'*38+ln+b'\0\0'
    ext=struct.pack('<H',len(ext))+ext[2:]
    body=struct.pack('<BBIIH',t,0,0,0,0x10)+short+ext
    return struct.pack('<H',len(body)+2)+body
pidl=root_item('20D04FE0-3AEA-1069-A2D8-08002B30309D')+vol_item('C:\\')+file_item('Users')+file_item('max')+file_item('Downloads')+file_item('invoice.exe',0x32)+b'\0\0'
print('idlist ->', w.parse_idlist(pidl))
ua=w.rot13('{F38BF404-1D43-42F2-9305-67DE0B28FC23}'.replace('F38BF404-1D43-42F2-9305-67DE0B28FC23','F38BF404-1D43-42F2-9305-67DE0B28FC23'))
ua_name=w.rot13(T)
ua_data=struct.pack('<IIII',0,5,7,123456)+b'\0'*44+struct.pack('<Q',FT(2026))+b'\0'*4
nt=R(tree({
 r'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count':{ua_name:ua_data},
 r'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.exe':{'0':'invoice.exe\0'.encode('utf-16le')+b'\x14\x00junk','MRUListEx':struct.pack('<iI',0,0xFFFFFFFF)},
 r'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\exe':{'0':pidl,'MRUListEx':struct.pack('<iI',0,0xFFFFFFFF)},
 r'Software\Microsoft\Office\16.0\Word\User MRU\LiveId_X\File MRU':{'Item 1':'[F00000000][T01DCF2A1B2C3D4E5][O00000000]*'+T},
}),'max\\NTUSER.DAT')
bag=tree({r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU':{'0':root_item('20D04FE0-3AEA-1069-A2D8-08002B30309D')},
          r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0':{'0':vol_item('C:\\')},
          r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0':{'0':file_item('Users')},
          r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\0':{'0':file_item('max')},
          r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\0\0':{'0':file_item('Downloads')},
          r'Local Settings\Software\Microsoft\Windows\Shell\BagMRU\0\0\0\0\0':{}})
uc=R(bag,'max\\UsrClass.dat')
args=types.SimpleNamespace(target=T, root='test/img', max_events=10, max_usn=10, no_vss=True, deep_registry=False)
ctx=w.Ctx(args)
amc=R(tree({r'Root\InventoryApplicationFile\invoice.exe|1a2b':{'LowerCaseLongPath':T.lower(),'FileId':'0000'+ctx.target.sha1,'Publisher':'evil corp','LinkDate':'11/14/2023 22:13:20','Name':'invoice.exe'}}),'Amcache.hve')
ctx._system=(system,'ControlSet001'); ctx._software=software; ctx._amcache=amc
ctx._users=[w.User('max','S-1-5-21-1-2-3-1001',r'test/img/Users/max',nt,uc)]
for m in ['shimcache','bam','userassist','mru','shellbags','amcache','persistence','deepreg']:
    n=len(ctx.r.findings); w.MODULES[m]['fn'](ctx)
    for f in ctx.r.findings[n:]: print(f"{m:11}| {f['artifact'][:28]:28}| {f['match']:5}| {f['summary'][:80]} | {list(f['times'].values())[:1]}")
print('errors', ctx.r.errors)
