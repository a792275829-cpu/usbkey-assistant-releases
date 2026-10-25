#!/usr/bin/env python3
"""Local, bounded login diagnostics: no credentials, headers or message bodies."""
import argparse,datetime,http.client,json,os,pathlib,re,signal,ssl,subprocess,time
parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--seconds',type=int,default=3600)
args=parser.parse_args();root=pathlib.Path(args.output).resolve();root.mkdir(parents=True,exist_ok=True);os.chmod(root,0o700)
source=pathlib.Path.home()/'Library/Logs/广东电力USBKey助手/bridge.log'
cert=pathlib.Path.home()/'Library/Application Support/广东电力USBKey助手/tls/localhost.crt'
context=ssl.create_default_context(cafile=str(cert));started=time.time();stop=False

def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(name,value):
 p=root/name
 with p.open('a',encoding='utf8') as f:os.chmod(p,0o600);f.write(json.dumps(value,ensure_ascii=False)+'\n')
def bridge_record(value,baseline=False):
 allowed=['timestamp','event','requestId','method','status','errorType','parameterShape','cacheEntries',
 'authenticatedSessionLeasePreserved','dfAuthenticated','authStatusWord','pinVerified','pinStatusWord','retries',
 'signatureStatusWord','exitCode','algorithm','certificateFileId','certificateCount','readStatus','operation','reason',
 'recipientIdentifiers','deviceCertificates']
 record={k:value[k] for k in allowed if k in value}
 record['observedAt']=now();record['baseline']=baseline
 write('bridge.jsonl',record)
def local_status(path):
 connection=http.client.HTTPSConnection('127.0.0.1',10443,timeout=2,context=context)
 try:
  connection.request('GET',path);response=connection.getresponse();data=response.read(32768)
  if path=='/health':return {'httpStatus':response.status,'identityMatches':data==b'netca-ft3000gm'}
  v=json.loads(data);return {k:v.get(k) for k in ['deviceFound','deviceCount','certificateCount','selectedDeviceId','requiresSelection']}
 finally:connection.close()
def network_status():
 result={}
 for name,command in [('defaultRoute',['/sbin/route','-n','get','default']),('siteReachability',['/usr/sbin/scutil','-r','pm.gd.csg.cn'])]:
  try:
   r=subprocess.run(command,capture_output=True,text=True,timeout=2)
   if name=='defaultRoute':
    match=re.search(r'^\s*interface:\s*(\S+)',r.stdout,re.M);result['interface']=match.group(1) if match else None;result['hasDefaultRoute']=r.returncode==0
   else:result['systemReachability']=r.stdout.strip()[:180]
  except Exception as e:result[name+'Error']=type(e).__name__
 try:result['bridge']=local_status('/health')
 except Exception as e:result['bridge']={'errorType':type(e).__name__}
 return result

def finish(signum=None,frame=None):
 global stop
 stop=True
signal.signal(signal.SIGTERM,finish);signal.signal(signal.SIGINT,finish)
meta={'pid':os.getpid(),'startedAt':now(),'endsAfterSeconds':args.seconds,'target':'https://pm.gd.csg.cn/portal/#/user/login',
 'scope':['existing redacted bridge audit','local bridge TLS health','default interface','system reachability'],
 'notCollected':['PIN','password','captcha','cookies','authorization headers','certificate bodies','signatures','request/response bodies','IP addresses']}
(root/'session.json').write_text(json.dumps(meta,ensure_ascii=False,indent=2)+'\n');os.chmod(root/'session.json',0o600)
position=0;inode=None;pending=''
if source.exists():
 inode=source.stat().st_ino
 with source.open('rb') as f:
  f.seek(max(0,source.stat().st_size-131072));data=f.read();position=f.tell()
 for line in data.decode('utf8',errors='replace').splitlines():
  try:
   value=json.loads(line);at=datetime.datetime.fromisoformat(value['timestamp'].replace('Z','+00:00')).timestamp()
   if at>=started-1200:bridge_record(value,True)
  except (ValueError,KeyError,TypeError):pass
try:write('state.jsonl',{'timestamp':now(),'event':'initial_devices',**local_status('/status')})
except Exception as e:write('state.jsonl',{'timestamp':now(),'event':'initial_devices_unavailable','errorType':type(e).__name__})
previous=None;next_sample=0;heartbeat=0
while not stop and time.time()-started<args.seconds:
 try:
  stat=source.stat()
  if inode!=stat.st_ino or stat.st_size<position:position=0;pending='';inode=stat.st_ino
  with source.open('rb') as f:f.seek(position);chunk=f.read(262144);position=f.tell()
  pending+=chunk.decode('utf8',errors='replace');lines=pending.split('\n');pending=lines.pop()
  for line in lines:
   try:bridge_record(json.loads(line))
   except (ValueError,TypeError):pass
 except OSError:pass
 current=time.time()
 if current>=next_sample:
  value=network_status()
  if value!=previous or current>=heartbeat:
   write('state.jsonl',{'timestamp':now(),'event':'state_change' if value!=previous else 'heartbeat',**value});previous=value;heartbeat=current+30
  next_sample=current+5
 time.sleep(.5)
write('state.jsonl',{'timestamp':now(),'event':'monitor_stopped','reason':'requested' if stop else 'time_limit'})
