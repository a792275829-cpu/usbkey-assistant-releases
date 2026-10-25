import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, chmodSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { connect } from 'node:tls';
import { request as httpsRequest } from 'node:https';
import { once } from 'node:events';
import { randomBytes, sign, X509Certificate } from 'node:crypto';
import { certificateObject } from '../server/certificates.mjs';
import { buildNetcaLegacyDetachedCms, buildAesCbcEnvelopedData } from '../server/cms.mjs';

const temp=mkdtempSync(join(tmpdir(),'native-backend-'));
const bin=resolve(process.env.RUST_BIN_DIR??'rust-transport/target/debug');
const config=join(temp,'state.json'), helperLog=join(temp,'helper.jsonl');
let child,socket,stderr='';
const deadline=(p,ms=12000)=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('native backend test timeout')),ms);p.then(v=>{clearTimeout(timer);resolve(v)},e=>{clearTimeout(timer);reject(e)});});
function masked(text){const payload=Buffer.from(text),mask=randomBytes(4);let header;if(payload.length<126)header=Buffer.from([129,128|payload.length]);else{header=Buffer.alloc(4);header[0]=129;header[1]=254;header.writeUInt16BE(payload.length,2);}for(let i=0;i<payload.length;i++)payload[i]^=mask[i%4];return Buffer.concat([header,mask,payload]);}
try {
  for(const [name,usage] of [['sign','digitalSignature'],['enc','keyEncipherment']]) {
    execFileSync('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=NETCA Fixture Holder/O=Fixture Org','-addext',`keyUsage=${usage}`,'-addext','subjectKeyIdentifier=hash','-days','30','-keyout',join(temp,`${name}.key`),'-out',join(temp,`${name}.crt`)],{stdio:'ignore'});
    execFileSync('/usr/bin/openssl',['x509','-in',join(temp,`${name}.crt`),'-outform','DER','-out',join(temp,`${name}.der`)]);
  }
  execFileSync('/usr/bin/openssl',['req','-x509','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-days','1','-keyout',join(temp,'tls.key'),'-out',join(temp,'tls.crt')],{stdio:'ignore'});
  const signDer=readFileSync(join(temp,'sign.der')),encDer=readFileSync(join(temp,'enc.der'));
  let state={devices:['a1'],mode:'success',sign:signDer.toString('base64'),enc:encDer.toString('base64')};
  const save=changes=>{state={...state,...changes};writeFileSync(config,JSON.stringify(state));};save({});
  const helper=join(temp,'helper.py');
  writeFileSync(helper,`#!/usr/bin/python3
import json,sys,os,subprocess,base64,time
s=json.load(open(${JSON.stringify(config)}));op=sys.argv[1];device=sys.argv[3] if len(sys.argv)>3 else 'a1'
lines=sys.stdin.read().splitlines()
with open(${JSON.stringify(helperLog)},'a') as log:log.write(json.dumps({'pid':os.getpid(),'parent':os.getppid(),'op':op,'device':device,'lines':len(lines)})+'\\n')
if s['mode']=='hang' and op=='--sign-digest-info':time.sleep(60)
if s['mode']=='slow' and op=='--sign-digest-info':time.sleep(5)
if op=='--list-devices':out={'devices':[{'device_id':d,'device_type':47} for d in s['devices']]}
elif op=='--include-certificate':out={'device_found':True,'device_id':device,'device_type':47,'certificate_count':2,'certificate_file_ids':'3001;3002','container_diagnostics':'0:1240010101300109023002','certificates':[{'file_id':'3001','encode':s['sign']},{'file_id':'3002','encode':s['enc']}]}
elif op=='--pin-status':out={'retries':5}
else:
    needs=op!='--decrypt-rsa-block-no-pin'
    if needs and (s['mode']=='badpin' or not lines or lines[0]!='fixture-pin'):
        print(json.dumps({'pin_verified':False,'verify_sw':'63C2','retries':2}));sys.exit(4)
    data=base64.b64decode(lines[-1])
    if op=='--sign-digest-info':
        value=subprocess.check_output(['/usr/bin/openssl','rsautl','-sign','-inkey',${JSON.stringify(join(temp,'sign.key'))}],input=data,stderr=subprocess.DEVNULL)
        if s['mode']=='badSignature':value=b'\\0'*256
        out={'signed':True,'signature_base64':base64.b64encode(value).decode()}
    else:
        value=subprocess.check_output(['/usr/bin/openssl','rsautl','-decrypt','-raw','-inkey',${JSON.stringify(join(temp,'enc.key'))}],input=data,stderr=subprocess.DEVNULL)
        out={'decrypted':True,'rsa_block_base64':base64.b64encode(value).decode()}
print(json.dumps(out))
`);chmodSync(helper,0o700);
  child=spawn(join(bin,'usbkey-transport'),['--port','0','--cert',join(temp,'tls.crt'),'--key',join(temp,'tls.key'),'--native-worker',join(bin,'usbkey-worker'),'--probe',helper,'--signer',helper,'--log',join(temp,'audit.log')],{env:{...process.env,PATH:'/usr/bin:/bin:/usr/sbin:/sbin',USBKEY_PRIVATE_PIN_CHANNEL:'1'},stdio:['pipe','pipe','pipe']});
  const stored=new Map();let privateBuffer='';
  child.stdout.setEncoding('utf8');child.stdout.on('data',chunk=>{privateBuffer+=chunk;while(privateBuffer.includes('\n')){const end=privateBuffer.indexOf('\n'),line=privateBuffer.slice(0,end);privateBuffer=privateBuffer.slice(end+1);const req=JSON.parse(line);assert.equal(req.privateChannel,'pin-store-v1');let status=0,pin;
    if(req.operation==='read'){pin=stored.get(req.account);if(pin===undefined)status=-25300;}
    else if(req.operation==='write')stored.set(req.account,req.pin);
    else if(req.operation==='remove')stored.delete(req.account);
    else if(req.operation==='clear')stored.clear();
    child.stdin.write(JSON.stringify({privateChannel:'pin-store-v1',requestId:req.requestId,status,pin})+'\n');}});
  const port=await deadline(new Promise((resolve,reject)=>{child.stderr.on('data',chunk=>{stderr+=chunk;const m=stderr.match(/listening on 127\.0\.0\.1:(\d+)/);if(m)resolve(Number(m[1]));});child.once('exit',code=>reject(new Error(`native backend exited ${code}: ${stderr}`)));child.once('error',reject);}));
  const tls={host:'127.0.0.1',port,ca:readFileSync(join(temp,'tls.crt')),servername:'localhost'};
  function http(path,method='GET',body='',headers={}){return deadline(new Promise((resolve,reject)=>{const req=httpsRequest({...tls,path,method,headers},res=>{let text='';res.on('data',c=>text+=c);res.on('end',()=>resolve({status:res.statusCode,body:text}));});req.on('error',reject);req.end(body);}));}
  socket=connect(tls);socket.on('error',()=>{});await deadline(once(socket,'secureConnect'));
  let buffer=Buffer.alloc(0),upgraded=false;const received=[],waiting=[];
  const deliver=v=>waiting.length?waiting.shift()(v):received.push(v);
  const next=()=>deadline(received.length?Promise.resolve(received.shift()):new Promise(r=>waiting.push(r)));
  socket.on('data',chunk=>{buffer=Buffer.concat([buffer,chunk]);if(!upgraded){const end=buffer.indexOf('\r\n\r\n');if(end<0)return;assert.match(buffer.subarray(0,end).toString(),/^HTTP\/1.1 101/);buffer=buffer.subarray(end+4);upgraded=true;deliver('upgraded');}while(buffer.length>=2){let size=buffer[1]&127,offset=2;if(size===126){if(buffer.length<4)return;size=buffer.readUInt16BE(2);offset=4;}else if(size===127){if(buffer.length<10)return;size=Number(buffer.readBigUInt64BE(2));offset=10;}if(buffer.length<offset+size)return;const opcode=buffer[0]&15;if(opcode===1)deliver(JSON.parse(buffer.subarray(offset,offset+size)));buffer=buffer.subarray(offset+size);}});
  socket.write(['GET / HTTP/1.1',`Host: localhost:${port}`,'Connection: Upgrade','Upgrade: websocket',`Sec-WebSocket-Key: ${randomBytes(16).toString('base64')}`,'Sec-WebSocket-Version: 13','Sec-WebSocket-Protocol: crypto-jsonrpc-protocol','Origin: https://pm.gd.csg.cn','\r\n'].join('\r\n'));assert.equal(await next(),'upgraded');
  let id=1;
  async function rpc(name,param={}){const request={requestId:id++,requestVersion:1,lwsObjectId:'native-test',requestOrigin:'fixture',requestQuery:{function:name,param}};socket.write(masked(JSON.stringify(request)));const response=await next();assert.equal(response.requestId,request.requestId);assert.equal(response.lwsObjectId,request.lwsObjectId);return response;}
  const ok=async(name,param)=>{const value=await rpc(name,param);assert.equal(value.responseResult.status,0,JSON.stringify(value.responseResult));return value.responseEntity;};
  assert.equal((await http('/health')).body,'netca-ft3000gm');
  const status=JSON.parse((await http('/status')).body);assert.equal(status.deviceFound,true);assert.equal(status.organization,'Fixture Org');assert.equal(status.retries,5);
  assert.equal((await ok('GetVersionInfo1')).version,'macOS-ft3000gm-1.1.15');
  assert.equal((await ok('IsInsertKey')).insertCount,1);
  const list=await ok('GetCertList');assert.equal(list.certCount,2);assert.deepEqual(list.certInfo,list.certList);
  for(const record of list.certInfo){const der=record.fileId==='3001'?signDer:encDer;for(const [key,value]of Object.entries(certificateObject(der)))assert.deepEqual(record[key],value,`certificate field ${key}`);}
  assert.equal((await ok('GetCertList',{type:1})).certInfo[0].fileId,'3002');assert.equal((await ok('GetCertList',{type:2})).certInfo[0].fileId,'3001');
  const portal=JSON.parse(readFileSync('tests/fixtures/portal-certificate-selector.json'));
  assert.equal((await ok('GetCertStringAttribute',{id:-1,cert:portal})).certCode,signDer.toString('base64'));
  assert.equal((await ok('GetCertStringAttribute',{id:-1,cert:{encode:'',certCode:encDer.toString('base64')}})).certCode,encDer.toString('base64'));
  writeFileSync(join(temp,'.capture-certificate-selector-once'),'');
  assert.notEqual((await rpc('GetCertStringAttribute',{id:-1,cert:{condition:"Unknown='x'",encode:signDer.toString('base64')}})).responseResult.status,0);
  assert.equal(existsSync(join(temp,'.capture-certificate-selector-once')),false);
  assert.equal(readFileSync(join(temp,'rejected-certificate-selector.json'),'utf8').includes(signDer.toString('base64')),false);
  for(const condition of ["IssuerCN~'OtherCA' && CertType='Signature'","IssuerCN~'NETCA' || CertType='Signature'","CertType~'Sign'","Unknown='x'"]){assert.notEqual((await rpc('GetCertStringAttribute',{id:-1,cert:{type:'device',condition}})).responseResult.status,0);}
  const content=Buffer.from('native 兼容签名 -50,277,281,287,400');
  for(const algorithm of [undefined,2,4])for(const includeCertOption of [0,1,2,3]) {
    const entity=await ok('SignedDataSign',{...(algorithm===undefined?{}:{algo:algorithm}),detached:1,includeCertOption,certPwd:'fixture-pin',data:{text:content.toString('base64')}});
    const digest=algorithm===4?'sha256':'sha1';const signature=sign(algorithm===4?'RSA-SHA256':'RSA-SHA1',content,readFileSync(join(temp,'sign.key')));
    const oid=algorithm===undefined?'1.2.840.113549.1.1.1':algorithm===4?'1.2.840.113549.1.1.11':'1.2.840.113549.1.1.5';
    assert.equal(entity.signValue,buildNetcaLegacyDetachedCms(signDer,signature,digest,oid).toString('base64'),'CMS must match legacy bytes exactly');assert.equal(entity.signedData,entity.signValue);
  }
  assert.equal(stored.size,1);await ok('ClearPwdCache');
  assert.ok((await ok('SignedDataSign',{algo:4,detached:1,data:{text:content.toString('base64')}})).signValue,'cached lease must work without prompting');
  const encCert=new X509Certificate(encDer);
  for(const algo of [-1,0,4,6]) {
    const encrypted=await ok('EnvelopedDataEncrypt',{algo,cert:algo===-1?{encode:encDer.toString('base64')}:{type:'device',condition:"CertType='Encrypt'"},data:{text:content.toString('base64')}});
    const envelope=Buffer.from(encrypted.encryptValue,'base64');writeFileSync(join(temp,'envelope.der'),envelope);
    const clear=execFileSync('/usr/bin/openssl',['cms','-decrypt','-inform','DER','-in',join(temp,'envelope.der'),'-inkey',join(temp,'enc.key'),'-recip',join(temp,'enc.crt')]);assert.deepEqual(clear,content);
    const decrypted=await ok('EnvelopedDataDecrypt',{encData:encrypted.encryptValue});assert.deepEqual(Buffer.from(decrypted.clearValue,'base64'),content);assert.equal(decrypted.clearEncodeType,'base64');
    const nodeEnvelope=buildAesCbcEnvelopedData(encCert,content,algo===6?256:128).toString('base64');
    assert.deepEqual(Buffer.from((await ok('EnvelopedDataDecrypt',{encData:nodeEnvelope})).clearValue,'base64'),content);
  }
  await http('/pin-cache/clear','POST','',{'Content-Type':'application/json'});assert.equal(stored.size,0);
  const noPinEnvelope=buildAesCbcEnvelopedData(encCert,content,128).toString('base64');assert.deepEqual(Buffer.from((await ok('EnvelopedDataDecrypt',{encData:noPinEnvelope})).clearValue,'base64'),content);assert.equal(stored.size,0);
  let logs=()=>readFileSync(helperLog,'utf8').trim().split('\n').map(JSON.parse);
  save({mode:'badpin'});const before=logs().filter(x=>x.op==='--sign-digest-info').length;
  const rejected=await ok('SignedDataSign',{algo:4,detached:1,certPwd:'fixture-pin',data:{text:content.toString('base64')}});assert.deepEqual(rejected,{result:-5,retrynum:2});assert.equal(logs().filter(x=>x.op==='--sign-digest-info').length,before+1);
  save({mode:'badSignature'});assert.notEqual((await rpc('SignedDataSign',{algo:4,detached:1,certPwd:'fixture-pin',data:{text:content.toString('base64')}})).responseResult.status,0);assert.equal(stored.size,0);
  save({mode:'success',devices:['a1','b1']});await http('/status');assert.equal((await ok('GetCertList')).certCount,4);
  const selected=await http('/selection','POST','{"deviceId":"b1"}',{'Content-Type':'application/json'});assert.equal(JSON.parse(selected.body).selectedDeviceId,'b1');
  assert.equal((await ok('SignedDataSign',{algo:4,detached:1,certPwd:'fixture-pin',data:{text:content.toString('base64')}})).certObject.deviceId,'b1');
  assert.equal((await ok('GetCertStringAttribute',{id:-1,cert:{deviceId:'a1',condition:"CertType='Sign'"}})).certCode,signDer.toString('base64'));
  assert.notEqual((await rpc('EnvelopedDataDecrypt',{encData:'broken'})).responseResult.status,0);
  assert.notEqual((await rpc('EnvelopedDataDecrypt',{encData:noPinEnvelope,savefileName:true})).responseResult.status,0);
  assert.equal((await rpc('UnknownMethod')).responseResult.status,-11001);
  // A status read must not queue behind a slow hardware operation; it answers
  // from the last known snapshot and marks it stale instead of failing.
  const known=JSON.parse((await http('/status')).body);
  save({mode:'slow'});
  const slow=rpc('SignedDataSign',{algo:4,detached:1,certPwd:'fixture-pin',data:{text:content.toString('base64')}});
  await new Promise(r=>setTimeout(r,400));
  const startedAt=Date.now();const busy=(await http('/status')).body;const waited=Date.now()-startedAt;
  assert.ok(waited<8000,`status waited ${waited}ms behind hardware work`);
  assert.equal(JSON.parse(busy).stale,true);
  assert.equal(JSON.parse(busy).deviceFound,known.deviceFound);
  await slow;save({mode:'success'});
  // Wait for the baseline scan before subscribing, then observe a real topology change.
  await new Promise(r=>setTimeout(r,1100));const monitorId=id;await ok('MonitorDevice',{delayTime:0});save({devices:['a1']});const event=await next();assert.equal(event.requestId,monitorId);assert.equal(event.responseEntity.pullOut,true);assert.equal(event.responseEntity.deviceId,'b1');
  const audit=readFileSync(join(temp,'audit.log'),'utf8');assert.equal(audit.includes('fixture-pin'),false);assert.equal(audit.includes(content.toString('base64')),false);assert.ok(logs().every(x=>x.parent===child.pid));
  const workerPid=audit.trim().split('\n').map(JSON.parse).find(x=>x.mode==='rust-native-worker').pid;
  assert.match(execFileSync('/bin/ps',['-p',String(workerPid),'-o','comm='],{encoding:'utf8'}),/usbkey-worker/);
  socket.destroy();
  // Without a device subscription nothing may poll the hardware any more.
  await new Promise(r=>setTimeout(r,600));
  const idleProbes=logs().filter(x=>x.op==='--list-devices').length;
  await new Promise(r=>setTimeout(r,2000));
  assert.equal(logs().filter(x=>x.op==='--list-devices').length,idleProbes,'device scans continue without a subscriber');
  child.kill('SIGTERM');await deadline(once(child,'exit'));assert.equal(child.exitCode,0);assert.throws(()=>process.kill(workerPid,0),{code:'ESRCH'});
  console.log('Node-free native RPC, certificate fields/selectors, byte-identical CMS, OpenSSL/Node envelope interoperability, PIN error/lease compatibility, monitor and shutdown tests PASSED');
}catch(error){throw new Error(`${error.message}\nNative diagnostics:\n${stderr}`,{cause:error});}
finally{socket?.destroy();if(child&&child.exitCode===null&&child.signalCode===null){child.kill('SIGTERM');await deadline(once(child,'exit'),3000).catch(()=>child.kill('SIGKILL'));}rmSync(temp,{recursive:true,force:true});}
