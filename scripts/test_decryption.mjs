import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { constants, privateDecrypt } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { envelopedDataEncrypt, envelopedDataDecrypt } from '../server/netca_readonly_bridge.mjs';

const hardware = process.argv.includes('--hardware');
const text = Buffer.from('macOS 报价加载测试 -50,277,281,287,400');
const temp = mkdtempSync(join(tmpdir(), 'gdpower-decrypt-test-'));
try {
  let probe;
  let deps;
  let privateKey;
  if (hardware) {
    probe = JSON.parse(execFileSync('build/ft3000gm-hid-probe', ['--include-certificate'], {encoding:'utf8'}));
    deps = {probeReader: async () => probe};
  } else {
    execFileSync('/usr/bin/openssl', ['req','-x509','-newkey','rsa:2048','-nodes',
      '-subj','/CN=Local decrypt test','-addext','keyUsage=keyEncipherment',
      '-addext','subjectKeyIdentifier=hash','-days','1',
      '-keyout',join(temp,'key.pem'),'-out',join(temp,'cert.pem')], {stdio:'ignore'});
    const cert = execFileSync('/usr/bin/openssl',['x509','-in',join(temp,'cert.pem'),'-outform','DER']);
    probe = {certificates:[{file_id:'3002',encode:cert.toString('base64')}]};
    privateKey = readFileSync(join(temp,'key.pem'));
    deps = {probeReader:async()=>probe,
      pinReader:async()=> { throw new Error('unexpected PIN prompt'); },
      decryptBlockWithoutPin:async (b)=>privateDecrypt({key:privateKey,padding:constants.RSA_NO_PADDING},b)};
  }
  for (const algo of (hardware ? [0] : [0,6])) {
    const enc = await envelopedDataEncrypt({algo,cert:{type:'device',condition:"CertType='Encrypt'"},
      data:{text:text.toString('base64')}},async()=>probe);
    const dec = await envelopedDataDecrypt({encData:enc.encryptValue},deps);
    assert.equal(dec.clearEncodeType,'base64');
    assert.deepEqual(Buffer.from(dec.clearValue,'base64'),text);
    if (!hardware) {
      await assert.rejects(()=>envelopedDataDecrypt({encData:'broken'},deps));
      await assert.rejects(()=>envelopedDataDecrypt({encData:enc.encryptValue,savefileName:'/tmp/no-write'},deps));
      await assert.rejects(()=>envelopedDataDecrypt({encData:enc.encryptValue},
        {...deps,decryptBlockWithoutPin:async()=>Buffer.alloc(256)}), /公钥自检/);
      let prompted = 0;
      const fallback = await envelopedDataDecrypt({encData:enc.encryptValue}, {
        ...deps,
        decryptBlockWithoutPin: async()=> {
          const error = new Error('authentication required');
          error.code = 'USBKEY_USER_AUTH_REQUIRED';
          throw error;
        },
        pinReader: async()=> { prompted += 1; return 'test-only'; },
        decryptBlockWithPin: async (_pin,b)=>
          privateDecrypt({key:privateKey,padding:constants.RSA_NO_PADDING},b),
      });
      assert.equal(prompted, 1);
      assert.deepEqual(Buffer.from(fallback.clearValue,'base64'),text);
      let leaseUses = 0;
      const leased = await envelopedDataDecrypt({encData:enc.encryptValue}, {
        ...deps,
        authenticationPin: 'test-only',
        decryptBlockWithoutPin: async()=> {
          throw new Error('no-PIN path must not run with a login lease');
        },
        decryptBlockWithPin: async (pin,b)=> {
          assert.equal(pin, 'test-only');
          leaseUses += 1;
          return privateDecrypt({key:privateKey,padding:constants.RSA_NO_PADDING},b);
        },
      });
      assert.equal(leaseUses, 1);
      assert.deepEqual(Buffer.from(leased.clearValue,'base64'),text);
    }
  }
  console.log(hardware ? 'USBKey hardware decryption round-trip PASSED' : 'Offline decryption and failure-path tests PASSED');
} finally {rmSync(temp,{recursive:true,force:true});}
