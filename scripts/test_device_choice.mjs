import assert from "node:assert/strict";
import { createBridgeServer } from "../server/websocket-server.mjs";
import { createDeviceSelection } from "../server/device-selection.mjs";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request } from "node:https";
import { once } from "node:events";
const temp = mkdtempSync(join(tmpdir(), "device-choice-"));
let server;
try {
  execFileSync("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-days", "1", "-keyout", join(temp,"key"), "-out", join(temp,"cert")], { stdio: "ignore" });
  const tls = { key: readFileSync(join(temp,"key")), cert: readFileSync(join(temp,"cert")) };
  let revocations = 0;
  let forgotten = 0;
  const selection = createDeviceSelection({ authentication: { invalidate() { revocations++; } } });
  let inventory = [{ device_id: "a1" }, { device_id: "b1" }];
  server = createBridgeServer({ tls, selection, dispatchRequest: async () => {},
    authentication: { async forgetSavedPins() { forgotten++; } },
    readInventory: async () => inventory, readStatus: async ({selection}) => ({deviceFound:true,selectedDeviceId:selection.current()}) });
  server.listen(0,"127.0.0.1"); await once(server,"listening");
  const call = (body, headers = {}, path = "/selection", method = "POST") => new Promise((resolve,reject) => {
    const req = request({host:"127.0.0.1",port:server.address().port,servername:"localhost",ca:tls.cert,
      path,method,headers:{"Content-Type":"application/json",...headers}}, (res) => {
      let text="";res.setEncoding("utf8");res.on("data",(d)=>text+=d);res.on("end",()=>resolve({status:res.statusCode,text}));
    });
    req.setTimeout(3000,()=>req.destroy(new Error("timeout")));req.on("error",reject);req.end(body);
  });
  assert.equal((await call('{"deviceId":"b1"}', {Origin:"https://pm.gd.csg.cn"})).status,403);
  assert.equal(selection.current(),null);
  assert.equal((await call('{"deviceId":"b1"}', {"Content-Type":"text/plain"})).status,403);
  assert.equal((await call('{"deviceId":"missing"}')).status,400);
  assert.equal((await call('{"deviceId":"b1"}')).status,200);
  assert.equal(selection.current(),"b1");assert.equal(revocations,1);
  assert.equal(JSON.parse((await call(undefined,{},"/status","GET")).text).selectedDeviceId,"b1");
  assert.equal((await call('{"deviceId":"b1"}')).status,200); assert.equal(revocations,1);
  assert.equal((await call('{"deviceId":"a1"}')).status,200); assert.equal(revocations,2);
  inventory=[{device_id:"b1"}];selection.reconcile(inventory);
  assert.equal(selection.current(),"b1");assert.equal(revocations,3);
  assert.equal((await call("x".repeat(1100))).status,413);
  assert.equal((await call('{}', {Origin:"https://pm.gd.csg.cn"}, "/pin-cache/clear")).status,403);
  assert.equal((await call('{}', {"Content-Type":"text/plain"}, "/pin-cache/clear")).status,403);
  assert.equal(forgotten,0);
  assert.equal((await call('{}', {}, "/pin-cache/clear")).status,200);
  assert.equal(forgotten,1);
  console.log("Native device choice, Origin rejection, stale-device refusal and PIN revocation tests PASSED");
} finally { if(server) await new Promise((resolve)=>server.close(resolve));rmSync(temp,{recursive:true,force:true}); }
