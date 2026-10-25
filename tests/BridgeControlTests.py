"""Real Rust IPC/HTTP with simulated devices and a fake Keychain pipe only."""
import concurrent.futures
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request


PROJECT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("RUST_BIN_DIR", PROJECT / "rust-transport/target/debug"))


class BridgeControlTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="usbkey-control-tests-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.state = self.work / "state.json"
        self.log = self.work / "helper.jsonl"
        self.configure(["a1"], 0)
        self.clear_delay = 0
        self.clears = 0
        subprocess.run([
            "/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
            "-days", "1", "-keyout", str(self.work / "key"),
            "-out", str(self.work / "cert"),
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        helper = self.work / "helper"
        helper.write_text(f"""#!/usr/bin/python3
import json,sys,time
state=json.load(open({str(self.state)!r}))
operation=sys.argv[1]
def log(event):
    with open({str(self.log)!r},'a') as f: f.write(json.dumps({{'operation':operation,'event':event}})+'\\n')
log('start')
if operation=='--list-devices':
    out={{'devices':[{{'device_id':d}} for d in state['devices']]}}
else:
    time.sleep(state['delay'])
    out={{'device_found':True,'device_id':sys.argv[3],'certificates':[],'certificate_count':0}}
log('done')
print(json.dumps(out))
""")
        helper.chmod(0o700)
        self.process = subprocess.Popen([
            str(BIN / "usbkey-transport"), "--native-worker", str(BIN / "usbkey-worker"),
            "--port", "0", "--cert", str(self.work / "cert"), "--key", str(self.work / "key"),
            "--probe", str(helper), "--signer", str(helper), "--log", str(self.work / "audit"),
        ], env={**os.environ, "USBKEY_PRIVATE_PIN_CHANNEL": "1"},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop)
        line = self.process.stderr.readline()
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
        self.assertIsNotNone(match, line)
        self.port = int(match[1])
        self.context = ssl.create_default_context(cafile=str(self.work / "cert"))
        self.reader = threading.Thread(target=self.keychain, daemon=True)
        self.reader.start()

    def stop(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if hasattr(self, "reader"):
            self.reader.join(timeout=15)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()

    def keychain(self):
        for line in self.process.stdout:
            request = json.loads(line)
            if request["operation"] == "clear":
                self.clears += 1
                time.sleep(self.clear_delay)
            reply = {"privateChannel": "pin-store-v1", "requestId": request["requestId"], "status": 0}
            try:
                self.process.stdin.write(json.dumps(reply) + "\n")
                self.process.stdin.flush()
            except (BrokenPipeError, ValueError):
                return

    def configure(self, devices, delay):
        temporary = self.state.with_suffix(".tmp")
        temporary.write_text(json.dumps({"devices": devices, "delay": delay}))
        temporary.replace(self.state)

    def request(self, path, body=None):
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self.context))
        request = urllib.request.Request(
            f"https://127.0.0.1:{self.port}{path}",
            data=None if body is None else json.dumps(body).encode(),
            headers={} if body is None else {"Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=25) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def events(self, event):
        if not self.log.exists():
            return 0
        return sum(json.loads(line) == {"operation": "--include-certificate", "event": event}
                   for line in self.log.read_text().splitlines())

    def wait_for(self, predicate, seconds=20):
        until = time.monotonic() + seconds
        while not predicate():
            self.assertLess(time.monotonic(), until, "fixture did not reach the expected state")
            time.sleep(0.05)

    def test_late_status_updates_cache_and_concurrent_readers_share_scan(self):
        self.configure(["a1"], 4.5)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda _: self.request("/status"), range(3)))
        self.assertTrue(all(code == 503 for code, _ in results), results)
        self.assertEqual(self.events("start"), 1, "concurrent readers queued duplicate scans")
        self.wait_for(lambda: self.events("done") == 1)
        # The background task must publish even though all original HTTP waiters left.
        time.sleep(0.2)
        code, body = self.request("/status")
        self.assertEqual(code, 200)
        self.assertTrue(body["deviceFound"])
        self.assertTrue(body["stale"])
        self.assertEqual(body["selectedDeviceId"], "a1")

    def test_expired_selection_and_clear_never_run_after_queue_drains(self):
        self.configure(["a1", "b1"], 8)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            scan = pool.submit(self.request, "/status")
            self.wait_for(lambda: self.events("start") == 1)
            select = pool.submit(self.request, "/selection", {"deviceId": "b1"})
            clear = pool.submit(self.request, "/pin-cache/clear", {})
            self.assertEqual(scan.result()[0], 503)
            self.assertEqual(select.result()[0], 503)
            self.assertEqual(clear.result()[0], 503)
            self.wait_for(lambda: self.events("done") == 2)
        self.configure(["a1", "b1"], 0)
        # This successful control is a barrier behind the two expired jobs.
        self.assertEqual(self.request("/pin-cache/clear", {})[0], 200)
        self.assertEqual(self.clears, 1, "expired clear still reached the Keychain pipe")
        code, body = self.request("/status")
        self.assertEqual(code, 200)
        self.assertEqual(body["selectedDeviceId"], "a1", "expired selection still changed devices")

    def test_started_clear_waits_for_actual_result_instead_of_reporting_timeout(self):
        self.clear_delay = 11
        started = time.monotonic()
        code, body = self.request("/pin-cache/clear", {})
        self.assertEqual(code, 200)
        self.assertTrue(body["cleared"])
        self.assertGreaterEqual(time.monotonic() - started, 10)
        self.assertEqual(self.clears, 1)


if __name__ == "__main__":
    unittest.main()
