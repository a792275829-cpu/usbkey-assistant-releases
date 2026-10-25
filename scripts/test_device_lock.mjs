import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { once } from "node:events";

const temp = mkdtempSync(join(tmpdir(), "device-lock-test-"));
const children = [];
try {
  const source = join(temp, "lock-test.c");
  const binary = join(temp, "lock-test");
  writeFileSync(source, `#include "${resolve(import.meta.dirname, "../src/ft3000gm_lock.h")}"
int main(int argc, char **argv) {
  (void)argv;
  int fd = acquire_device_lock();
  if (fd < 0) return 1;
  puts("locked"); fflush(stdout);
  if (argc > 1) { for (;;) pause(); }
  close(fd); return 0;
}
`);
  execFileSync("/usr/bin/clang", ["-std=c11", "-Wall", "-Wextra", "-Wpedantic", source, "-o", binary]);
  const first = spawn(binary, ["hold"]); children.push(first);
  first.on("error", () => {});
  assert.match((await once(first.stdout, "data"))[0].toString(), /locked/);
  const second = spawn(binary); children.push(second);
  second.on("error", () => {});
  let output = "";
  second.stdout.on("data", (chunk) => { output += chunk; });
  const closed = once(second, "close");
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(output, "", "another process must wait while the lock is held");
  first.kill("SIGKILL");
  const result = await Promise.race([closed, new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error("lock was not released after process exit")), 3000);
    timer.unref();
  })]);
  assert.equal(result[0], 0); assert.equal(output.trim(), "locked");
  console.log("Cross-process device lock and release-on-exit tests PASSED");
} finally {
  for (const child of children) { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); }
  rmSync(temp, { recursive: true, force: true });
}
