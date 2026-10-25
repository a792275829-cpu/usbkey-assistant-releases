import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
const temp = mkdtempSync(join(tmpdir(), "native-device-selection-"));
try {
  const source = join(temp, "select.c"), binary = join(temp, "select");
  writeFileSync(source, `#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDManager.h>
#include <IOKit/IOKitLib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
static CFSetRef inventory;
static CFSetRef fake_copy(IOHIDManagerRef manager) { (void)manager; return (CFSetRef)CFRetain(inventory); }
static io_service_t fake_service(IOHIDDeviceRef device) {
  int id = 0; CFNumberGetValue((CFNumberRef)device, kCFNumberIntType, &id); return (io_service_t)id;
}
static kern_return_t fake_entry(io_service_t service, uint64_t *entry) { *entry = service; return KERN_SUCCESS; }
#define IOHIDManagerCopyDevices fake_copy
#define IOHIDDeviceGetService fake_service
#define IORegistryEntryGetRegistryEntryID fake_entry
#include "${resolve(import.meta.dirname, "../src/ft3000gm_devices.h")}"
int main(void) {
  int one = 1, two = 2;
  CFNumberRef a = CFNumberCreate(NULL, kCFNumberIntType, &one), b = CFNumberCreate(NULL, kCFNumberIntType, &two);
  const void *both[] = { a, b };
  inventory = CFSetCreate(NULL, both, 2, &kCFTypeSetCallBacks);
  assert(ft_select_device(NULL, 0) == NULL); /* Never pick an arbitrary token. */
  assert(ft_select_device(NULL, 3) == NULL);
  IOHIDDeviceRef selected = ft_select_device(NULL, 2); assert(selected == (IOHIDDeviceRef)b); CFRelease(selected);
  CFRelease(inventory); inventory = CFSetCreate(NULL, both, 1, &kCFTypeSetCallBacks);
  selected = ft_select_device(NULL, 0); assert(selected == (IOHIDDeviceRef)a); CFRelease(selected);
  assert(ft_select_device(NULL, 2) == NULL); /* Never fall back after unplug. */
  uint64_t parsed = 0;
  assert(ft_parse_device_id("ffffffffffffffff", &parsed) && parsed == UINT64_MAX);
  assert(!ft_parse_device_id("0", &parsed)); assert(!ft_parse_device_id("-1", &parsed));
  assert(!ft_parse_device_id("12345678901234567", &parsed)); assert(!ft_parse_device_id("x", &parsed));
  CFRelease(inventory); CFRelease(a); CFRelease(b); puts("Native attachment selection and argument validation PASSED"); return 0;
}
`);
  execFileSync("/usr/bin/clang", ["-std=c11", "-Wall", "-Wextra", "-Wpedantic", source, "-o", binary,
    "-framework", "CoreFoundation", "-framework", "IOKit"]);
  assert.match(execFileSync(binary, { encoding: "utf8" }), /PASSED/);
  console.log("Native attachment selection, unplug refusal and argument validation tests PASSED");
} finally { rmSync(temp, { recursive: true, force: true }); }
