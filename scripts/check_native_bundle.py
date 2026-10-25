"""Verify the actual distributable is self-contained and does not bundle Node."""
import plistlib
import subprocess
import sys
from pathlib import Path

app = Path(sys.argv[1])
contents = app / "Contents"
info = plistlib.loads((contents / "Info.plist").read_bytes())
resources = contents / "Resources"
executables = [contents / "MacOS" / info["CFBundleExecutable"]]
executables += [resources / "bin" / name for name in (
    "usbkey-transport", "usbkey-worker", "ft3000gm-hid-probe", "ft3000gm-signer")]
for path in executables:
    assert path.is_file(), f"Missing executable: {path}"
    subprocess.run(["/usr/bin/lipo", "-verify_arch", "arm64", str(path)], check=True)
    libraries = subprocess.check_output(["/usr/bin/otool", "-L", str(path)], text=True)
    for line in libraries.splitlines()[1:]:
        library = line.strip().split(" (", 1)[0]
        assert library.startswith(("/usr/lib/", "/System/Library/")), f"External runtime dependency: {library}"
assert not (resources / "runtime").exists(), "Legacy runtime directory remains"
assert not (resources / "server").exists(), "Legacy JavaScript server remains"
for file in contents.rglob("*"):
    assert file.name.lower() != "node" and file.suffix not in (".mjs", ".js"), f"Node/JavaScript asset: {file}"
notices = (resources / "THIRD_PARTY_NOTICES.txt").read_text()
assert "OpenSSL" in notices and "Rust standard library" in notices, "Missing runtime license notices"
print("Native application bundle: arm64, system libraries only, no Node/JavaScript runtime, notices present — PASSED")
