"""Bundle license texts for the locked Rust dependency graph (including OpenSSL)."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("metadata")
parser.add_argument("output")
parser.add_argument("--sysroot", required=True)
args = parser.parse_args()
metadata = json.loads(Path(args.metadata).read_text())
sections = ["USBKey 助手 — 第三方组件许可\n"]
for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
    if package["source"] is None:
        continue
    root = Path(package["manifest_path"]).parent
    files = set()
    for pattern in ("LICENSE*", "COPYING*", "NOTICE*", "license*", "licenses/**/*", "openssl/LICENSE*", "openssl/NOTICE*"):
        files.update(p for p in root.glob(pattern) if p.is_file())
    if package.get("license_file"):
        files.add(root / package["license_file"])
    sections.append(f"\n{'=' * 72}\n{package['name']} {package['version']}\nSPDX: {package.get('license') or 'see license file'}\n{package.get('repository') or ''}\n")
    for file in sorted(files):
        sections.append(f"\n--- {file.relative_to(root)} ---\n{file.read_text(errors='replace')}\n")
std = Path(args.sysroot) / "share/doc/rust"
for file in sorted(std.glob("COPYRIGHT*")) + sorted(std.glob("LICENSE*")):
    if file.is_file():
        sections.append(f"\n--- Rust standard library: {file.name} ---\n{file.read_text(errors='replace')}\n")
Path(args.output).write_text("".join(sections))
