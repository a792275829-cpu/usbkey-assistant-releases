import json
from pathlib import Path
import plistlib
import subprocess
import tarfile
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]


class PatchManifestTests(unittest.TestCase):
    def test_permission_only_change_is_included_in_patch(self):
        with tempfile.TemporaryDirectory(prefix="usbkey-patch-tests-") as temporary:
            root = Path(temporary)
            for name, version, mode in [("old", "1.0.0", 0o644), ("new", "1.0.1", 0o755)]:
                contents = root / (name + ".app") / "Contents"
                (contents / "MacOS").mkdir(parents=True)
                with (contents / "Info.plist").open("wb") as handle:
                    plistlib.dump({"CFBundleIdentifier": "cn.gdpower.usbkeyassistant",
                                   "CFBundleShortVersionString": version}, handle)
                helper = contents / "MacOS/helper"
                helper.write_text("#!/bin/sh\nexit 0\n")
                helper.chmod(mode)
                (contents / "MacOS/unchanged").write_text("unchanged")
            subprocess.run([
                "/usr/bin/python3", str(PROJECT / "scripts/build_patch.py"),
                "--from", str(root / "old.app"), "--app", str(root / "new.app"),
                "--out", str(root), "--force",
            ], check=True, capture_output=True, text=True)
            with tarfile.open(next(root.glob("*.tar.gz"))) as archive:
                manifest = json.load(archive.extractfile("patch.json"))
                files = {entry["path"]: entry for entry in manifest["files"]}
                self.assertEqual(files["Contents/MacOS/helper"]["mode"], "0755")
                self.assertNotIn("Contents/MacOS/unchanged", files)
                self.assertEqual(archive.getmember("Contents/MacOS/helper").mode, 0o755)
                base = {entry["path"]: entry for entry in manifest["base"]}
                self.assertEqual(base["Contents/MacOS/helper"]["sha256"],
                                 files["Contents/MacOS/helper"]["sha256"])


if __name__ == "__main__":
    unittest.main()
