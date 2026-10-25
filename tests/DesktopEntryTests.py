"""Exercise desktop migration against temporary app bundles, without installing."""
import pathlib
import plistlib
import subprocess
import tempfile
import unittest

HELPER = pathlib.Path(__file__).resolve().parents[1] / 'packaging/pkg-scripts/sync-desktop-entry.sh'
BUNDLE_ID = 'cn.gdpower.usbkeyassistant'


class DesktopEntryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='usbkey-desktop-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.source = self.root / 'Applications/USBKey Assistant.app'
        self.desktop = self.root / 'User Home/Desktop/USBKey Assistant.app'
        self.backups = self.root / 'User Home/Library/Application Support/App Backups'
        self.desktop.parent.mkdir(parents=True)
        self.bundle(self.source, '1.1.17')

    def bundle(self, path, version, identifier=BUNDLE_ID):
        (path / 'Contents').mkdir(parents=True, exist_ok=True)
        with (path / 'Contents/Info.plist').open('wb') as handle:
            plistlib.dump({'CFBundleIdentifier': identifier, 'CFBundleShortVersionString': version}, handle)

    def migrate(self):
        return subprocess.run(['/bin/sh', str(HELPER), str(self.source), str(self.desktop)],
                              capture_output=True, text=True)

    def test_migration_replaces_old_bundle_and_follows_future_updates(self):
        self.bundle(self.desktop, '1.1.16')
        (self.desktop / 'Contents/original-data').write_text('preserve me')
        self.assertEqual(self.migrate().returncode, 0)
        self.assertTrue(self.desktop.is_symlink())
        self.assertEqual(self.desktop.resolve(), self.source.resolve())
        self.assertFalse(self.backups.exists())
        self.assertFalse((self.desktop / 'Contents/original-data').exists())
        self.assertEqual(list(self.desktop.parent.glob('.usbkey-replace.*')), [])
        self.bundle(self.source, '1.1.18')
        with (self.desktop / 'Contents/Info.plist').open('rb') as handle:
            self.assertEqual(plistlib.load(handle)['CFBundleShortVersionString'], '1.1.18')
        self.assertEqual(self.migrate().returncode, 0)
        self.assertFalse(self.backups.exists())

    def test_absent_desktop_entry_stays_absent(self):
        self.assertEqual(self.migrate().returncode, 0)
        self.assertFalse(self.desktop.exists())

    def test_unrelated_application_is_preserved(self):
        self.bundle(self.desktop, '1.0', 'example.unrelated')
        original = (self.desktop / 'Contents/Info.plist').read_bytes()
        self.assertEqual(self.migrate().returncode, 0)
        self.assertFalse(self.desktop.is_symlink())
        self.assertEqual((self.desktop / 'Contents/Info.plist').read_bytes(), original)

    def test_unrelated_symbolic_link_is_preserved(self):
        other = self.root / 'Other.app'
        self.bundle(other, '1.0')
        self.desktop.symlink_to(other)
        self.assertEqual(self.migrate().returncode, 0)
        self.assertEqual(self.desktop.resolve(), other.resolve())

    def test_unrelated_regular_file_is_preserved(self):
        self.desktop.write_text('unrelated')
        self.assertEqual(self.migrate().returncode, 0)
        self.assertEqual(self.desktop.read_text(), 'unrelated')

    def test_invalid_installation_does_not_change_desktop(self):
        self.bundle(self.desktop, '1.1.16')
        self.bundle(self.source, '1.0', 'example.unrelated')
        self.assertNotEqual(self.migrate().returncode, 0)
        self.assertFalse(self.desktop.is_symlink())
        self.assertFalse(self.backups.exists())


if __name__ == '__main__':
    unittest.main()
