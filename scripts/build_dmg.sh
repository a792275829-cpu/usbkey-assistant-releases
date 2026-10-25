#!/bin/sh
# Package the signed application as a drag-and-drop disk image.
#
# The image contains the application next to an /Applications symlink, so the
# user installs by dragging and the resulting bundle belongs to them. That is
# what lets later updates replace the application in place without asking for
# an administrator password every time.
#
# Usage: sh scripts/build_dmg.sh [path/to/App.app]
# Prints: DMG=<absolute path>
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
APP_NAME=${APP_NAME:-广东电力USBKey助手}
APP_BUNDLE=${1:-"$PROJECT_DIR/build/release/$APP_NAME.app"}
DIST_DIR="$PROJECT_DIR/dist"
ROOT="$PROJECT_DIR/build/dmg-root"
VOLUME_NAME=${VOLUME_NAME:-USBKey 助手}

if [ ! -d "$APP_BUNDLE" ]; then
  echo "Missing application bundle: $APP_BUNDLE" >&2
  exit 1
fi
if [ ! -f "$APP_BUNDLE/Contents/Info.plist" ]; then
  echo "Not an application bundle: $APP_BUNDLE" >&2
  exit 1
fi

VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_BUNDLE/Contents/Info.plist")
IDENTIFIER=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$APP_BUNDLE/Contents/Info.plist")
if [ "$IDENTIFIER" != "cn.gdpower.usbkeyassistant" ]; then
  echo "Unexpected bundle identifier: $IDENTIFIER" >&2
  exit 1
fi

DMG_PATH="$DIST_DIR/$APP_NAME-$VERSION-apple-silicon.dmg"
/bin/mkdir -p "$DIST_DIR"
/bin/rm -rf "$ROOT"
/bin/mkdir -p "$ROOT"

# Copy without resource forks or quarantine data; the volume only offers the
# bundle and the drop target.
/usr/bin/ditto --norsrc --noextattr --noqtn --noacl \
  "$APP_BUNDLE" "$ROOT/$APP_NAME.app"
/bin/ln -s /Applications "$ROOT/Applications"
/usr/bin/xattr -cr "$ROOT" 2>/dev/null || true

/bin/rm -f "$DMG_PATH"
# diskutil replaced the deprecated `hdiutil create -volname`; keep hdiutil as a
# fallback for build machines without it.
if ! /usr/sbin/diskutil image create from "$ROOT" \
      --volumeName "$VOLUME_NAME $VERSION" --format UDZO "$DMG_PATH" >/dev/null 2>&1; then
  /usr/bin/hdiutil create \
    -volname "$VOLUME_NAME $VERSION" \
    -srcfolder "$ROOT" \
    -fs HFS+ \
    -format UDZO \
    -imagekey zlib-level=9 \
    -ov "$DMG_PATH" >/dev/null
fi

/usr/bin/hdiutil verify "$DMG_PATH" >/dev/null

(
  cd "$DIST_DIR"
  /usr/bin/shasum -a 256 "$(basename "$DMG_PATH")" > "$(basename "$DMG_PATH").sha256"
) 2>/dev/null

/bin/rm -rf "$ROOT"
echo "DMG=$DMG_PATH"
