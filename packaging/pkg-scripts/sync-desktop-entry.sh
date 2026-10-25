#!/bin/sh
# Keep an existing desktop entry attached to the canonical installation.
# Replace the old bundle with an entry to the installed application.
set -eu

SOURCE_APP=${1:?Missing installed application path}
DESKTOP_APP=${2:?Missing desktop application path}
EXPECTED_ID="cn.gdpower.usbkeyassistant"

SOURCE_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$SOURCE_APP/Contents/Info.plist" 2>/dev/null || true)
if [ "$SOURCE_ID" != "$EXPECTED_ID" ]; then
  echo "Installed application identity check failed; desktop entry was not changed." >&2
  exit 1
fi

# Do not create a new icon, follow an unknown link, or replace another app.
if [ -L "$DESKTOP_APP" ]; then
  if [ "$(/usr/bin/readlink "$DESKTOP_APP")" = "$SOURCE_APP" ]; then
    echo "Desktop entry already follows the installed application."
  else
    echo "Unrelated desktop link was preserved."
  fi
  exit 0
fi
if [ ! -d "$DESKTOP_APP" ]; then
  exit 0
fi
DESKTOP_ID=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$DESKTOP_APP/Contents/Info.plist" 2>/dev/null || true)
if [ "$DESKTOP_ID" != "$EXPECTED_ID" ]; then
  echo "Unrelated desktop application was preserved."
  exit 0
fi

# Stage on the same filesystem so a failed link creation can restore the old app.
BACKUP_DIR=$(/usr/bin/mktemp -d "$(/usr/bin/dirname "$DESKTOP_APP")/.usbkey-replace.XXXXXX")
BACKUP_APP="$BACKUP_DIR/$(/usr/bin/basename "$DESKTOP_APP")"
/bin/mv "$DESKTOP_APP" "$BACKUP_APP"
if ! /bin/ln -s "$SOURCE_APP" "$DESKTOP_APP"; then
  /bin/mv "$BACKUP_APP" "$DESKTOP_APP"
  /bin/rmdir "$BACKUP_DIR"
  echo "Could not create desktop entry; previous application was restored." >&2
  exit 1
fi
echo "Desktop entry now follows: $SOURCE_APP"
/bin/rm -rf "$BACKUP_DIR"
echo "Previous desktop application replaced."
