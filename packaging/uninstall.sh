#!/bin/sh
set -eu

APP_NAME="广东电力USBKey助手"
APP_PATH="/Applications/$APP_NAME.app"
LABEL="cn.gdpower.usbkeyassistant"
TARGET_USER=${SUDO_USER:-$(/usr/bin/stat -f '%Su' /dev/console)}

if [ "$TARGET_USER" = "root" ] || [ "$TARGET_USER" = "loginwindow" ]; then
  echo "无法确定需要卸载的登录用户。" >&2
  exit 1
fi

if [ "$(/usr/bin/id -u)" -ne 0 ]; then
  exec /usr/bin/sudo "$0" "$@"
fi

TARGET_UID=$(/usr/bin/id -u "$TARGET_USER")
TARGET_HOME=$(/usr/bin/dscl . -read "/Users/$TARGET_USER" NFSHomeDirectory | /usr/bin/awk '{print $2}')
DATA_DIR="$TARGET_HOME/Library/Application Support/$APP_NAME"
AGENT_PATH="$TARGET_HOME/Library/LaunchAgents/$LABEL.plist"

/bin/launchctl bootout "gui/$TARGET_UID/$LABEL" 2>/dev/null || true
/usr/bin/pkill -f "$APP_PATH/Contents/MacOS/GDPowerUSBKeyAssistant" 2>/dev/null || true
/usr/bin/pkill -f "$APP_PATH/Contents/Resources/bin/usbkey-transport" 2>/dev/null || true
/usr/bin/pkill -f "$APP_PATH/Contents/Resources/bin/usbkey-worker" 2>/dev/null || true

if [ -s "$DATA_DIR/tls/localhost.crt" ]; then
  CERT_HASH=$(/usr/bin/openssl x509 -in "$DATA_DIR/tls/localhost.crt" -noout -fingerprint -sha1 \
    | /usr/bin/awk -F= '{gsub(":", "", $2); print $2}')
  if [ -n "$CERT_HASH" ]; then
    /usr/bin/security delete-certificate -Z "$CERT_HASH" /Library/Keychains/System.keychain 2>/dev/null || true
  fi
fi

/bin/rm -f "$AGENT_PATH"
/bin/rm -rf "$DATA_DIR" "$APP_PATH"
echo "$APP_NAME 已卸载。运行日志保留在 $TARGET_HOME/Library/Logs/$APP_NAME"
