#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VERSION=${VERSION:-$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PROJECT_DIR/app/Info.plist")}
APP_NAME=${APP_NAME:-广东电力USBKey助手}
ICON_SOURCE="$PROJECT_DIR/app/AppIconSource.jpg"
APP_BUNDLE="$PROJECT_DIR/build/release/$APP_NAME.app"
CONTENTS="$APP_BUNDLE/Contents"
RESOURCES="$CONTENTS/Resources"
MACOS="$CONTENTS/MacOS"
UNIVERSAL_DIR="$PROJECT_DIR/build/universal"
PACKAGE_ROOT="$PROJECT_DIR/build/package-root"
DIST_DIR="$PROJECT_DIR/dist"
PKG_PATH="$DIST_DIR/$APP_NAME-$VERSION-apple-silicon.pkg"
MIN_VERSION="12.0"
NETCA_TRUST_STORE="$PROJECT_DIR/vendor/netca/netca-trust.sqlite"

case "$PROJECT_DIR" in
  */newdriver) ;;
  *) echo "Unexpected project directory: $PROJECT_DIR" >&2; exit 1 ;;
esac

MACOSX_DEPLOYMENT_TARGET="$MIN_VERSION" "${CARGO:-$HOME/.cargo/bin/cargo}" build \
  --locked --release --target aarch64-apple-darwin --manifest-path "$PROJECT_DIR/rust-transport/Cargo.toml"

/bin/rm -rf "$PROJECT_DIR/build/release" "$UNIVERSAL_DIR" "$PACKAGE_ROOT"
/bin/mkdir -p "$MACOS" "$RESOURCES/bin" \
  "$RESOURCES/certs" "$UNIVERSAL_DIR/arm64" "$DIST_DIR"

if [ ! -f "$NETCA_TRUST_STORE" ]; then
  echo "NETCA trust store is missing: $NETCA_TRUST_STORE" >&2
  echo "It is committed; restore it from git, or copy the file" >&2
  echo "'commonappdata/NETCA/certs/trust' out of the extracted vendor bundle." >&2
  exit 1
fi

COMMON_CFLAGS="-std=c11 -O2 -Wall -Wextra -Wpedantic -mmacosx-version-min=$MIN_VERSION"
/usr/bin/clang $COMMON_CFLAGS -arch arm64 "$PROJECT_DIR/src/ft3000gm_hid_probe.c" \
  -o "$RESOURCES/bin/ft3000gm-hid-probe" \
  -framework IOKit -framework CoreFoundation -framework Security
/usr/bin/clang $COMMON_CFLAGS -arch arm64 "$PROJECT_DIR/src/ft3000gm_signer.c" \
  -o "$RESOURCES/bin/ft3000gm-signer" \
  -framework IOKit -framework CoreFoundation
/usr/bin/xcrun swiftc "$PROJECT_DIR"/app/*.swift \
  -parse-as-library -target "arm64-apple-macosx$MIN_VERSION" -O \
  -framework AppKit -framework Security -o "$MACOS/GDPowerUSBKeyAssistant"

/usr/bin/install -m 644 "$PROJECT_DIR/app/Info.plist" "$CONTENTS/Info.plist"
/usr/bin/install -m 644 "$NETCA_TRUST_STORE" "$RESOURCES/certs/netca-trust.sqlite"
/usr/bin/install -m 755 "$PROJECT_DIR/rust-transport/target/aarch64-apple-darwin/release/usbkey-transport" "$RESOURCES/bin/usbkey-transport"
/usr/bin/install -m 755 "$PROJECT_DIR/rust-transport/target/aarch64-apple-darwin/release/usbkey-worker" "$RESOURCES/bin/usbkey-worker"
"${CARGO:-$HOME/.cargo/bin/cargo}" metadata --locked --format-version 1 --filter-platform aarch64-apple-darwin \
  --manifest-path "$PROJECT_DIR/rust-transport/Cargo.toml" > "$UNIVERSAL_DIR/rust-metadata.json"
/usr/bin/python3 "$SCRIPT_DIR/collect_rust_notices.py" "$UNIVERSAL_DIR/rust-metadata.json" \
  "$RESOURCES/THIRD_PARTY_NOTICES.txt" --sysroot "$("${RUSTC:-$HOME/.cargo/bin/rustc}" --print sysroot)"
/usr/bin/install -m 755 "$PROJECT_DIR/packaging/uninstall.sh" "$RESOURCES/uninstall.sh"
ICONSET="$UNIVERSAL_DIR/AppIcon.iconset"
/bin/mkdir -p "$ICONSET"
for SPEC in \
  "16 icon_16x16.png" \
  "32 icon_16x16@2x.png" \
  "32 icon_32x32.png" \
  "64 icon_32x32@2x.png" \
  "128 icon_128x128.png" \
  "256 icon_128x128@2x.png" \
  "256 icon_256x256.png" \
  "512 icon_256x256@2x.png" \
  "512 icon_512x512.png" \
  "1024 icon_512x512@2x.png"
do
  SIZE=${SPEC%% *}
  NAME=${SPEC#* }
  /usr/bin/sips -s format png -z "$SIZE" "$SIZE" "$ICON_SOURCE" \
    --out "$ICONSET/$NAME" >/dev/null
done
/usr/bin/iconutil -c icns "$ICONSET" -o "$RESOURCES/AppIcon.icns"

/usr/bin/plutil -replace CFBundleShortVersionString -string "$VERSION" "$CONTENTS/Info.plist"
/usr/bin/plutil -replace CFBundleVersion -string "${BUILD_NUMBER:-1}" "$CONTENTS/Info.plist"
/usr/bin/plutil -lint "$CONTENTS/Info.plist"

SIGN_IDENTITY=${APP_SIGN_IDENTITY:--}
/usr/bin/codesign --force --deep --sign "$SIGN_IDENTITY" "$APP_BUNDLE"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
/usr/bin/python3 "$SCRIPT_DIR/check_native_bundle.py" "$APP_BUNDLE"
if [ "${SKIP_PACKAGE:-0}" = 1 ]; then
  echo "Application: $APP_BUNDLE"
  exit 0
fi

# Default distribution: a drag-and-drop disk image. Copying the bundle out of
# the image keeps it owned by the user who installed it, which is what makes
# later in-place updates work without an authorization prompt.
DMG_PATH=$(/bin/sh "$SCRIPT_DIR/build_dmg.sh" "$APP_BUNDLE" | /usr/bin/sed -n 's/^DMG=//p')

# The PKG is still built for clients that only know the package asset. Set
# BUILD_PKG=0 once every installation has moved to a DMG build.
if [ "${BUILD_PKG:-1}" = 0 ]; then
  echo "Application: $APP_BUNDLE"
  echo "Installer:   $DMG_PATH"
  echo "Checksum:    $DMG_PATH.sha256"
  exit 0
fi

/bin/mkdir -p "$PACKAGE_ROOT/Applications"
/usr/bin/ditto --norsrc --noextattr --noqtn --noacl \
  "$APP_BUNDLE" "$PACKAGE_ROOT/Applications/$APP_NAME.app"
/usr/bin/xattr -cr "$PACKAGE_ROOT"
/bin/chmod 755 "$PROJECT_DIR/packaging/pkg-scripts/preinstall" "$PROJECT_DIR/packaging/pkg-scripts/postinstall"

# Always upgrade the canonical application, even if a desktop entry exists.
COMPONENT_PLIST="$PROJECT_DIR/build/package-components.plist"
/usr/bin/pkgbuild --analyze --root "$PACKAGE_ROOT" "$COMPONENT_PLIST"
/usr/libexec/PlistBuddy -c 'Set :0:BundleIsRelocatable false' "$COMPONENT_PLIST" 2>/dev/null || \
  /usr/libexec/PlistBuddy -c 'Add :0:BundleIsRelocatable bool false' "$COMPONENT_PLIST"

PKGBUILD_ARGS=""
if [ -n "${PKG_SIGN_IDENTITY:-}" ]; then
  PKGBUILD_ARGS="--sign $PKG_SIGN_IDENTITY"
fi

# shellcheck disable=SC2086
/usr/bin/pkgbuild --root "$PACKAGE_ROOT" \
  --scripts "$PROJECT_DIR/packaging/pkg-scripts" \
  --component-plist "$COMPONENT_PLIST" \
  --identifier "cn.gdpower.usbkeyassistant.pkg" \
  --version "$VERSION" \
  --install-location / \
  --compression latest --min-os-version "$MIN_VERSION" \
  $PKGBUILD_ARGS "$PKG_PATH"

/usr/sbin/pkgutil --check-signature "$PKG_PATH" || true
(
  cd "$DIST_DIR"
  /usr/bin/shasum -a 256 "$(basename "$PKG_PATH")" > "$(basename "$PKG_PATH").sha256"
)

echo "Application: $APP_BUNDLE"
echo "Installer:   $DMG_PATH"
echo "Checksum:    $DMG_PATH.sha256"
echo "Package:     $PKG_PATH"
echo "PKG sha256:  $PKG_PATH.sha256"
