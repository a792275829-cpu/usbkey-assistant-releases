#!/bin/sh
# Publish the built disk image, an incremental patch when one applies, and their
# checksums. Source is committed and pushed separately before release.
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
APP_NAME=${APP_NAME:-广东电力USBKey助手}
VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$PROJECT_DIR/app/Info.plist")
REPOSITORY=$(/usr/libexec/PlistBuddy -c 'Print :GitHubUpdateRepository' "$PROJECT_DIR/app/Info.plist")
NOTES_FILE=${1:?Usage: scripts/publish_release.sh /path/to/release-notes.md}
DMG="$PROJECT_DIR/dist/$APP_NAME-$VERSION-apple-silicon.dmg"
PKG="$PROJECT_DIR/dist/$APP_NAME-$VERSION-apple-silicon.pkg"
test -f "$NOTES_FILE"
test -f "$DMG"
test -f "$DMG.sha256"
(
    cd "$PROJECT_DIR/dist"
    /usr/bin/shasum -a 256 -c "$(basename "$DMG").sha256"
)
# GitHub normalizes non-ASCII asset names, so publish predictable ASCII names.
UPLOAD_DIR="$PROJECT_DIR/build/github-release-$VERSION"
/bin/mkdir -p "$UPLOAD_DIR"
ASSETS=""
add_asset() {
    SOURCE=$1
    NAME=$2
    /bin/cp "$SOURCE" "$UPLOAD_DIR/$NAME"
    (
        cd "$UPLOAD_DIR"
        /usr/bin/shasum -a 256 "$NAME" > "$NAME.sha256"
    )
    ASSETS="$ASSETS $UPLOAD_DIR/$NAME $UPLOAD_DIR/$NAME.sha256"
    echo "Asset: $NAME ($(/usr/bin/stat -f %z "$SOURCE") bytes)"
}
add_asset "$DMG" "USBKeyAssistant-$VERSION-apple-silicon.dmg"
# Released alongside the image so installations that only know the package asset
# can still upgrade themselves. Stop publishing it once every client is on a
# disk-image build (BUILD_PKG=0).
if [ -f "$PKG" ] && [ -f "$PKG.sha256" ]; then
    ( cd "$PROJECT_DIR/dist" && /usr/bin/shasum -a 256 -c "$(basename "$PKG").sha256" )
    add_asset "$PKG" "USBKeyAssistant-$VERSION-apple-silicon.pkg"
else
    echo "No legacy package for this version; disk image only."
fi

# Most releases only change a few files. Offer a patch that upgrades the
# previous build in place; the client verifies it against its own installation
# and falls back to the full image when anything does not match.
PREVIOUS_VERSION=${PATCH_FROM:-$(/bin/sh "$SCRIPT_DIR/project-tool.sh" previous-version "$PROJECT_DIR/dist" "$VERSION")}
PATCH_PATH=""
if [ -n "$PREVIOUS_VERSION" ]; then
    PREVIOUS=""
    for SUFFIX in dmg pkg; do
        CANDIDATE="$PROJECT_DIR/dist/$APP_NAME-$PREVIOUS_VERSION-apple-silicon.$SUFFIX"
        if [ -f "$CANDIDATE" ]; then
            PREVIOUS="$CANDIDATE"
            break
        fi
    done
    if [ -n "$PREVIOUS" ]; then
        PATCH_OUTPUT=$(/bin/sh "$SCRIPT_DIR/project-tool.sh" patch --from "$PREVIOUS" 2>&1 || true)
        printf '%s\n' "$PATCH_OUTPUT" | /usr/bin/grep -v '^PATCH=' >&2 || true
        PATCH_PATH=$(printf '%s\n' "$PATCH_OUTPUT" | /usr/bin/sed -n 's/^PATCH=//p')
    else
        echo "Previous build not found locally for version $PREVIOUS_VERSION" >&2
    fi
fi

if [ -n "$PATCH_PATH" ] && [ -f "$PATCH_PATH" ]; then
    add_asset "$PATCH_PATH" "$(/usr/bin/basename "$PATCH_PATH")"
else
    echo "No incremental patch for this version; the disk image is published alone."
fi

# shellcheck disable=SC2086
gh release create "v$VERSION" $ASSETS \
    --repo "$REPOSITORY" --target main --title "USBKey 助手 v$VERSION" \
    --notes-file "$NOTES_FILE" --draft
# Only expose the release after all installer assets have finished uploading.
gh release edit "v$VERSION" --repo "$REPOSITORY" --draft=false --latest
