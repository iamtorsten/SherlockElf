#!/bin/bash

# Setze die notwendigen Umgebungsvariablen
export IOS_CERTID=""  # Hier die tatsächliche IOS_CERTID einfügen
CERTIFICATE_P12_PATH=""
CERTIFICATE_PASSWORD=""  # Hier das tatsächliche Passwort einfügen

# Git konfigurieren
git config --global user.name ""
git config --global user.email ""

# Decode and import the certificate
if [ ! -f "$CERTIFICATE_P12_PATH" ]; then
    echo "Certificate file $CERTIFICATE_P12_PATH does not exist."
    exit 1
else
    security import "$CERTIFICATE_P12_PATH" -k ~/Library/Keychains/login.keychain -P "$CERTIFICATE_PASSWORD" -T /usr/bin/codesign || {
        echo "Import failed, possibly due to incorrect password."
        exit 1
    }
    echo "Certificate imported successfully."
fi

# Verzeichnis des Skripts ermitteln
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
FRIDA_DIR="$SCRIPT_DIR/frida"
PATCH_DIR="$SCRIPT_DIR/patches/frida-core"

# Frida-Repository klonen und Submodule initialisieren
git clone --recurse-submodules https://github.com/frida/frida "$FRIDA_DIR"
cd "$FRIDA_DIR" || exit 1
git submodule update --init --recursive

# Patches anwenden
if [ -d "$PATCH_DIR" ]; then
    cd subprojects/frida-core || exit 1
    for patch in "$PATCH_DIR"/*.patch; do
        git am "$patch"
    done
    cd "$FRIDA_DIR" || exit 1
else
    echo "Directory $PATCH_DIR does not exist."
    exit 1
fi

# Build-Verzeichnis erstellen
mkdir -p build-ios-arm64
cd build-ios-arm64 || exit 1

# Frida konfigurieren und überprüfen
echo "Configuring the build..."
"$FRIDA_DIR/configure" --host=ios-arm64
if [ ! -f build.ninja ]; then
    echo "Error: build.ninja was not generated. Configuration failed."
    exit 1
fi

# Frida bauen
echo "Starting build with ninja..."
ninja subprojects/frida-core/lib/gadget/frida-gadget.dylib subprojects/frida-core/server/frida-server || {
    echo "Build failed for ios-arm64"
    ls -alh
    exit 1
}
echo "Build step completed."

# Ergebnisse verpacken und umbenennen
gzip -c subprojects/frida-core/lib/gadget/frida-gadget.dylib > "SherlockElf-frida-gadget.dylib.gz"
gzip -c subprojects/frida-core/server/frida-server > "SherlockElf-frida-server.gz"

echo "SherlockElf Gadget and Server have been built and packaged successfully."
