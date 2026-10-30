#!/bin/sh
set -eu

root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" != 0 ]; then
    echo 'Run this uninstaller as root: sudo sh uninstall.sh' >&2
    exit 1
fi
unit="$root/etc/systemd/system/sentryguard.service"
if [ ! -f "$unit" ] || ! grep -q '^ExecStart=/usr/local/bin/sentryguard run$' "$unit"; then
    echo 'No matching manual installation found. Use the package manager for DEB/RPM installations.' >&2
    exit 1
fi
if [ -z "$root" ] && [ -d /run/systemd/system ]; then
    systemctl stop sentryguard.service
    systemctl disable sentryguard.service
fi
rm -f "$root/usr/local/bin/sentryguard" "$unit" \
    "$root/usr/local/share/sentryguard/README.md" \
    "$root/usr/local/share/sentryguard/VERSION" \
    "$root/usr/local/share/sentryguard/LICENSE" \
    "$root/usr/local/share/sentryguard/assets/logo.svg" \
    "$root/usr/local/share/sentryguard/uninstall.sh"
if [ -z "$root" ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
echo 'SentryGuard uninstalled. Configuration, database, and existing bans were preserved.'
echo 'To remove bans, run sentryguard reset before uninstalling.'
