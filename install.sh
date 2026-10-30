#!/bin/sh
set -eu

src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${DESTDIR:-}
if [ -z "$root" ] && [ "$(id -u)" != 0 ]; then
    echo 'Run this installer as root: sudo sh install.sh' >&2
    exit 1
fi
for file in sentryguard config.yaml sentryguard.service README.md uninstall.sh VERSION LICENSE; do
    test -f "$src/$file" || { echo "Missing installation file: $file" >&2; exit 1; }
done
if [ -e "$root/usr/bin/sentryguard" ] || [ -e "$root/usr/lib/systemd/system/sentryguard.service" ] || [ -e "$root/lib/systemd/system/sentryguard.service" ]; then
    echo 'A packaged installation exists. Remove it with its package manager before manual installation.' >&2
    exit 1
fi
if [ -L "$root/etc/SentryGuard" ] || [ -L "$root/etc/SentryGuard/config.yaml" ]; then
    echo 'The configuration directory and file must not be symbolic links.' >&2
    exit 1
fi
if [ -e "$root/etc/systemd/system/sentryguard.service" ] && ! grep -q '^ExecStart=/usr/local/bin/sentryguard run$' "$root/etc/systemd/system/sentryguard.service"; then
    echo 'An unrelated sentryguard.service exists; installation stopped.' >&2
    exit 1
fi
install -d -m 0755 "$root/usr/local/bin" "$root/etc/systemd/system" "$root/usr/local/share/sentryguard"
install -d -m 0700 "$root/etc/SentryGuard"
install -m 0755 "$src/sentryguard" "$root/usr/local/bin/sentryguard"
if [ ! -e "$root/etc/SentryGuard/config.yaml" ]; then
    install -m 0600 "$src/config.yaml" "$root/etc/SentryGuard/config.yaml"
fi
sed 's|ExecStart=/usr/bin/sentryguard|ExecStart=/usr/local/bin/sentryguard|' "$src/sentryguard.service" > "$root/etc/systemd/system/sentryguard.service"
chmod 0644 "$root/etc/systemd/system/sentryguard.service"
install -m 0755 "$src/uninstall.sh" "$root/usr/local/share/sentryguard/uninstall.sh"
install -m 0644 "$src/README.md" "$root/usr/local/share/sentryguard/README.md"
install -m 0644 "$src/VERSION" "$root/usr/local/share/sentryguard/VERSION"
install -m 0644 "$src/LICENSE" "$root/usr/local/share/sentryguard/LICENSE"
install -D -m 0644 "$src/assets/logo.svg" "$root/usr/local/share/sentryguard/assets/logo.svg"
if [ -z "$root" ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
echo 'Installed SentryGuard. Existing configuration was preserved.'
echo 'Start or restart the service: sudo systemctl enable --now sentryguard'
echo 'After an upgrade, use: sudo systemctl restart sentryguard'
