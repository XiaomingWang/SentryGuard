#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(cat "$repo/VERSION")
case "$version" in
    ''|*[!0-9A-Za-z.+~-]*) echo "Invalid VERSION: $version" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64) deb_arch=amd64; rpm_arch=x86_64; go_arch=amd64 ;;
    aarch64) deb_arch=arm64; rpm_arch=aarch64; go_arch=arm64 ;;
    *) echo 'Only x86_64 and aarch64 build hosts are supported.' >&2; exit 1 ;;
esac

go_cmd=${GO:-go}
rpm_cmd=${RPMBUILD:-rpmbuild}
command -v "$go_cmd" >/dev/null 2>&1 || { echo "Go toolchain not found: $go_cmd" >&2; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { echo 'dpkg-deb is required.' >&2; exit 1; }
command -v "$rpm_cmd" >/dev/null 2>&1 || { echo "rpmbuild is required: $rpm_cmd" >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
output="$repo/dist"
mkdir -p "$output" "$stage/deb/DEBIAN" "$stage/deb/usr/bin" \
    "$stage/deb/usr/lib/systemd/system" "$stage/deb/usr/share/doc/sentryguard" \
    "$stage/deb/etc/SentryGuard" "$stage/rpm/SOURCES" "$stage/rpm/SPECS" \
    "$stage/rpm/BUILD" "$stage/rpm/BUILDROOT" "$stage/rpm/RPMS" "$stage/rpm/SRPMS" "$stage/rpm/DB"

(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH="$go_arch" \
    "$go_cmd" build -trimpath -ldflags='-s -w' -o "$stage/sentryguard" .)

install -m 0755 "$stage/sentryguard" "$stage/deb/usr/bin/sentryguard"
install -m 0600 "$repo/config.yaml" "$stage/deb/etc/SentryGuard/config.yaml"
install -m 0644 "$repo/sentryguard.service" "$stage/deb/usr/lib/systemd/system/sentryguard.service"
install -m 0644 "$repo/README.md" "$stage/deb/usr/share/doc/sentryguard/README.md"
install -D -m 0644 "$repo/assets/logo.svg" "$stage/deb/usr/share/doc/sentryguard/assets/logo.svg"
install -m 0644 "$repo/LICENSE" "$stage/deb/usr/share/doc/sentryguard/copyright"
chmod 0700 "$stage/deb/etc/SentryGuard"
install -m 0755 "$repo/packaging/deb/postinst" "$stage/deb/DEBIAN/postinst"
install -m 0755 "$repo/packaging/deb/prerm" "$stage/deb/DEBIAN/prerm"
install -m 0755 "$repo/packaging/deb/postrm" "$stage/deb/DEBIAN/postrm"
printf '%s\n' '/etc/SentryGuard/config.yaml' > "$stage/deb/DEBIAN/conffiles"
cat > "$stage/deb/DEBIAN/control" <<EOF
Package: sentryguard
Version: $version
Section: admin
Priority: optional
Architecture: $deb_arch
Maintainer: SentryGuard local build <root@localhost>
Depends: systemd
Description: SSH failed-password monitor and IP ban manager
 SentryGuard monitors SSH password failures in the systemd journal,
 records IP bans in SQLite, and updates hosts.deny and optional nftables.
EOF
dpkg-deb --build --root-owner-group -Zxz "$stage/deb" \
    "$output/sentryguard_${version}_${deb_arch}.deb"

install -m 0755 "$stage/sentryguard" "$stage/rpm/SOURCES/sentryguard"
install -m 0600 "$repo/config.yaml" "$stage/rpm/SOURCES/config.yaml"
install -m 0644 "$repo/sentryguard.service" "$stage/rpm/SOURCES/sentryguard.service"
install -m 0644 "$repo/README.md" "$stage/rpm/SOURCES/README.md"
install -m 0644 "$repo/LICENSE" "$stage/rpm/SOURCES/LICENSE"
install -m 0644 "$repo/assets/logo.svg" "$stage/rpm/SOURCES/logo.svg"
sed -e "s/@VERSION@/$version/g" -e "s/@RPM_ARCH@/$rpm_arch/g" \
    "$repo/packaging/sentryguard.spec.in" > "$stage/rpm/SPECS/sentryguard.spec"
"$rpm_cmd" -bb --define "_topdir $stage/rpm" --define "_dbpath $stage/rpm/DB" \
    --define '_rpmformat 4' \
    --define '_binary_payload w9.gzdio' --define 'debug_package %{nil}' \
    "$stage/rpm/SPECS/sentryguard.spec"
install -m 0644 "$stage/rpm/RPMS/$rpm_arch/sentryguard-${version}-1.$rpm_arch.rpm" \
    "$output/sentryguard-${version}-1.$rpm_arch.rpm"
printf 'Built %s and %s\n' \
    "$output/sentryguard_${version}_${deb_arch}.deb" \
    "$output/sentryguard-${version}-1.$rpm_arch.rpm"
