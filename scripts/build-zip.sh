#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(cat "$repo/VERSION")
case "$version" in ''|*[!0-9A-Za-z.+~-]*) echo 'Invalid VERSION' >&2; exit 1 ;; esac
case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    *) echo 'Only x86_64 and aarch64 build hosts are supported.' >&2; exit 1 ;;
esac
go_cmd=${GO:-go}
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT HUP INT TERM
name="sentryguard-${version}-linux-${arch}"
mkdir -p "$stage/$name" "$repo/dist"
(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$go_cmd" build -trimpath -ldflags='-s -w' -o "$stage/$name/sentryguard" .)
for file in install.sh uninstall.sh config.yaml sentryguard.service README.md VERSION LICENSE; do
    cp "$repo/$file" "$stage/$name/$file"
done
mkdir -p "$stage/$name/assets"
cp "$repo/assets/logo.svg" "$stage/$name/assets/logo.svg"
chmod 0755 "$stage/$name/install.sh" "$stage/$name/uninstall.sh"
python3 - "$stage" "$name" "$repo/dist/$name.zip" <<'PY'
import pathlib, sys, zipfile
stage, name, output = sys.argv[1:]
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted((pathlib.Path(stage) / name).rglob('*')):
        if path.is_file():
            archive.write(path, str(path.relative_to(stage)))
print('Built ' + output)
PY
