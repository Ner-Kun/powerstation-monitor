#!/data/data/com.termux/files/usr/bin/bash
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/ntfy-src"
BIN="$ROOT/bin/ntfy-cgo"

pkg install -y golang sqlite git

if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --branch v2.38.1 https://github.com/binwiederhier/ntfy "$SRC"
fi

mkdir -p "$SRC/server/site" "$SRC/server/docs" "$ROOT/bin"
printf '<html></html>' > "$SRC/server/site/index.html"
printf '<html></html>' > "$SRC/server/docs/index.html"

cd "$SRC"
CGO_ENABLED=1 go build \
  -tags sqlite_omit_load_extension,osusergo,netgo \
  -ldflags '-s -w' \
  -o "$BIN" .

echo "built $BIN"
