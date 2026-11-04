#!/usr/bin/env bash
# Build a reproducible, isolated Proton-compatible natpmpc client.
# NO apt replacement, no firewall changes, no VPN traffic, no automatic install.
set -Eeuo pipefail
umask 077

SOURCE_VERSION=20230423
SOURCE_URL="https://deb.debian.org/debian/pool/main/libn/libnatpmp/libnatpmp_${SOURCE_VERSION}.orig.tar.gz"
SOURCE_SHA256="0684ed2c8406437e7519a1bd20ea83780db871b3a3a5d752311ba3e889dbfc70"
DESTINATION="/usr/local/libexec/vpngw-natpmpc"
MODE="${1:---build-only}"

case "$MODE" in
  --build-only|--install|--verify) ;;
  *) echo "Usage: $0 [--build-only|--verify|--install]" >&2; exit 2 ;;
esac

for tool in sha256sum install; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done

if [[ "$MODE" == "--verify" ]]; then
  [[ -x "$DESTINATION" && -f "$DESTINATION.sha256" && -f "$DESTINATION.version" ]] || exit 1
  [[ "$(cat "$DESTINATION.version")" == "$SOURCE_VERSION" ]] || exit 1
  (cd /usr/local/libexec && sha256sum -c --status vpngw-natpmpc.sha256)
  exit
fi

for tool in curl make gcc readelf mktemp tar; do
  command -v "$tool" >/dev/null || { echo "Missing build dependency: $tool" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --connect-timeout 15 --max-time 90 "$SOURCE_URL" -o "$WORK/source.tar.gz"
printf '%s  %s\n' "$SOURCE_SHA256" "$WORK/source.tar.gz" | sha256sum --check --status || {
  echo "Upstream source SHA-256 mismatch; aborting" >&2
  exit 1
}
mkdir -m 0700 "$WORK/src"
tar -xzf "$WORK/source.tar.gz" -C "$WORK/src" --strip-components=1 --no-same-owner
make -C "$WORK/src" --no-print-directory natpmpc-static
BIN="$WORK/src/natpmpc-static"
[[ -s "$BIN" && -x "$BIN" ]] || { echo "Build output unavailable" >&2; exit 1; }
# The client may link to the system libc but must not resolve libnatpmp.so
# from Ubuntu 22.04 (which is known to be incompatible).
if readelf -d "$BIN" | grep -Eq 'Shared library: \[libnatpmp'; then
  echo "Unexpected dynamic libnatpmp dependency; aborting" >&2
  exit 1
fi

sha256sum "$BIN"
if [[ "$MODE" == "--build-only" ]]; then
  echo "Verified source $SOURCE_VERSION; isolated build succeeded. Nothing installed."
  exit 0
fi

[[ "$EUID" -eq 0 ]] || { echo "--install requires root" >&2; exit 1; }
install -d -m 0755 /usr/local/libexec
install -m 0755 "$BIN" "$DESTINATION.new"
(cd /usr/local/libexec && sha256sum vpngw-natpmpc.new > vpngw-natpmpc.sha256.new)
sed -i 's/vpngw-natpmpc.new/vpngw-natpmpc/' /usr/local/libexec/vpngw-natpmpc.sha256.new
printf '%s\n' "$SOURCE_VERSION" > "$DESTINATION.version.new"
chmod 0644 "$DESTINATION.version.new" /usr/local/libexec/vpngw-natpmpc.sha256.new
mv -f "$DESTINATION.new" "$DESTINATION"
mv -f "$DESTINATION.version.new" "$DESTINATION.version"
mv -f /usr/local/libexec/vpngw-natpmpc.sha256.new /usr/local/libexec/vpngw-natpmpc.sha256
"$0" --verify
echo "Isolated binary installed. Distribution natpmpc package left unchanged."
