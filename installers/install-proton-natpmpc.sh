#!/usr/bin/env bash
# Provision a pinned, private Proton-compatible natpmpc without replacing OS packages.
set -Eeuo pipefail

SOURCE_URL="https://miniupnp.tuxfamily.org/files/libnatpmp-20230423.tar.gz"
SOURCE_SHA256="0684ed2c8406437e7519a1bd20ea83780db871b3a3a5d752311ba3e889dbfc70"
TARGET="/usr/local/libexec/vpngw-natpmpc"
VERSION="20230423"

[[ ${EUID} -eq 0 ]] || { echo "root required" >&2; exit 1; }
install -d -o root -g root -m 0755 /usr/local/libexec

# Avoid a build when the private binary has already been verified.
if [[ -f "${TARGET}" && -f "${TARGET}.sha256" && -f "${TARGET}.version" ]] \
   && [[ "$(cat "${TARGET}.version")" == "${VERSION}" ]] \
   && (cd /usr/local/libexec && sha256sum -c vpngw-natpmpc.sha256 >/dev/null); then
  echo "Private natpmpc ${VERSION} already verified"
  exit 0
fi

for tool in curl tar sha256sum gcc make install; do
  if ! command -v "${tool}" >/dev/null; then
    if [[ "${VPNGW_PROVISION_BUILD_TOOLS:-1}" == "1" ]] \
       && command -v apt-get >/dev/null; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        --no-install-recommends curl gcc make libc6-dev
      break
    fi
    echo "Missing build dependency: ${tool}" >&2
    exit 1
  fi
done
for tool in curl tar sha256sum gcc make install; do
  command -v "${tool}" >/dev/null || exit 1
done

tmp="$(mktemp -d /tmp/vpngw-natpmp.XXXXXXXX)"
trap 'rm -rf -- "${tmp}"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --max-time 90 \
  "${SOURCE_URL}" -o "${tmp}/source.tar.gz"
printf '%s  %s\n' "${SOURCE_SHA256}" "${tmp}/source.tar.gz" | sha256sum -c -
tar -xzf "${tmp}/source.tar.gz" -C "${tmp}"
make -C "${tmp}/libnatpmp-20230423" all

# Static executable does not depend on the outdated system libnatpmp.so.
install -o root -g root -m 0755 \
  "${tmp}/libnatpmp-20230423/natpmpc-static" "${TARGET}"
printf '%s\n' "${VERSION}" > "${TARGET}.version"
chmod 0644 "${TARGET}.version"
(cd /usr/local/libexec && sha256sum vpngw-natpmpc > vpngw-natpmpc.sha256 \
  && chmod 0644 vpngw-natpmpc.sha256 \
  && sha256sum -c vpngw-natpmpc.sha256)
echo "Private Proton-compatible natpmpc ${VERSION} installed"
