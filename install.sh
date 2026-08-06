#!/bin/sh
set -eu

version="${GOVP_VERSION:-v0.1.11}"
install_dir="${GOVP_INSTALL_DIR:-/usr/local/bin}"

case "$(uname -s)" in
  Darwin) os="macos" ;;
  Linux) os="linux" ;;
  *) echo "govp: unsupported operating system" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  arm64|aarch64) arch="arm64" ;;
  x86_64|amd64) arch="x86_64" ;;
  *) echo "govp: unsupported architecture" >&2; exit 1 ;;
esac

asset="govp-${os}-${arch}"
base="https://govp.io/downloads/cli/${version}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

curl -fsSL "${base}/${asset}" -o "${tmp_dir}/${asset}"
curl -fsSL "${base}/SHA256SUMS" -o "${tmp_dir}/SHA256SUMS"

expected="$(awk -v name="$asset" '$2 == name { print $1 }' "${tmp_dir}/SHA256SUMS")"
actual="$(openssl dgst -sha256 "${tmp_dir}/${asset}" | awk '{print $NF}')"
if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
  echo "govp: checksum verification failed" >&2
  exit 1
fi

chmod +x "${tmp_dir}/${asset}"
if [ -w "$install_dir" ]; then
  mv "${tmp_dir}/${asset}" "${install_dir}/govp"
else
  sudo mv "${tmp_dir}/${asset}" "${install_dir}/govp"
fi

"${install_dir}/govp" self-test
echo "govp installed at ${install_dir}/govp"
