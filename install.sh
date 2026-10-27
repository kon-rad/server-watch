#!/bin/sh
# Install the latest server-watch release binary for this machine.
#   curl -fsSL https://raw.githubusercontent.com/kon-rad/server-watch/main/install.sh | sh
# Set SERVER_WATCH_VERSION=v0.1.0 to pin a version, INSTALL_DIR to choose where it goes.
set -eu

repo="kon-rad/server-watch"
os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
  Linux/x86_64)                target=x86_64-unknown-linux-gnu ;;
  Linux/aarch64|Linux/arm64)   target=aarch64-unknown-linux-gnu ;;
  Darwin/arm64)                target=aarch64-apple-darwin ;;
  Darwin/x86_64)               target=x86_64-apple-darwin ;;
  *) echo "server-watch: no prebuilt binary for $os/$arch. Try: cargo install server-watch" >&2; exit 1 ;;
esac

if [ -n "${SERVER_WATCH_VERSION:-}" ]; then
  base="https://github.com/$repo/releases/download/$SERVER_WATCH_VERSION"
else
  base="https://github.com/$repo/releases/latest/download"
fi
name="server-watch-$target"
dir=${INSTALL_DIR:-/usr/local/bin}
[ -w "$dir" ] || { [ "$(id -u)" = 0 ] || dir="$HOME/.local/bin"; }
mkdir -p "$dir"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/$name.tar.gz" -o "$tmp/$name.tar.gz"
curl -fsSL "$base/$name.tar.gz.sha256" -o "$tmp/$name.tar.gz.sha256"
want=$(cut -d' ' -f1 "$tmp/$name.tar.gz.sha256")
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1); else got=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1); fi
[ "$want" = "$got" ] || { echo "server-watch: checksum mismatch, refusing to install" >&2; exit 1; }
tar xzf "$tmp/$name.tar.gz" -C "$tmp"
install -m 0755 "$tmp/$name/server-watch" "$dir/server-watch"
echo "Installed $dir/server-watch ($("$dir/server-watch" --version))"
case ":$PATH:" in *":$dir:"*) ;; *) echo "Add $dir to your PATH." ;; esac
echo "Next: server-watch doctor"
