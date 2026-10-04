#!/usr/bin/bash
# Install the openconnect-gp CLI, polkit helper, and Omarchy bar widget.
# Asks for the portal address and which bar side gets the icon.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="/usr/local"
LIB_DIR="$PREFIX/lib/openconnect-gp"
BIN_PATH="$PREFIX/bin/ocgp"
PLUGIN_ID="openconnect-gp"
PLUGIN_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/$PLUGIN_ID"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/openconnect-gp"
PORTAL=""
USERNAME=""
SECTION=""
ASSUME_YES=0

fail() {
  echo "install: $*" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage: ./install.sh [--portal HOST] [--username NAME] [--section left|center|right] [--yes]

With no flags, asks for the portal and the bar side.
EOF
}

while (($# > 0)); do
  case "$1" in
    --portal)
      PORTAL="${2:-}"
      shift 2
      ;;
    --username)
      USERNAME="${2:-}"
      shift 2
      ;;
    --section)
      SECTION="${2:-}"
      shift 2
      ;;
    --yes)
      ASSUME_YES=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

command -v openconnect >/dev/null || fail "openconnect is not installed"
command -v python3 >/dev/null || fail "python3 is not installed"
[[ -x /usr/lib/openconnect/hipreport.sh ]] || fail "missing /usr/lib/openconnect/hipreport.sh"
[[ -x /etc/vpnc/vpnc-script ]] || fail "missing /etc/vpnc/vpnc-script"

interactive() {
  [[ -t 0 && -t 1 && $ASSUME_YES -eq 0 ]]
}

if [[ -z $PORTAL ]]; then
  interactive || fail "pass --portal"
  if command -v gum >/dev/null; then
    PORTAL="$(gum input --header "GlobalProtect portal address" --placeholder "vpn.example.com")"
  else
    read -r -p "GlobalProtect portal address: " PORTAL
  fi
fi
[[ -n $PORTAL ]] || fail "portal address is required"

if [[ -z $USERNAME && $ASSUME_YES -eq 0 ]]; then
  if interactive; then
    if command -v gum >/dev/null; then
      USERNAME="$(gum input --header "VPN username (blank is fine, the panel can store it later)" --placeholder "name or DOMAIN\\name")" || true
    else
      read -r -p "VPN username (blank is fine): " USERNAME
    fi
  fi
fi

if [[ -z $SECTION ]]; then
  interactive || fail "pass --section left, center, or right"
  if command -v gum >/dev/null; then
    SECTION="$(printf '%s\n' right left center | gum choose --header "Put the VPN icon on which side of the bar?" --selected right)"
  else
    echo "Put the VPN icon on which side of the bar?"
    select SECTION in right left center; do
      [[ -n $SECTION ]] && break
    done
  fi
fi
[[ $SECTION == left || $SECTION == center || $SECTION == right ]] || fail "section must be left, center, or right"

user_name="$(id -un)"
[[ $user_name =~ ^[A-Za-z0-9._-]+$ ]] || fail "user name cannot be embedded in the polkit rule"

echo "Installing CLI to $BIN_PATH"
echo "Polkit will let user $(id -un) connect and disconnect without a password prompt."
echo "The helper only starts or stops this tunnel."

sudo install -d -m 755 "$LIB_DIR"
sudo install -m 644 "$ROOT/src/ocgp.py" "$LIB_DIR/ocgp.py"
sudo tee "$BIN_PATH" >/dev/null <<EOF
#!/usr/bin/env python3
import runpy
runpy.run_path("${LIB_DIR}/ocgp.py", run_name="__main__")
EOF
sudo tee "$LIB_DIR/vpnc-split" >/dev/null <<EOF
#!/usr/bin/env python3
import runpy
import sys
sys.argv = [sys.argv[0], "_vpnc"]
runpy.run_path("${LIB_DIR}/ocgp.py", run_name="__main__")
EOF
sudo chmod 755 "$BIN_PATH" "$LIB_DIR/vpnc-split"
sudo install -Dm644 "$ROOT/share/polkit/org.openconnectgp.policy" /usr/share/polkit-1/actions/org.openconnectgp.policy
rule="$(sed "s/__USER__/${user_name}/g" "$ROOT/share/polkit/10-openconnect-gp.rules.in")"
rule_path="/etc/polkit-1/rules.d/10-openconnect-gp.rules"
printf '%s\n' "$rule" | sudo tee "$rule_path" >/dev/null
sudo chown root:polkitd "$rule_path"
sudo chmod 644 "$rule_path"
if command -v systemctl >/dev/null; then
  sudo systemctl reload polkit || true
fi

python3 - "$ROOT/src" "$PORTAL" "$USERNAME" "$CONFIG_DIR" <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import ocgp
portal = ocgp.normalize_portal(sys.argv[2])
username = ocgp.check_username(sys.argv[3])
path = Path(sys.argv[4]) / "config.json"
path.parent.mkdir(parents=True, exist_ok=True)
data = {}
if path.is_file():
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(loaded, dict):
        data = loaded
data["portal"] = portal
if username:
    data["username"] = username
data.setdefault("os", "linux")
data.setdefault("extra_routes", [])
data.setdefault("dns_domains", [])
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
os.chmod(path, 0o600)
print(path)
PY

if ! command -v omarchy >/dev/null; then
  echo "CLI installed. Omarchy is not on PATH, so the bar icon was not added."
  exit 0
fi

rm -rf "$PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR"
install -m 644 "$ROOT/manifest.json" "$ROOT/Panel.qml" "$ROOT/VpnIcon.qml" "$PLUGIN_DIR/"
omarchy-shell shell rescanPlugins >/dev/null || true
found=0
for _ in $(seq 1 40); do
  if omarchy plugin list --json | jq -e --arg id "$PLUGIN_ID" 'any(.[]; .id == $id)' >/dev/null; then
    found=1
    break
  fi
  sleep 0.05
done
[[ $found -eq 1 ]] || fail "shell did not see $PLUGIN_ID"
if jq -e --arg id "$PLUGIN_ID" '.. | objects | select(.id? == $id)' "${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/shell.json" >/dev/null; then
  omarchy bar move "$PLUGIN_ID" --section "$SECTION"
else
  omarchy plugin enable "$PLUGIN_ID" --section "$SECTION"
fi

echo
echo "Installed. Icon is on the $SECTION side of the bar."
echo "Portal saved. Open the icon, type the password, and connect. The password is not saved."
echo "Split tunnel is always on. Add extra CIDRs in the panel if the portal sends none."
if interactive; then
  read -r -p "Press enter to close. " _
fi
