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

Detects the distro and installs its packages.
Arch and Omarchy use pacman. Zorin, Ubuntu, and Debian use apt.
With no flags, asks for the portal. The bar side is asked only on Omarchy.
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

# shellcheck source=share/distro.sh
source "$ROOT/share/distro.sh"

interactive() {
  [[ -t 0 && -t 1 && $ASSUME_YES -eq 0 ]]
}

first_exec() {
  local path
  for path in "$@"; do
    if [[ -x $path ]]; then
      printf '%s\n' "$path"
      return 0
    fi
  done
  return 1
}

os_id="unknown"
os_like=""
if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  os_id="${ID:-unknown}"
  os_like="${ID_LIKE:-}"
fi
family="$(distro_family "$os_id" "$os_like")"
echo "Distro: ${os_id} (${family})"

packages_for() {
  case "$1" in
    arch) printf '%s\n' openconnect vpnc python polkit ;;
    debian) printf '%s\n' openconnect vpnc-scripts python3 policykit-1 systemd-resolved ;;
    *) return 1 ;;
  esac
}

package_installed() {
  case "$family" in
    arch) pacman -Q "$1" >/dev/null 2>&1 ;;
    debian) dpkg-query -W -f '${Status}' "$1" 2>/dev/null | grep -q 'install ok installed' ;;
    *) return 1 ;;
  esac
}

missing=()
if [[ $family == unknown ]]; then
  fail "distro '${os_id}' is not supported. Supported: Arch, Omarchy, Zorin, Ubuntu, Debian."
fi
while IFS= read -r pkg; do
  package_installed "$pkg" || missing+=("$pkg")
done < <(packages_for "$family")

if ((${#missing[@]} > 0)); then
  echo "Installing packages: ${missing[*]}"
  if [[ $ASSUME_YES -eq 0 ]]; then
    interactive || fail "pass --yes to install packages"
    read -r -p "Install these packages? [y/N] " answer
    [[ $answer == [yY] ]] || fail "package install declined"
  fi
  command -v sudo >/dev/null || fail "sudo is not installed"
  case "$family" in
    arch)
      if ! pacman -Si "${missing[@]}" >/dev/null 2>&1; then
        sudo pacman -Sy
      fi
      sudo pacman -S --needed --noconfirm "${missing[@]}"
      ;;
    debian)
      sudo apt-get update
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
      ;;
  esac
  hash -r
fi

oc_bin="$(command -v openconnect || true)"
if [[ -z $oc_bin ]]; then
  oc_bin="$(first_exec /usr/sbin/openconnect /usr/bin/openconnect || true)"
fi
[[ -n $oc_bin ]] || fail "openconnect is not installed"
command -v python3 >/dev/null || fail "python3 is not installed"
first_exec /usr/lib/openconnect/hipreport.sh /usr/libexec/openconnect/hipreport.sh >/dev/null \
  || fail "missing hipreport.sh"
first_exec /etc/vpnc/vpnc-script /usr/share/vpnc-scripts/vpnc-script >/dev/null \
  || fail "missing vpnc-script"

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

user_name="$(id -un)"
[[ $user_name =~ ^[A-Za-z0-9._-]+$ ]] || fail "user name cannot be embedded in the polkit rule"

echo "Installing CLI to $BIN_PATH"
echo "Polkit will let user $(id -un) connect and disconnect without a password prompt."
echo "The helper only starts or stops this tunnel."

sudo install -d -m 755 "$LIB_DIR" "$LIB_DIR/apple-silicon"
sudo install -m 644 "$ROOT/src/ocgp.py" "$LIB_DIR/ocgp.py"
sudo install -m 755 "$ROOT/share/hip-wrapper" "$LIB_DIR/hip-wrapper"
sudo install -m 755 "$ROOT/share/apple-silicon/sw_vers" "$LIB_DIR/apple-silicon/sw_vers"
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
sudo install -d -m 755 /etc/polkit-1/rules.d
polkit_group="polkitd"
if ! getent group polkitd >/dev/null; then
  if getent group polkit >/dev/null; then
    polkit_group="polkit"
  else
    fail "polkit group not found"
  fi
fi
printf '%s\n' "$rule" | sudo tee "$rule_path" >/dev/null
sudo chown "root:${polkit_group}" "$rule_path"
sudo chmod 644 "$rule_path"
# Zorin/Ubuntu polkit.service has no reload job. systemctl reload prints
# "Job type reload is not applicable" and changes nothing. polkitd watches
# rules.d itself. Arch/Omarchy CanReload=yes, so reload there.
if command -v systemctl >/dev/null && [[ $(systemctl show polkit.service -p CanReload --value 2>/dev/null || true) == yes ]]; then
  sudo systemctl reload polkit
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
  echo "CLI installed. No Omarchy bar on this distro. Connect with: ocgp connect"
  exit 0
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
