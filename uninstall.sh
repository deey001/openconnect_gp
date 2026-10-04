#!/usr/bin/bash
# Remove the CLI, polkit rule, and bar widget. Leaves the user config in place.

set -euo pipefail

PLUGIN_ID="openconnect-gp"
PLUGIN_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/$PLUGIN_ID"

if [[ -t 0 && -t 1 ]] && command -v gum >/dev/null; then
  gum confirm "Remove openconnect-gp from this machine?" || exit 1
elif [[ -t 0 && -t 1 ]]; then
  read -r -p "Remove openconnect-gp from this machine? [y/N] " answer
  [[ $answer == y || $answer == Y ]] || exit 1
else
  echo "Pass a terminal to confirm uninstall." >&2
  exit 1
fi

if command -v ocgp >/dev/null; then
  ocgp disconnect || true
fi

if command -v omarchy >/dev/null && [[ -d $PLUGIN_DIR ]]; then
  omarchy plugin disable "$PLUGIN_ID" || true
fi
rm -rf "$PLUGIN_DIR"

sudo rm -f /usr/local/bin/ocgp
sudo rm -rf /usr/local/lib/openconnect-gp
sudo rm -f /usr/share/polkit-1/actions/org.openconnectgp.policy
sudo rm -f /etc/polkit-1/rules.d/10-openconnect-gp.rules
if command -v systemctl >/dev/null; then
  sudo systemctl reload polkit || true
fi
if command -v omarchy-shell >/dev/null; then
  omarchy-shell shell rescanPlugins >/dev/null || true
fi

echo "Removed. Config left at ${XDG_CONFIG_HOME:-$HOME/.config}/openconnect-gp/config.json"
