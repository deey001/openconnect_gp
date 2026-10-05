#!/usr/bin/bash
# shellcheck shell=bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../share/distro.sh
source "$root/share/distro.sh"

check() {
  local got
  got="$(distro_family "$1" "$2")"
  if [[ $got != "$3" ]]; then
    echo "distro_family($1, $2) = $got, want $3" >&2
    exit 1
  fi
}

check omarchy arch arch
check arch "" arch
check zorin ubuntu debian
check ubuntu debian debian
check debian "" debian
check linuxmint ubuntu debian
check pop "ubuntu debian" debian
check fedora "" unknown
check opensuse "suse opensuse" unknown
echo "distro family ok"
