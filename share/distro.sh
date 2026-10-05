# Distro family for the installer. Source this. Do not execute it.
# distro_family ID ID_LIKE  ->  arch | debian | unknown

distro_family() {
  local id="${1:-}" like="${2:-}"
  case "$id" in
    arch | omarchy | artix | manjaro | endeavouros | cachyos)
      printf '%s\n' arch
      return
      ;;
    zorin | ubuntu | debian | pop | linuxmint | elementary | neon | kali | raspbian)
      printf '%s\n' debian
      return
      ;;
  esac
  case " $like " in
    *" arch "* | *" archlinux "*)
      printf '%s\n' arch
      return
      ;;
    *" ubuntu "* | *" debian "*)
      printf '%s\n' debian
      return
      ;;
  esac
  printf '%s\n' unknown
}
