# openconnect-gp

Split-tunnel GlobalProtect client for Linux. The tunnel is OpenConnect (`--protocol=gp`). The panel is an [Omarchy](https://omarchy.org/) bar widget in the Quattro shell: one icon, one popup, same type as the network and Tailscale panels.

The portal address is yours. Nothing in this repo points at a workplace.

The protocol flow follows the open client path documented by OpenConnect and used by [GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect): portal prelogin, `openconnect --authenticate`, then a cookie handed to a root helper that opens the tunnel. That project is the reference. This one does not copy it. Its GUI is proprietary; this panel is MIT.

## Split tunnel

The vpnc script wrapper drops every default route the gateway offers, including `0.0.0.0/0` and an IPv6 prefix of 0. It keeps the gateway's other split routes and any `extra_routes` you add. After connect, systemd-resolved is told the tunnel is not a default DNS route. VPN DNS is used only for the portal search domain, `CISCO_SPLIT_DNS`, and `dns_domains`.

If the portal sends only a full tunnel, the link still comes up, and no company route is installed until you add CIDRs.

## Install

Needs `openconnect`, `python3`, `vpnc` (for `/etc/vpnc/vpnc-script`), and, for the icon, Omarchy 4.

```bash
git clone https://github.com/deey001/openconnect_gp.git
cd openconnect_gp
./install.sh
```

The installer asks:

1. GlobalProtect portal address (`vpn.example.com` or `https://vpn.example.com/...`)
2. Username, which you can leave blank and set in the panel
3. Bar side: right, left, or center

It installs:

- `/usr/local/bin/ocgp`
- `/usr/local/lib/openconnect-gp/vpnc-split`
- a polkit action, plus a rule that lets the installing user connect and disconnect without a password prompt
- the bar widget `openconnect-gp`

Non-interactive:

```bash
./install.sh --portal vpn.example.com --username jdoe --section right --yes
```

Remove it with `./uninstall.sh`. That asks before deleting, and it leaves `~/.config/openconnect-gp/config.json` in place. The config has no password.

## Use

Left click the gate icon to open the panel. Right click connects or disconnects. The password is sent on stdin and is not written to disk, argv, or the status file.

```bash
ocgp connect
ocgp disconnect
ocgp status
ocgp prelogin
ocgp config set extra_routes "10.1.0.0/16, 192.168.0.0/16"
ocgp config set dns_domains "corp.example.com"
ocgp connect --browser
```

`connect --browser` is the SAML path (`--external-browser=xdg-open`). Password portals can ignore it. A second factor can go in the code field, or as a second line when you pipe JSON:

```bash
printf '%s\n' '{"password":"...","code":"123456"}' | ocgp connect
```

The panel has three HIP report buttons under the title: Windows, Linux, and Apple. The choice is sent on the next connect. The same choice from a terminal:

```bash
ocgp config set os apple-silicon
ocgp config set os win
```

`apple-silicon` sends the Mac HIP report: Xprotect, Gatekeeper, FileVault, and the built-in firewall, with macOS 26.0. OpenConnect 9.21 has no Apple Silicon token, so the client still passes `--os=mac-intel` to select that report. The report text does not say Intel. `win` sends the Windows report. The other OpenConnect values are `linux`, `linux-64`, `mac-intel`, `android`, and `apple-ios`.

OpenConnect logs the HIP report as `Trying to run HIP Trojan script`. That is upstream's name for `/usr/lib/openconnect/hipreport.sh`. A line that says the script completed is a normal report, not malware and not a failure. ESP often fails and the tunnel continues over HTTPS.

## Config

`~/.config/openconnect-gp/config.json`

```json
{
  "portal": "vpn.example.com",
  "username": "jdoe",
  "os": "linux",
  "extra_routes": ["10.1.0.0/16"],
  "dns_domains": ["corp.example.com"]
}
```

## What root is allowed to do

`pkexec` runs `/usr/local/bin/ocgp` only for `_tunnel` and `_disconnect`. The tunnel command checks the cookie, host, username, and OS, and it refuses a config path outside the invoking user's `openconnect-gp` directory. It then starts a system service, `ocgp.service`, so OpenConnect can open `/dev/net/tun`. A user-session `pkexec` stays in the session cgroup, and Omarchy closes that cgroup to the session devices. The script passed to OpenConnect is the split-tunnel wrapper, not a shell string from the portal.

OpenConnect writes `--pid-file` only together with `--background`. The service records its pid before the exec, and the helper treats an address on `ocgp0` as success. It does not stop a tunnel that already has an address. The status command runs as you, and OpenConnect runs as root, so a permission error on the pid still counts as alive.

The polkit rule allows the user who ran `install.sh`. It does not require a logind seat. Omarchy's Wayland session often has none, and polkit would otherwise deny the click with no dialog. Other users still get an admin prompt.

## License

MIT. OpenConnect itself is LGPL. The HIP report script used here is the one shipped with OpenConnect, not a copy stored in this repo.
