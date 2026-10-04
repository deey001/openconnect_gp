#!/usr/bin/env python3
"""OpenConnect GlobalProtect client with a hard split tunnel.

Password and cookie stay off argv. The default route is never installed.
"""

from __future__ import annotations

import errno
import fcntl
import getpass
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

IFACE = "ocgp0"
RUN_DIR = Path("/run/openconnect-gp")
PID_FILE = RUN_DIR / "openconnect.pid"
STATUS_FILE = RUN_DIR / "status.json"
LOCK_FILE = RUN_DIR / "lock"
COOKIE_FILE = RUN_DIR / "cookie"
TUNNEL_ENV = RUN_DIR / "tunnel.env"
SERVICE = "ocgp.service"
REAL_VPNC = Path("/etc/vpnc/vpnc-script")
HIP_SCRIPT = Path("/usr/lib/openconnect/hipreport.sh")
LIB_DIR = Path("/usr/local/lib/openconnect-gp")
HELPER = Path("/usr/local/bin/ocgp")
OS_CHOICES = {"linux", "linux-64", "win", "mac-intel", "apple-silicon", "android", "apple-ios"}
# OpenConnect 9.21 accepts only mac-intel for a Mac. That value selects the
# Mac HIP report. apple-silicon keeps the same report and replaces the
# Intel-era 10.16.0 fallback with a current macOS version.
OPENCONNECT_OS = {"apple-silicon": "mac-intel"}
PORTAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
USER_RE = re.compile(r"^[\w.@\\-]{1,128}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9:+/=_-]{8,256}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
AUTH_LINE_RE = re.compile(r"^([A-Z][A-Z0-9_]*)='(.*)'$")


def config_path() -> Path:
    override = os.environ.get("OCGP_CONFIG")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "openconnect-gp" / "config.json"


def default_config() -> dict:
    return {
        "portal": "",
        "username": "",
        "os": "linux",
        "extra_routes": [],
        "dns_domains": [],
    }


def load_config(path: Path | None = None) -> dict:
    path = path or config_path()
    data = default_config()
    if path.is_file():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise SystemExit("config is not a JSON object")
        data.update(loaded)
    data["extra_routes"] = list(data.get("extra_routes") or [])
    data["dns_domains"] = list(data.get("dns_domains") or [])
    return data


def save_config(data: dict, path: Path | None = None) -> None:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def normalize_portal(value: str) -> str:
    text = value.strip()
    text = re.sub(r"^https?://", "", text, flags=re.IGNORECASE)
    text = text.split("/")[0].strip()
    if not PORTAL_RE.fullmatch(text):
        raise ValueError(f"portal address refused: {value!r}")
    return text


def check_username(value: str) -> str:
    text = value.strip()
    if text and not USER_RE.fullmatch(text):
        raise ValueError("username has characters this client will not send")
    return text


def check_os_name(value: str) -> str:
    text = (value or "linux").strip()
    if text not in OS_CHOICES:
        raise ValueError(f"os must be one of: {', '.join(sorted(OS_CHOICES))}")
    return text


def openconnect_os(os_name: str) -> str:
    return OPENCONNECT_OS.get(os_name, os_name)


def ipv4_ok(addr: str) -> bool:
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return False
    return all(0 <= num <= 255 for num in nums)


def mask_from_len(length: int) -> str:
    bits = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
    return ".".join(str((bits >> shift) & 255) for shift in (24, 16, 8, 0))


def parse_cidr(cidr: str) -> tuple[str, str, str]:
    text = cidr.strip()
    addr, sep, length_text = text.partition("/")
    if not sep or not ipv4_ok(addr):
        raise ValueError(f"not an IPv4 CIDR: {cidr}")
    try:
        length = int(length_text)
    except ValueError as exc:
        raise ValueError(f"not an IPv4 CIDR: {cidr}") from exc
    if not 1 <= length <= 32:
        raise ValueError(f"prefix length refused: {cidr}")
    if addr == "0.0.0.0":
        raise ValueError("0.0.0.0 is a default route and is refused")
    return addr, mask_from_len(length), str(length)


def parse_route_list(value: str) -> list[str]:
    routes: list[str] = []
    for item in re.split(r"[\s,]+", value.strip()):
        if not item:
            continue
        addr, _mask, length = parse_cidr(item)
        routes.append(f"{addr}/{length}")
    return routes


def parse_domain_list(value: str) -> list[str]:
    domains: list[str] = []
    for item in re.split(r"[\s,]+", value.strip()):
        if not item:
            continue
        name = item[1:] if item.startswith("~") else item
        if not DOMAIN_RE.fullmatch(name):
            raise ValueError(f"DNS domain refused: {item}")
        domains.append(name)
    return domains


def scrub(text: str) -> str:
    kept = []
    for line in text.splitlines():
        lowered = line.lower()
        if "cookie" in lowered or "password" in lowered or "passwd" in lowered:
            continue
        kept.append(line)
    message = "\n".join(kept[-8:]).strip()
    return message[:500]


def parse_auth_output(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        match = AUTH_LINE_RE.match(line.strip())
        if match:
            found[match.group(1)] = match.group(2)
    return found


def _drop_indexed(env: dict[str, str], prefix: str) -> None:
    for key in list(env):
        if key.startswith(prefix):
            del env[key]


def _v4_includes(env: dict[str, str]) -> list[tuple[str, str, str]]:
    try:
        count = int(env.get("CISCO_SPLIT_INC") or 0)
    except ValueError:
        count = 0
    routes = []
    for index in range(max(0, count)):
        addr = env.get(f"CISCO_SPLIT_INC_{index}_ADDR", "")
        mask = env.get(f"CISCO_SPLIT_INC_{index}_MASK", "")
        length = env.get(f"CISCO_SPLIT_INC_{index}_MASKLEN", "")
        if not ipv4_ok(addr) or addr == "0.0.0.0":
            continue
        if length in {"", "0"}:
            continue
        routes.append((addr, mask, length))
    return routes


def _v6_includes(env: dict[str, str]) -> list[tuple[str, str]]:
    try:
        count = int(env.get("CISCO_IPV6_SPLIT_INC") or 0)
    except ValueError:
        count = 0
    routes = []
    for index in range(max(0, count)):
        addr = env.get(f"CISCO_IPV6_SPLIT_INC_{index}_ADDR", "")
        length = env.get(f"CISCO_IPV6_SPLIT_INC_{index}_MASKLEN", "")
        if not addr or length in {"", "0"}:
            continue
        routes.append((addr, length))
    return routes


def extra_routes_from_config(path: str | None) -> list[tuple[str, str, str]]:
    if not path:
        return []
    file = Path(path)
    if not file.is_file():
        return []
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    routes = []
    for item in data.get("extra_routes") or []:
        try:
            routes.append(parse_cidr(str(item)))
        except ValueError:
            continue
    return routes


def dns_domains(env: dict[str, str], path: str | None) -> list[str]:
    names: list[str] = []
    for key in ("CISCO_DEF_DOMAIN", "CISCO_SPLIT_DNS"):
        raw = env.get(key, "")
        for item in raw.replace(",", " ").split():
            name = item[1:] if item.startswith("~") else item
            if DOMAIN_RE.fullmatch(name):
                names.append(name)
    if path and Path(path).is_file():
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for item in data.get("dns_domains") or []:
            name = str(item)
            name = name[1:] if name.startswith("~") else name
            if DOMAIN_RE.fullmatch(name):
                names.append(name)
    unique = []
    seen = set()
    for name in names:
        if name not in seen:
            seen.add(name)
            unique.append("~" + name)
    return unique


def rewrite_split_env(env: dict[str, str], config: str | None = None) -> dict[str, str]:
    """Return env that cannot install an IPv4 or IPv6 default route."""
    updated = dict(env)
    routes = _v4_includes(updated)
    seen = {addr for addr, _mask, _length in routes}
    for addr, mask, length in extra_routes_from_config(config):
        if addr not in seen:
            routes.append((addr, mask, length))
            seen.add(addr)
    _drop_indexed(updated, "CISCO_SPLIT_INC_")
    # "0" is non-empty, so vpnc-script takes the split loop and skips
    # set_ipv4_default_route. An empty value would install the default route.
    updated["CISCO_SPLIT_INC"] = str(len(routes)) if routes else "0"
    for index, (addr, mask, length) in enumerate(routes):
        updated[f"CISCO_SPLIT_INC_{index}_ADDR"] = addr
        updated[f"CISCO_SPLIT_INC_{index}_MASK"] = mask or mask_from_len(int(length))
        updated[f"CISCO_SPLIT_INC_{index}_MASKLEN"] = length

    v6 = _v6_includes(updated)
    _drop_indexed(updated, "CISCO_IPV6_SPLIT_INC_")
    if v6 or updated.get("INTERNAL_IP6_ADDRESS") or updated.get("INTERNAL_IP6_NETMASK"):
        updated["CISCO_IPV6_SPLIT_INC"] = str(len(v6)) if v6 else "0"
        for index, (addr, length) in enumerate(v6):
            updated[f"CISCO_IPV6_SPLIT_INC_{index}_ADDR"] = addr
            updated[f"CISCO_IPV6_SPLIT_INC_{index}_MASKLEN"] = length
    return updated


def apply_split_dns(env: dict[str, str], config: str | None) -> None:
    tundev = env.get("TUNDEV", "")
    if not tundev or not Path("/usr/bin/resolvectl").exists():
        return
    subprocess.run(
        ["/usr/bin/resolvectl", "default-route", tundev, "false"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    domains = dns_domains(env, config)
    if domains:
        subprocess.run(
            ["/usr/bin/resolvectl", "domain", tundev, *domains],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def vpnc_main() -> int:
    reason = os.environ.get("reason", "")
    config = os.environ.get("OCGP_CONFIG", "")
    env = os.environ.copy()
    if reason in {"connect", "disconnect", "reconnect"}:
        env = rewrite_split_env(env, config or None)
    if not REAL_VPNC.is_file():
        print(f"missing {REAL_VPNC}", file=sys.stderr)
        return 1
    result = subprocess.run([str(REAL_VPNC)], env=env, check=False)
    if reason == "connect":
        apply_split_dns(env, config or None)
    return result.returncode


def write_status(payload: dict) -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(RUN_DIR, 0o755)
    tmp = STATUS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    tmp.replace(STATUS_FILE)


def read_status_file() -> dict:
    try:
        data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def pid_alive(pid: int) -> bool:
    """True when the pid exists.

    Signal 0 does not kill the process. A root OpenConnect returns EPERM to
    the desktop user; that still means the pid is alive. ESRCH means it exited.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as exc:
        return exc.errno == errno.EPERM
    return True


def read_pid() -> int | None:
    try:
        text = PID_FILE.read_text(encoding="utf-8").strip()
        pid = int(text)
    except (OSError, ValueError):
        return None
    return pid


def our_openconnect(pid: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False
    cmd = raw.replace(b"\x00", b" ").decode("utf-8", "replace")
    return "openconnect" in cmd and IFACE in cmd


def service_main_pid() -> int | None:
    try:
        raw = subprocess.check_output(
            ["systemctl", "show", SERVICE, "-p", "MainPID", "--value"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    text = raw.strip()
    if text.isdigit() and int(text) > 0:
        return int(text)
    return None


def connected_pid() -> int | None:
    """Pid of the live tunnel. OpenConnect writes --pid-file only with --background."""
    seen: set[int] = set()
    for pid in (read_pid(), service_main_pid()):
        if not pid or pid in seen:
            continue
        seen.add(pid)
        if pid_alive(pid) and our_openconnect(pid):
            return pid
    return None


def ip_json(args: list[str]) -> list:
    try:
        raw = subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def iface_ipv4() -> str:
    for entry in ip_json(["ip", "-j", "addr", "show", "dev", IFACE]):
        for addr in entry.get("addr_info") or []:
            if addr.get("family") == "inet":
                return str(addr.get("local") or "")
    return ""


def iface_routes() -> list[str]:
    routes = []
    for entry in ip_json(["ip", "-j", "route", "show", "dev", IFACE]):
        dst = str(entry.get("dst") or "")
        if dst:
            routes.append(dst)
    for entry in ip_json(["ip", "-6", "-j", "route", "show", "dev", IFACE]):
        dst = str(entry.get("dst") or "")
        if dst and dst not in routes:
            routes.append(dst)
    return routes


def default_route_present(routes: list[str]) -> bool:
    return any(route in {"default", "0.0.0.0/0", "::/0"} for route in routes)


def phase_state(stored_state: str, pid: int | None, ipv4: str, since: float, now: float) -> str:
    """What the panel should show. A dead process is never connected."""
    if pid and ipv4:
        return "connected"
    if pid or (stored_state == "connecting" and now - since < 90):
        return "connecting"
    if stored_state == "error" or (stored_state == "connected" and not pid):
        return "error"
    return "disconnected"


def build_status() -> dict:
    cfg = {}
    try:
        cfg = load_config()
    except (OSError, json.JSONDecodeError, SystemExit):
        cfg = default_config()
    stored = read_status_file()
    pid = connected_pid()
    routes = iface_routes() if pid else []
    ipv4 = iface_ipv4() if pid else ""
    started = float(stored.get("since") or 0)
    state = phase_state(str(stored.get("state") or ""), pid, ipv4, started, time.time())
    message = "" if state == "connected" else str(stored.get("message") or "")
    if state == "error" and not message:
        message = "Tunnel process exited during setup"
    if state == "connected" and not any("/" in route and route not in {"default", "0.0.0.0/0", "::/0"} for route in routes):
        message = "Tunnel is up with no split routes. Add extra CIDRs, or the portal sent only a full tunnel."
    if state == "connected" and default_route_present(routes):
        state = "error"
        message = "Default route landed on the tunnel. Disconnect. Split tunnel refused to keep it."
    return {
        "state": state,
        "portal": cfg.get("portal") or stored.get("portal") or "",
        "username": cfg.get("username") or "",
        "os": cfg.get("os") or "linux",
        "extra_routes": cfg.get("extra_routes") or [],
        "dns_domains": cfg.get("dns_domains") or [],
        "gateway": stored.get("gateway") or "",
        "ipv4": ipv4,
        "interface": IFACE,
        "split": True,
        "routes": routes,
        "message": message,
        "pid": pid,
        "connected_at": stored.get("connected_at"),
    }


def notify(title: str, body: str) -> None:
    if not Path("/usr/bin/notify-send").exists():
        return
    subprocess.run(
        ["notify-send", "-a", "openconnect-gp", title, body[:180]],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def prelogin(portal: str) -> dict:
    host = normalize_portal(portal)
    url = f"https://{host}/global-protect/prelogin.esp"
    body = urllib.parse.urlencode(
        {"tmp": "tmp", "clientVer": "4100", "clientos": "Linux"}
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "PAN GlobalProtect",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read()
    except urllib.error.URLError as exc:
        raise SystemExit(f"prelogin failed: {exc}") from exc
    root = ET.fromstring(payload)
    values = {child.tag.split("}")[-1]: (child.text or "").strip() for child in root}
    saml = bool(values.get("saml-auth-method") or values.get("saml-request"))
    return {
        "portal": host,
        "auth": "browser" if saml else "password",
        "saml": saml,
        "username_label": values.get("username-label") or "Username",
        "password_label": values.get("password-label") or "Password",
        "message": values.get("authentication-message") or "",
        "region": values.get("region") or "",
    }


def read_secret() -> tuple[str, str]:
    if sys.stdin.isatty():
        password = getpass.getpass("Password: ")
        return password, ""
    line = sys.stdin.readline()
    if not line.strip():
        raise SystemExit("password missing")
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit("password payload is not JSON") from exc
    if not isinstance(data, dict):
        raise SystemExit("password payload is not a JSON object")
    return str(data.get("password") or ""), str(data.get("code") or "")


def run_auth(portal: str, username: str, password: str, code: str, os_name: str, browser: bool) -> dict[str, str]:
    cmd = [
        "openconnect",
        "--protocol=gp",
        "--authenticate",
        f"--os={openconnect_os(os_name)}",
        "--user",
        username,
    ]
    feed = None
    if browser:
        cmd.append("--external-browser=xdg-open")
    else:
        cmd.append("--passwd-on-stdin")
        feed = password + "\n"
        if code:
            feed += code + "\n"
    cmd.append(portal)
    try:
        result = subprocess.run(
            cmd,
            input=feed,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("authentication timed out") from exc
    parsed = parse_auth_output(result.stdout)
    if result.returncode != 0 or "COOKIE" not in parsed or "HOST" not in parsed:
        detail = scrub(result.stderr) or scrub(result.stdout) or "authentication failed"
        raise SystemExit(detail)
    return parsed


def invoking_uid() -> int | None:
    for key in ("PKEXEC_UID", "SUDO_UID"):
        value = os.environ.get(key, "")
        if value.isdigit():
            return int(value)
    return None


def require_root_helper() -> int:
    if os.geteuid() != 0:
        raise SystemExit("tunnel helper must run as root through pkexec")
    uid = invoking_uid()
    if uid is None:
        raise SystemExit("refusing to run without PKEXEC_UID")
    return uid


def user_config_ok(uid: int, raw_path: str) -> Path:
    home = Path(pwd.getpwuid(uid).pw_dir).resolve()
    path = Path(raw_path).resolve()
    if path.name != "config.json" or path.parent.name != "openconnect-gp":
        raise SystemExit("config path refused")
    if not path.is_relative_to(home):
        raise SystemExit("config path is outside the invoking user home")
    return path


def lock_run():
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(RUN_DIR, 0o755)
    handle = LOCK_FILE.open("a+", encoding="utf-8")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def quote_env(key: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{key}="{escaped}"'


def write_root_file(path: Path, text: str, mode: int) -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(RUN_DIR, 0o755)
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)


def service_journal() -> str:
    result = subprocess.run(
        ["journalctl", "-u", SERVICE, "-n", "80", "--no-pager", "-o", "cat"],
        text=True,
        capture_output=True,
        check=False,
    )
    return result.stdout or result.stderr or ""


def journal_line_benign(line: str) -> bool:
    """OpenConnect progress that is not a tunnel failure.

    "HIP Trojan script" is upstream's name for hipreport.sh. ESP falling
    back to HTTPS still leaves a working SSL tunnel.
    """
    markers = (
        "HIP Trojan",
        "HIP script",
        "HIP report submitted",
        "hipreport.esp",
        "hipreportcheck",
        "Failed to connect ESP tunnel",
        "using HTTPS instead",
        "Configured as ",
        "with SSL connected",
        "Session authentication will expire",
        "vhost-net",
        "signer not found",
        "Server certificate verify failed",
    )
    return any(marker in line for marker in markers)


def tunnel_failure_text(journal: str) -> str:
    kept = []
    for line in journal.splitlines():
        lowered = line.lower()
        if "cookie" in lowered or "password" in lowered or "passwd" in lowered:
            continue
        if journal_line_benign(line):
            continue
        text = line.strip()
        if text:
            kept.append(text)
    return "\n".join(kept[-8:])[:500]


def stop_service() -> None:
    subprocess.run(["systemctl", "stop", SERVICE], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "reset-failed", SERVICE], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cmd_exec_tunnel() -> int:
    """System-service entry. Opens the tun device outside the user session cgroup."""
    if os.geteuid() != 0 or os.environ.get("PKEXEC_UID"):
        print("refusing to start the tunnel outside the system service", file=sys.stderr)
        return 1
    if not (os.environ.get("INVOCATION_ID") or os.environ.get("JOURNAL_STREAM")):
        print("refusing to start the tunnel outside the system service", file=sys.stderr)
        return 1
    try:
        env_text = TUNNEL_ENV.read_text(encoding="utf-8")
        cookie = COOKIE_FILE.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"tunnel secrets missing: {exc}", file=sys.stderr)
        return 1
    COOKIE_FILE.unlink(missing_ok=True)
    TUNNEL_ENV.unlink(missing_ok=True)
    fields: dict[str, str] = {}
    for line in env_text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        fields[key] = raw[1:-1] if raw.startswith('"') and raw.endswith('"') else raw
    host = fields.get("OCGP_HOST", "")
    username = fields.get("OCGP_USER", "")
    os_name = fields.get("OCGP_OS", "linux")
    fingerprint = fields.get("OCGP_FINGERPRINT", "")
    csd_user = fields.get("OCGP_CSD_USER", "")
    config = fields.get("OCGP_CONFIG", "")
    try:
        username = check_username(username)
        os_name = check_os_name(os_name)
        if not HOST_RE.fullmatch(host) or not username:
            raise ValueError("tunnel target refused")
        if fingerprint and not FINGERPRINT_RE.fullmatch(fingerprint):
            raise ValueError("fingerprint refused")
        if csd_user and not USER_RE.fullmatch(csd_user):
            raise ValueError("csd user refused")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if not cookie.strip() or "\n" in cookie.strip() or len(cookie) > 16384:
        print("cookie refused", file=sys.stderr)
        return 1
    # --pid-file is written only when OpenConnect backgrounds itself. This
    # process execs OpenConnect, so the pid stays the same.
    try:
        PID_FILE.write_text(f"{os.getpid()}\n", encoding="utf-8")
        os.chmod(PID_FILE, 0o644)
    except OSError as exc:
        print(f"pid file: {exc}", file=sys.stderr)
        return 1
    cmd = [
        "openconnect",
        "--protocol=gp",
        "--cookie-on-stdin",
        f"--pid-file={PID_FILE}",
        f"--interface={IFACE}",
        f"--script={LIB_DIR / 'vpnc-split'}",
        f"--csd-wrapper={LIB_DIR / 'hip-wrapper'}",
        "--syslog",
        f"--os={openconnect_os(os_name)}",
        "--user",
        username,
    ]
    if csd_user:
        cmd.extend([f"--csd-user={csd_user}"])
    if fingerprint:
        cmd.extend(["--servercert", fingerprint])
    cmd.append(host)
    env = os.environ.copy()
    if config:
        env["OCGP_CONFIG"] = config
    if os_name == "apple-silicon":
        env["OCGP_HIP_PROFILE"] = "apple-silicon"
    read_fd, write_fd = os.pipe()
    os.write(write_fd, cookie.encode() if cookie.endswith("\n") else (cookie + "\n").encode())
    os.close(write_fd)
    os.dup2(read_fd, 0)
    os.close(read_fd)
    try:
        os.execvpe(cmd[0], cmd, env)
    except OSError as exc:
        PID_FILE.unlink(missing_ok=True)
        print(str(exc), file=sys.stderr)
        return 1
    return 1


def cmd_tunnel() -> int:
    uid = require_root_helper()
    line = sys.stdin.readline()
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit("tunnel payload is not JSON") from exc
    if not isinstance(data, dict):
        raise SystemExit("tunnel payload is not a JSON object")
    cookie = str(data.get("cookie") or "")
    host = str(data.get("host") or "")
    fingerprint = str(data.get("fingerprint") or "")
    username = check_username(str(data.get("username") or ""))
    os_name = check_os_name(str(data.get("os") or "linux"))
    portal = normalize_portal(str(data.get("portal") or host))
    config = user_config_ok(uid, str(data.get("config") or ""))
    if not cookie or "\n" in cookie or len(cookie) > 16384:
        raise SystemExit("cookie refused")
    if not HOST_RE.fullmatch(host):
        raise SystemExit("gateway host refused")
    if fingerprint and not FINGERPRINT_RE.fullmatch(fingerprint):
        raise SystemExit("fingerprint refused")
    if not username:
        raise SystemExit("username missing")
    if not HIP_SCRIPT.is_file():
        raise SystemExit(f"missing {HIP_SCRIPT}")

    with lock_run():
        existing = connected_pid()
        if existing:
            print(f"already connected (pid {existing})")
            return 0
        write_status(
            {
                "state": "connecting",
                "portal": portal,
                "gateway": host,
                "message": "",
                "since": time.time(),
                "connected_at": None,
            }
        )
        user = pwd.getpwuid(uid).pw_name
        env_body = "\n".join(
            [
                quote_env("OCGP_HOST", host),
                quote_env("OCGP_USER", username),
                quote_env("OCGP_OS", os_name),
                quote_env("OCGP_FINGERPRINT", fingerprint),
                quote_env("OCGP_CSD_USER", user),
                quote_env("OCGP_CONFIG", str(config)),
                quote_env("OCGP_PORTAL", portal),
            ]
        ) + "\n"
        write_root_file(TUNNEL_ENV, env_body, 0o600)
        write_root_file(COOKIE_FILE, cookie if cookie.endswith("\n") else cookie + "\n", 0o600)
        stop_service()
        started = subprocess.run(
            [
                "systemd-run",
                "--system",
                "--collect",
                "--unit",
                "ocgp",
                "--description",
                "openconnect-gp split tunnel",
                "--no-block",
                "/usr/local/bin/ocgp",
                "_exec-tunnel",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if started.returncode != 0:
            COOKIE_FILE.unlink(missing_ok=True)
            TUNNEL_ENV.unlink(missing_ok=True)
            message = scrub(started.stderr) or scrub(started.stdout) or "systemd-run failed"
            write_status(
                {
                    "state": "error",
                    "portal": portal,
                    "gateway": host,
                    "message": message,
                    "since": time.time(),
                }
            )
            print(message, file=sys.stderr)
            return started.returncode or 1

        def mark_up() -> bool:
            if not (connected_pid() and iface_ipv4()):
                return False
            COOKIE_FILE.unlink(missing_ok=True)
            write_status(
                {
                    "state": "connected",
                    "portal": portal,
                    "gateway": host,
                    "message": "",
                    "since": time.time(),
                    "connected_at": time.time(),
                }
            )
            print(f"split tunnel up via {host}")
            return True

        deadline = time.time() + 45
        seen_active = False
        while time.time() < deadline:
            if mark_up():
                return 0
            active = subprocess.run(
                ["systemctl", "is-active", SERVICE],
                text=True,
                capture_output=True,
                check=False,
            )
            unit_state = active.stdout.strip()
            if unit_state in {"active", "activating"}:
                seen_active = True
            if unit_state == "failed" or (seen_active and unit_state in {"inactive", "dead"}):
                break
            time.sleep(0.4)
        if mark_up():
            return 0
        # An address means the tun device is already up. Stopping the unit
        # here logs the user out of a working tunnel.
        if iface_ipv4():
            extra = time.time() + 10
            while time.time() < extra:
                if mark_up():
                    return 0
                time.sleep(0.4)
            COOKIE_FILE.unlink(missing_ok=True)
            message = "Tunnel has an address but its process was not found. It was left running."
            write_status(
                {
                    "state": "error",
                    "portal": portal,
                    "gateway": host,
                    "message": message,
                    "since": time.time(),
                }
            )
            print(message, file=sys.stderr)
            return 1
        COOKIE_FILE.unlink(missing_ok=True)
        TUNNEL_ENV.unlink(missing_ok=True)
        message = tunnel_failure_text(service_journal()) or "Failed to open the tunnel"
        stop_service()
        PID_FILE.unlink(missing_ok=True)
        write_status(
            {
                "state": "error",
                "portal": portal,
                "gateway": host,
                "message": message,
                "since": time.time(),
            }
        )
        print(message, file=sys.stderr)
        return 1


def cmd_disconnect() -> int:
    require_root_helper()
    with lock_run():
        stop_service()
        pid = connected_pid()
        if pid:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 8
            while time.time() < deadline and pid_alive(pid):
                time.sleep(0.2)
            if pid_alive(pid) and our_openconnect(pid):
                os.kill(pid, signal.SIGKILL)
        COOKIE_FILE.unlink(missing_ok=True)
        TUNNEL_ENV.unlink(missing_ok=True)
        PID_FILE.unlink(missing_ok=True)
        write_status({"state": "disconnected", "message": "", "gateway": "", "connected_at": None})
        print("disconnected")
        return 0


def pkexec(mode: str, payload: dict) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pkexec", str(HELPER), mode],
        input=json.dumps(payload) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )


def cmd_connect(browser: bool) -> int:
    if os.geteuid() == 0:
        raise SystemExit("run connect as your user. It will call pkexec for the tunnel.")
    cfg = load_config()
    portal = normalize_portal(str(cfg.get("portal") or ""))
    username = check_username(str(cfg.get("username") or ""))
    os_name = check_os_name(str(cfg.get("os") or "linux"))
    if not username:
        raise SystemExit("set a username first: ocgp config set username NAME")
    if connected_pid():
        print("already connected")
        return 0
    info = prelogin(portal)
    use_browser = browser or bool(info.get("saml"))
    password, code = ("", "")
    if not use_browser:
        password, code = read_secret()
        if not password:
            raise SystemExit("password missing")
    try:
        auth = run_auth(portal, username, password, code, os_name, use_browser)
    except SystemExit as exc:
        write_user_error(portal, str(exc))
        notify("GlobalProtect", str(exc)[:180] or "authentication failed")
        raise
    finally:
        password = ""
    host = auth.get("HOST", "")
    cookie = auth.get("COOKIE", "")
    fingerprint = auth.get("FINGERPRINT", "")
    result = pkexec(
        "_tunnel",
        {
            "cookie": cookie,
            "host": host,
            "fingerprint": fingerprint,
            "username": username,
            "os": os_name,
            "portal": portal,
            "config": str(config_path()),
        },
    )
    cookie = ""
    detail = scrub(result.stderr) or scrub(result.stdout)
    if result.returncode != 0:
        message = detail or "tunnel failed"
        write_user_error(portal, message)
        notify("GlobalProtect", message)
        print(message, file=sys.stderr)
        return result.returncode
    notify("GlobalProtect", f"Split tunnel up ({host})")
    if detail:
        print(detail)
    else:
        print("split tunnel up")
    return 0


def write_user_error(portal: str, message: str) -> None:
    # The user can write the status file only after the root helper has
    # created /run/openconnect-gp. If it has not, print and move on.
    try:
        if RUN_DIR.is_dir() and os.access(RUN_DIR, os.W_OK):
            write_status(
                {
                    "state": "error",
                    "portal": portal,
                    "message": scrub(message),
                    "since": time.time(),
                }
            )
    except OSError:
        return


def cmd_user_disconnect() -> int:
    if connected_pid() is None and not PID_FILE.exists():
        print("already disconnected")
        return 0
    result = pkexec("_disconnect", {})
    detail = scrub(result.stderr) or scrub(result.stdout)
    if result.returncode != 0:
        print(detail or "disconnect failed", file=sys.stderr)
        return result.returncode
    notify("GlobalProtect", "Disconnected")
    print(detail or "disconnected")
    return 0


def cmd_config_set(key: str, value: str) -> int:
    cfg = load_config()
    if key == "portal":
        cfg["portal"] = normalize_portal(value)
    elif key == "username":
        cfg["username"] = check_username(value)
    elif key == "os":
        cfg["os"] = check_os_name(value)
    elif key == "extra_routes":
        cfg["extra_routes"] = parse_route_list(value)
    elif key == "dns_domains":
        cfg["dns_domains"] = parse_domain_list(value)
    else:
        raise SystemExit("unknown config key")
    save_config(cfg)
    print(json.dumps({key: cfg[key]}))
    return 0


def cmd_setup() -> int:
    portal = input("GlobalProtect portal address: ").strip()
    username = input("Username (blank to set later): ").strip()
    cfg = load_config()
    cfg["portal"] = normalize_portal(portal)
    if username:
        cfg["username"] = check_username(username)
    save_config(cfg)
    print(f"saved {config_path()}")
    return 0


def usage() -> None:
    print(
        """Usage: ocgp <command>

  connect              Authenticate, then bring up a split tunnel
  connect --browser    Sign in with the desktop browser (SAML)
  disconnect           Stop the tunnel
  status               Print JSON status
  prelogin             Show how the portal wants you to sign in
  config set KEY VALUE Set portal, username, os, extra_routes, dns_domains
  setup                Ask for portal and username

The tunnel never takes the default route. Gateway split routes are kept.
extra_routes in the config are added. VPN DNS answers only the portal domains.
"""
    )


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in {"-h", "--help", "help"}:
        usage()
        return 0 if len(argv) > 1 else 1
    cmd = argv[1]
    if os.geteuid() == 0 and cmd not in {"_vpnc", "_tunnel", "_disconnect", "_exec-tunnel"}:
        print("refusing to run this command as root", file=sys.stderr)
        return 1
    if cmd == "_vpnc":
        return vpnc_main()
    if cmd == "_exec-tunnel":
        return cmd_exec_tunnel()
    if cmd == "_tunnel":
        return cmd_tunnel()
    if cmd == "_disconnect":
        return cmd_disconnect()
    if cmd == "status":
        print(json.dumps(build_status()))
        return 0
    if cmd == "prelogin":
        cfg = load_config()
        portal = argv[2] if len(argv) > 2 else str(cfg.get("portal") or "")
        print(json.dumps(prelogin(portal)))
        return 0
    if cmd == "connect":
        return cmd_connect("--browser" in argv[2:])
    if cmd == "disconnect":
        return cmd_user_disconnect()
    if cmd == "setup":
        return cmd_setup()
    if cmd == "config" and len(argv) >= 5 and argv[2] == "set":
        return cmd_config_set(argv[3], argv[4])
    usage()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except BrokenPipeError:
        raise SystemExit(0)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
