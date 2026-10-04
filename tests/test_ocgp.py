import errno
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import ocgp


class PortalTests(unittest.TestCase):
    def test_strips_url(self):
        self.assertEqual(ocgp.normalize_portal("https://panvpn.example.gov/global-protect/login.esp"), "panvpn.example.gov")

    def test_keeps_port(self):
        self.assertEqual(ocgp.normalize_portal("vpn.example.com:443"), "vpn.example.com:443")

    def test_refuses_junk(self):
        with self.assertRaises(ValueError):
            ocgp.normalize_portal("vpn.example.com;rm")
        with self.assertRaises(ValueError):
            ocgp.normalize_portal("")


class RouteTests(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(ocgp.mask_from_len(16), "255.255.0.0")
        self.assertEqual(ocgp.mask_from_len(24), "255.255.255.0")

    def test_default_cidr_refused(self):
        with self.assertRaises(ValueError):
            ocgp.parse_cidr("0.0.0.0/0")

    def test_parse_list(self):
        self.assertEqual(ocgp.parse_route_list("10.1.0.0/16, 192.168.5.0/24"), ["10.1.0.0/16", "192.168.5.0/24"])


class SplitTests(unittest.TestCase):
    def test_drops_default_and_keeps_split(self):
        env = {
            "reason": "connect",
            "CISCO_SPLIT_INC": "2",
            "CISCO_SPLIT_INC_0_ADDR": "0.0.0.0",
            "CISCO_SPLIT_INC_0_MASK": "0.0.0.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "0",
            "CISCO_SPLIT_INC_1_ADDR": "10.8.0.0",
            "CISCO_SPLIT_INC_1_MASK": "255.255.0.0",
            "CISCO_SPLIT_INC_1_MASKLEN": "16",
            "INTERNAL_IP4_ADDRESS": "10.9.0.4",
        }
        updated = ocgp.rewrite_split_env(env)
        self.assertEqual(updated["CISCO_SPLIT_INC"], "1")
        self.assertEqual(updated["CISCO_SPLIT_INC_0_ADDR"], "10.8.0.0")
        self.assertNotIn("CISCO_SPLIT_INC_1_ADDR", updated)
        self.assertNotIn("0.0.0.0", [updated[key] for key in updated if key.endswith("_ADDR")])

    def test_full_tunnel_becomes_no_default_route(self):
        env = {"INTERNAL_IP4_ADDRESS": "10.9.0.4", "INTERNAL_IP6_ADDRESS": "2001:db8::1"}
        updated = ocgp.rewrite_split_env(env)
        self.assertEqual(updated["CISCO_SPLIT_INC"], "0")
        self.assertEqual(updated["CISCO_IPV6_SPLIT_INC"], "0")

    def test_extra_routes_append(self):
        path = self._write_config(["192.168.50.0/24"])
        env = {
            "CISCO_SPLIT_INC": "1",
            "CISCO_SPLIT_INC_0_ADDR": "10.2.0.0",
            "CISCO_SPLIT_INC_0_MASK": "255.255.255.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "24",
        }
        updated = ocgp.rewrite_split_env(env, str(path))
        self.assertEqual(updated["CISCO_SPLIT_INC"], "2")
        self.assertEqual(updated["CISCO_SPLIT_INC_1_ADDR"], "192.168.50.0")
        self.assertEqual(updated["CISCO_SPLIT_INC_1_MASK"], "255.255.255.0")
        self.assertEqual(updated["CISCO_SPLIT_INC_1_MASKLEN"], "24")

    def test_dns_domains_are_route_only(self):
        path = self._write_domains(["corp.example"])
        env = {"CISCO_DEF_DOMAIN": "example.gov", "CISCO_SPLIT_DNS": "intra.example.gov,bad!name"}
        domains = ocgp.dns_domains(env, str(path))
        self.assertEqual(domains, ["~example.gov", "~intra.example.gov", "~corp.example"])

    def _write_config(self, routes: list[str]) -> Path:
        path = Path(self.id().replace(".", "_") + ".json")
        # unittest id has dots; keep the file in /tmp
        path = Path("/tmp") / ("ocgp-" + self.id().split(".")[-1] + ".json")
        path.write_text(json.dumps({"extra_routes": routes}), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path

    def _write_domains(self, domains: list[str]) -> Path:
        path = Path("/tmp") / ("ocgp-" + self.id().split(".")[-1] + ".json")
        path.write_text(json.dumps({"dns_domains": domains}), encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        return path


class PidTests(unittest.TestCase):
    def test_eperm_means_the_root_process_exists(self):
        with mock.patch("ocgp.os.kill", side_effect=PermissionError(errno.EPERM, "Operation not permitted")):
            self.assertTrue(ocgp.pid_alive(1039512))

    def test_esrch_means_the_process_exited(self):
        with mock.patch("ocgp.os.kill", side_effect=ProcessLookupError(errno.ESRCH, "No such process")):
            self.assertFalse(ocgp.pid_alive(1039512))

    def test_non_positive_pid_is_dead(self):
        self.assertFalse(ocgp.pid_alive(0))
        self.assertFalse(ocgp.pid_alive(-1))


class OsTests(unittest.TestCase):
    def test_apple_silicon_is_accepted(self):
        self.assertEqual(ocgp.check_os_name("apple-silicon"), "apple-silicon")

    def test_apple_silicon_selects_the_mac_hip_report(self):
        self.assertEqual(ocgp.openconnect_os("apple-silicon"), "mac-intel")
        self.assertEqual(ocgp.openconnect_os("win"), "win")

    def test_unknown_os_is_refused(self):
        with self.assertRaises(ValueError):
            ocgp.check_os_name("macos")


class PhaseTests(unittest.TestCase):
    def test_dead_process_is_an_error_even_if_status_said_connected(self):
        self.assertEqual(ocgp.phase_state("connected", None, "", 0, 10), "error")

    def test_live_tunnel_is_connected(self):
        self.assertEqual(ocgp.phase_state("connecting", 10, "10.9.0.4", 0, 5), "connected")

    def test_recent_start_stays_connecting(self):
        self.assertEqual(ocgp.phase_state("connecting", None, "", 100, 120), "connecting")


class JournalTests(unittest.TestCase):
    def test_hip_trojan_lines_are_not_a_failure(self):
        journal = "\n".join(
            [
                "Trying to run HIP Trojan script '/usr/lib/openconnect/hipreport.sh'.",
                "HIP script '/usr/lib/openconnect/hipreport.sh' completed successfully (report is 2285 bytes).",
                "POST https://65.87.76.8/ssl-vpn/hipreport.esp",
                "HIP report submitted successfully.",
                "Failed to connect ESP tunnel; using HTTPS instead.",
                "Configured as 10.190.177.158, with SSL connected and ESP unsuccessful",
                "Session authentication will expire at Tue, 03 Nov 2026 10:50:47 EST",
                "Using vhost-net for tun acceleration, ring size 32",
                "Server certificate verify failed: signer not found",
            ]
        )
        self.assertEqual(ocgp.tunnel_failure_text(journal), "")

    def test_tun_denial_stays_visible(self):
        journal = "\n".join(
            [
                "Trying to run HIP Trojan script '/usr/lib/openconnect/hipreport.sh'.",
                "Failed to open tun device: Operation not permitted",
                "Set up tun device failed",
            ]
        )
        text = ocgp.tunnel_failure_text(journal)
        self.assertIn("Failed to open tun device: Operation not permitted", text)
        self.assertIn("Set up tun device failed", text)
        self.assertNotIn("HIP Trojan", text)

    def test_cookie_line_still_dropped(self):
        journal = "COOKIE='secret'\nFailed to open tun device: Operation not permitted\n"
        text = ocgp.tunnel_failure_text(journal)
        self.assertNotIn("secret", text)
        self.assertIn("Failed to open tun device", text)


class AuthParseTests(unittest.TestCase):
    def test_parses_cookie_block(self):
        text = "COOKIE='abc123'\nHOST='10.1.2.3'\nFINGERPRINT='pin-sha256:abcd'\nnoise\n"
        parsed = ocgp.parse_auth_output(text)
        self.assertEqual(parsed["COOKIE"], "abc123")
        self.assertEqual(parsed["HOST"], "10.1.2.3")
        self.assertEqual(parsed["FINGERPRINT"], "pin-sha256:abcd")

    def test_scrub_drops_secrets(self):
        text = "Password: secret\nCOOKIE='nope'\nportal refused the HIP report\n"
        self.assertEqual(ocgp.scrub(text), "portal refused the HIP report")


if __name__ == "__main__":
    unittest.main()
