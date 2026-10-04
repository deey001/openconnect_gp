import json
import sys
import unittest
from pathlib import Path

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
