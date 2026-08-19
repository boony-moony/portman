import unittest
from unittest.mock import patch
import sys
import types


class _DecoratorHost:
    def route(self, *args, **kwargs):
        return lambda function: function

    def login_required(self, function):
        return function

    def verify_password(self, function):
        return function


class _Flask(_DecoratorHost):
    def __init__(self, *args, **kwargs):
        self.secret_key = None


flask = types.ModuleType("flask")
flask.Flask = _Flask
flask.request = types.SimpleNamespace(json=None)
flask.jsonify = lambda *args, **kwargs: (args, kwargs)
flask.session = {}
flask.redirect = flask.url_for = flask.make_response = lambda value, *args, **kwargs: value
sys.modules.setdefault("flask", flask)

httpauth = types.ModuleType("flask_httpauth")
httpauth.HTTPBasicAuth = _DecoratorHost
sys.modules.setdefault("flask_httpauth", httpauth)

werkzeug = types.ModuleType("werkzeug")
security = types.ModuleType("werkzeug.security")
security.generate_password_hash = lambda value: value
security.check_password_hash = lambda hashed, value: hashed == value
sys.modules.setdefault("werkzeug", werkzeug)
sys.modules.setdefault("werkzeug.security", security)

import app


class SteamRoutingTests(unittest.TestCase):
    def test_normalizes_source_network(self):
        self.assertEqual(app._valid_ipv4_cidr("172.20.0.9/24"), "172.20.0.0/24")

    def test_rejects_ipv6_source_network(self):
        with self.assertRaises(ValueError):
            app._valid_ipv4_cidr("fd00::/64")

    def test_home_script_is_source_scoped(self):
        script = app.home_steam_script({
            "steam_source_cidr": "172.20.0.0/24",
            "steam_wg_iface": "wg0",
            "steam_route_table": 51820,
        })
        self.assertIn('ip rule add from "$SOURCE_CIDR"', script)
        self.assertIn('nat -I POSTROUTING 1 -s "$SOURCE_CIDR"', script)
        self.assertIn('Table = off', script)
        self.assertNotIn("ip route replace default dev wg0\n", script)

    @patch.object(app, "WAN_IFACE", "eth0")
    def test_vps_rules_are_narrow(self):
        rules = app._steam_rule_specs({
            "steam_source_cidr": "172.20.0.0/24",
            "steam_wg_iface": "wg0",
        })
        rendered = [" ".join(spec) for _, spec in rules]
        self.assertTrue(all("portman-steam" in rule for rule in rendered))
        self.assertIn("-s 172.20.0.0/24", rendered[0])
        self.assertIn("-s 172.20.0.0/24", rendered[2])


if __name__ == "__main__":
    unittest.main()
