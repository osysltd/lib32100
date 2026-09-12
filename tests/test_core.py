from __future__ import annotations

import unittest
import urllib.parse

from lib32100 import (
    AuthProfile,
    build_get,
    decrypt_packet,
    encrypt_packet,
    parse_js_vars,
    parse_port,
    query_path,
)


class CoreTests(unittest.TestCase):
    def test_encrypt_decrypt_round_trip(self) -> None:
        clear = bytes(range(256))
        seed = "test-seed"
        encrypted = encrypt_packet(seed, clear)
        self.assertNotEqual(encrypted, clear)
        self.assertEqual(decrypt_packet(seed, encrypted), clear)

    def test_authenticated_path_contains_all_fields(self) -> None:
        profile = AuthProfile(
            login_user="login user",
            user_id="42",
            login_password="login&password",
            camera_user="camera user",
            camera_password="camera/password",
        )
        path = profile.authenticated_path("get_status.cgi?name=admin")
        parsed = urllib.parse.urlsplit(path)
        values = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self.assertEqual(values["name"], ["admin"])
        self.assertEqual(values["loginuse"], ["login user"])
        self.assertEqual(values["userId"], ["42"])
        self.assertEqual(values["loginpas"], ["login&password"])
        self.assertEqual(values["user"], ["camera user"])
        self.assertEqual(values["pwd"], ["camera/password"])

    def test_build_get_contains_path(self) -> None:
        clear = build_get(7, "/get_status.cgi")
        self.assertTrue(clear.startswith(b"\xF1\xD0"))
        self.assertIn(b"GET /get_status.cgi", clear)

    def test_parse_js_vars(self) -> None:
        values = parse_js_vars(b'var result="0"; rtspenable="1"; rtspport=10554;')
        self.assertEqual(values["result"], "0")
        self.assertEqual(values["rtspenable"], "1")
        self.assertEqual(values["rtspport"], "10554")

    def test_parse_port(self) -> None:
        self.assertEqual(parse_port("10554"), 10554)
        self.assertIsNone(parse_port("0"))
        self.assertIsNone(parse_port("65536"))
        self.assertIsNone(parse_port("invalid"))

    def test_query_path_encodes_parameters(self) -> None:
        path = query_path("set_rtsp.cgi", [("rtspuser", "viewer user"), ("rtsppwd", "a&b")])
        parsed = urllib.parse.urlsplit(path)
        values = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.path, "set_rtsp.cgi")
        self.assertEqual(values["rtspuser"], ["viewer user"])
        self.assertEqual(values["rtsppwd"], ["a&b"])


if __name__ == "__main__":
    unittest.main()
