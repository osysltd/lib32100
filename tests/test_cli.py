from __future__ import annotations

import unittest

from lib32100.cli import build_parser
from lib32100.core import DEFAULT_DISCOVERY_PORT, DEFAULT_SEED


class CliTests(unittest.TestCase):
    def test_enable_defaults_and_overrides(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "enable-rtsp",
                "--camera-ip",
                "10.0.0.20",
                "--seed",
                "another-seed",
                "--discovery-port",
                "32109",
                "--rtsp-port",
                "8554",
            ]
        )
        self.assertEqual(args.camera_ip, "10.0.0.20")
        self.assertEqual(args.seed, "another-seed")
        self.assertEqual(args.discovery_port, 32109)
        self.assertEqual(args.rtsp_port, 8554)

    def test_disable_defaults(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["disable-rtsp"])
        self.assertEqual(args.seed, DEFAULT_SEED)
        self.assertEqual(args.discovery_port, DEFAULT_DISCOVERY_PORT)


if __name__ == "__main__":
    unittest.main()
