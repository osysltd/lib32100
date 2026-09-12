from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .core import (
    DEFAULT_CAMERA_IP,
    DEFAULT_DISCOVERY_PORT,
    DEFAULT_SEED,
    disable_rtsp,
    enable_rtsp,
    extract_auth_profile,
    find_pcap,
)

DEFAULT_OUTPUT_NAME = "lib32100_credentials.json"


def _add_common_capture_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--pcap",
        default=None,
        help="Classic PCAP path. If omitted, the single .pcap file in the current directory is used.",
    )
    parser.add_argument("--camera-ip", default=DEFAULT_CAMERA_IP)
    parser.add_argument("--seed", default=DEFAULT_SEED)


def _add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    _add_common_capture_arguments(parser)
    parser.add_argument("--discovery-port", type=int, default=DEFAULT_DISCOVERY_PORT)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--reboot-wait", type=float, default=90.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lib32100",
        description="PPPP/CGI camera toolkit for credential extraction and persistent RTSP configuration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract a complete PPPP CGI authentication profile from a classic PCAP capture.",
    )
    _add_common_capture_arguments(extract_parser)
    extract_parser.add_argument(
        "--output",
        type=Path,
        default=Path(DEFAULT_OUTPUT_NAME),
        help=f"JSON output path. Default: {DEFAULT_OUTPUT_NAME}",
    )

    enable_parser = subparsers.add_parser(
        "enable-rtsp",
        help="Enable ONVIF and persistent authenticated RTSP, then verify the configuration after reboot.",
    )
    _add_runtime_arguments(enable_parser)
    enable_parser.add_argument("--rtsp-user", default=None)
    enable_parser.add_argument("--rtsp-password", default=None)
    enable_parser.add_argument("--rtsp-port", type=int, default=None)

    disable_parser = subparsers.add_parser(
        "disable-rtsp",
        help="Disable persistent RTSP while preserving the current RTSP port and authentication fields.",
    )
    _add_runtime_arguments(disable_parser)

    return parser


def _resolve_output(path: Path) -> Path:
    expanded = path.expanduser()
    if expanded.is_absolute():
        return expanded.resolve()
    return (Path.cwd() / expanded).resolve()


def _run_extract(args: argparse.Namespace) -> int:
    pcap = find_pcap(Path.cwd(), args.pcap)
    profile = extract_auth_profile(pcap, args.camera_ip, args.seed)
    payload = json.dumps(asdict(profile), indent=2, ensure_ascii=True) + "\n"
    output = _resolve_output(args.output)
    output.write_text(payload, encoding="utf-8", newline="\n")

    print(f"PCAP: {pcap}")
    print(payload, end="")
    print(f"Saved: {output}")
    return 0


def _run_enable(args: argparse.Namespace) -> int:
    enable_rtsp(
        camera_ip=args.camera_ip,
        pcap_value=args.pcap,
        script_dir=Path.cwd(),
        rtsp_user=args.rtsp_user,
        rtsp_password=args.rtsp_password,
        rtsp_port=args.rtsp_port,
        timeout=args.timeout,
        reboot_wait=args.reboot_wait,
        seed=args.seed,
        discovery_port=args.discovery_port,
    )
    return 0


def _run_disable(args: argparse.Namespace) -> int:
    disable_rtsp(
        camera_ip=args.camera_ip,
        pcap_value=args.pcap,
        script_dir=Path.cwd(),
        timeout=args.timeout,
        reboot_wait=args.reboot_wait,
        seed=args.seed,
        discovery_port=args.discovery_port,
    )
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "extract":
            return _run_extract(args)
        if args.command == "enable-rtsp":
            return _run_enable(args)
        if args.command == "disable-rtsp":
            return _run_disable(args)
        parser.error(f"Unsupported command: {args.command}")
    except Exception as error:
        print(f"ERROR {type(error).__name__}: {error}", flush=True)
        return 1
    return 2
