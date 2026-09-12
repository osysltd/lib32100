from __future__ import annotations

import ipaddress
import re
import socket
import struct
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

DEFAULT_DISCOVERY_PORT = 32108
TCP_MARKER = b"\x68\x00\x00\x00\x00\x00"
MAX_TCP_RECORD = 65535
MAX_CAPTURE_PACKET = 16 * 1024 * 1024
MAX_CGI_RESPONSE = 1024 * 1024
DEFAULT_SEED = "vstarcam2018"
DEFAULT_CAMERA_IP = "192.168.100.2"
DEFAULT_RTSP_PORT = 10554

_SHUFFLE = bytes.fromhex(
    "7c9ce84a13dedcb22f2123e4307b3d8cbc0b270c3cf79ae7087196009785efc1"
    "1fc4dba1c2ebd901faba3b05b81587832872d18b5ad6da9358feaacc6e1bf0a3"
    "88ab43c00db545384f502266207f075b14981d9ba72ab9a8cbf1fc4947063eb1"
    "0e043a945eee541134dd4df9ecc7c9e3781a6f706ba4bda95dd5f8e5bb26af42"
    "37d8e1020aae5f1cc573094e6924906d12b319ad748a2940f52dbea559e0f479"
    "d24bce8982488425c6912ba2fb8fe9a6b09e3f65f603312eac0f952c5ced39b7"
    "336c567eb4a0fd7a815351868d9f77ff6a80dfe2bf10d775645776f355cdd0c8"
    "18e6364162cf99f2324c67606192cad3ea637d16b68ed46835c3529d46441e17"
)

_JS_ASSIGNMENT = re.compile(
    r"(?:\bvar\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|[^;\r\n]*)\s*;"
)


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int


@dataclass(frozen=True)
class AuthProfile:
    login_user: str
    user_id: str
    login_password: str
    camera_user: str
    camera_password: str

    def authenticated_path(self, path: str) -> str:
        separator = "&" if "?" in path else "?"
        items = (
            ("loginuse", self.login_user),
            ("userId", self.user_id),
            ("loginpas", self.login_password),
            ("user", self.camera_user),
            ("pwd", self.camera_password),
        )
        query = "&".join(
            f"{urllib.parse.quote(name, safe='')}={urllib.parse.quote(value, safe='')}"
            for name, value in items
        )
        return f"/{path}{separator}{query}&"


@dataclass(frozen=True)
class TcpPayload:
    source: str
    source_port: int
    destination: str
    destination_port: int
    sequence: int
    payload: bytes


class SessionClosed(RuntimeError):
    pass


def log(message: str) -> None:
    print(time.strftime("[%H:%M:%S]"), message, flush=True)


def find_pcap(script_dir: Path, explicit: str | None) -> Path:
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        candidate = candidate.resolve()
        if not candidate.is_file():
            raise FileNotFoundError(f"PCAP not found: {candidate}")
        return candidate

    candidates = sorted(path for path in script_dir.glob("*.pcap") if path.is_file())
    if not candidates:
        raise FileNotFoundError(
            f"No .pcap file found next to the script: {script_dir}"
        )
    if len(candidates) != 1:
        names = ", ".join(path.name for path in candidates)
        raise RuntimeError(
            f"Multiple .pcap files found next to the script: {names}. Use --pcap to select one."
        )
    return candidates[0]


def _seed_hash(seed: str) -> tuple[int, int, int, int]:
    result = [0, 0, 0, 0]
    for value in seed.encode("ascii"):
        result[0] = (result[0] + value) & 0xFF
        result[1] = (result[1] - value) & 0xFF
        result[2] = (result[2] + value // 3) & 0xFF
        result[3] ^= value
    return result[0], result[1], result[2], result[3]


def encrypt_packet(seed: str, clear: bytes) -> bytes:
    hashed = _seed_hash(seed)
    output = bytearray()
    previous = 0
    for value in clear:
        encoded = value ^ _SHUFFLE[(hashed[previous & 3] + previous) & 0xFF]
        output.append(encoded)
        previous = encoded
    return bytes(output)


def decrypt_packet(seed: str, encrypted: bytes) -> bytes:
    hashed = _seed_hash(seed)
    output = bytearray()
    previous = 0
    for value in encrypted:
        output.append(value ^ _SHUFFLE[(hashed[previous & 3] + previous) & 0xFF])
        previous = value
    return bytes(output)


def wrap_tcp(seed: str, clear: bytes) -> bytes:
    encrypted = encrypt_packet(seed, clear)
    if len(encrypted) > MAX_TCP_RECORD:
        raise ValueError("PPPP TCP record is too large")
    return len(encrypted).to_bytes(2, "big") + TCP_MARKER + encrypted


def build_get(sequence: int, path: str) -> bytes:
    url = path.encode("ascii")
    inner = (
        b"\xD1\x00"
        + sequence.to_bytes(2, "big")
        + b"\x01\x0A\x00"
        + (len(url) + 4).to_bytes(2, "big")
        + b"\x00\x00\x00GET "
        + url
    )
    return b"\xF1\xD0" + len(inner).to_bytes(2, "big") + inner


def _pcap_format(data: bytes) -> str:
    if len(data) < 24:
        raise ValueError("PCAP is too short")
    formats = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    if data[:4] not in formats:
        raise ValueError("Unsupported PCAP format")
    return formats[data[:4]]


def _ipv4_from_packet(packet: bytes, linktype: int) -> bytes | None:
    if linktype == 101:
        return packet
    if linktype != 1 or len(packet) < 14:
        return None
    offset = 14
    ether_type = int.from_bytes(packet[12:14], "big")
    while ether_type in (0x8100, 0x88A8):
        if len(packet) < offset + 4:
            return None
        ether_type = int.from_bytes(packet[offset + 2 : offset + 4], "big")
        offset += 4
    if ether_type != 0x0800:
        return None
    return packet[offset:]


def read_tcp_payloads(path: Path) -> list[TcpPayload]:
    data = path.read_bytes()
    endian = _pcap_format(data)
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype not in (1, 101):
        raise ValueError(f"Unsupported PCAP linktype {linktype}")

    result: list[TcpPayload] = []
    offset = 24
    while offset + 16 <= len(data):
        _seconds, _fraction, included_length, _original_length = struct.unpack_from(
            endian + "IIII", data, offset
        )
        offset += 16
        if included_length > MAX_CAPTURE_PACKET or offset + included_length > len(data):
            raise ValueError("Invalid PCAP packet length")
        packet = data[offset : offset + included_length]
        offset += included_length
        ip = _ipv4_from_packet(packet, linktype)
        if ip is None or len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        header_length = (ip[0] & 0x0F) * 4
        if header_length < 20 or len(ip) < header_length or ip[9] != 6:
            continue
        transport = ip[header_length:]
        if len(transport) < 20:
            continue
        source_port, destination_port, sequence = struct.unpack_from("!HHI", transport, 0)
        tcp_header_length = (transport[12] >> 4) * 4
        if tcp_header_length < 20 or len(transport) < tcp_header_length:
            continue
        payload = transport[tcp_header_length:]
        if not payload:
            continue
        result.append(
            TcpPayload(
                source=str(ipaddress.IPv4Address(ip[12:16])),
                source_port=source_port,
                destination=str(ipaddress.IPv4Address(ip[16:20])),
                destination_port=destination_port,
                sequence=sequence,
                payload=payload,
            )
        )
    return result


def reassemble_flows(payloads: Iterable[TcpPayload]) -> dict[tuple[str, int, str, int], bytes]:
    grouped: dict[tuple[str, int, str, int], list[TcpPayload]] = {}
    for item in payloads:
        key = (item.source, item.source_port, item.destination, item.destination_port)
        grouped.setdefault(key, []).append(item)

    output: dict[tuple[str, int, str, int], bytes] = {}
    for key, segments in grouped.items():
        ordered = sorted(segments, key=lambda item: item.sequence)
        current: int | None = None
        stream = bytearray()
        valid = True
        for segment in ordered:
            sequence = segment.sequence
            payload = segment.payload
            if current is None:
                current = sequence
            if sequence + len(payload) <= current:
                continue
            if sequence < current:
                payload = payload[current - sequence :]
                sequence = current
            if sequence != current:
                valid = False
                break
            stream.extend(payload)
            current += len(payload)
        if valid and stream:
            output[key] = bytes(stream)
    return output


def iter_pppp_clear_records(stream: bytes, seed: str) -> Iterable[bytes]:
    offset = 0
    while offset + 8 <= len(stream):
        size = int.from_bytes(stream[offset : offset + 2], "big")
        if size <= 0 or offset + 8 + size > len(stream):
            return
        if stream[offset + 2 : offset + 8] != TCP_MARKER:
            return
        encrypted = stream[offset + 8 : offset + 8 + size]
        yield decrypt_packet(seed, encrypted)
        offset += 8 + size


def extract_auth_profile(pcap: Path, camera_ip: str, seed: str) -> AuthProfile:
    profiles: set[AuthProfile] = set()
    for key, stream in reassemble_flows(read_tcp_payloads(pcap)).items():
        _source, _source_port, destination, _destination_port = key
        if destination != camera_ip:
            continue
        for clear in iter_pppp_clear_records(stream, seed):
            if clear[:2] != b"\xF1\xD0":
                continue
            for match in re.finditer(rb"GET (/[^\x00-\x1F ]+)", clear):
                path = match.group(1).decode("ascii", errors="strict")
                values = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(path).query,
                    keep_blank_values=True,
                    strict_parsing=False,
                )
                required = ("loginuse", "userId", "loginpas", "user", "pwd")
                if not all(name in values and values[name] for name in required):
                    continue
                profiles.add(
                    AuthProfile(
                        login_user=values["loginuse"][0],
                        user_id=values["userId"][0],
                        login_password=values["loginpas"][0],
                        camera_user=values["user"][0],
                        camera_password=values["pwd"][0],
                    )
                )
    if not profiles:
        raise RuntimeError("No complete PPPP CGI authentication profile was found in the PCAP")
    if len(profiles) != 1:
        raise RuntimeError("Multiple different PPPP CGI authentication profiles were found in the PCAP")
    return next(iter(profiles))


def discover_local(
    camera_ip: str,
    seed: str,
    timeout: float,
    discovery_port: int = DEFAULT_DISCOVERY_PORT,
) -> Endpoint:
    if not 1 <= discovery_port <= 65535:
        raise ValueError("Discovery port must be between 1 and 65535")
    search_wire = encrypt_packet(seed, b"\xF1\x30\x00\x00")
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("", 0))
        sock.settimeout(0.12)
        last_send = 0.0
        target: Endpoint | None = None
        echoed = 0

        while time.monotonic() < deadline:
            now = time.monotonic()
            if target is None and now - last_send >= 0.4:
                for host in (camera_ip, "255.255.255.255"):
                    try:
                        sock.sendto(search_wire, (host, discovery_port))
                    except OSError:
                        pass
                last_send = now

            try:
                wire, address = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if address[0] != camera_ip:
                continue
            clear = decrypt_packet(seed, wire)
            if len(clear) < 4 or clear[0] != 0xF1:
                continue
            if clear[1] == 0x41:
                target = Endpoint(address[0], address[1])
                if echoed < 3:
                    sock.sendto(wire, address)
                    echoed += 1
                continue
            if clear[1] == 0x43:
                return Endpoint(address[0], address[1])
        raise TimeoutError("Camera did not complete the LAN F1 30 to F1 41 to F1 43 handshake")
    finally:
        sock.close()


class TcpRecordReader:
    def __init__(self, sock: socket.socket, seed: str) -> None:
        self.sock = sock
        self.seed = seed
        self.buffer = bytearray()

    def _fill(self, count: int) -> None:
        while len(self.buffer) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("PPPP TCP connection closed")
            self.buffer.extend(chunk)

    def read(self) -> bytes:
        self._fill(8)
        size = int.from_bytes(self.buffer[:2], "big")
        if size <= 0 or size > MAX_TCP_RECORD:
            raise RuntimeError(f"Invalid PPPP TCP record length {size}")
        if self.buffer[2:8] != TCP_MARKER:
            raise RuntimeError("Invalid PPPP TCP record marker")
        self._fill(8 + size)
        encrypted = bytes(self.buffer[8 : 8 + size])
        del self.buffer[: 8 + size]
        return decrypt_packet(self.seed, encrypted)


def parse_js_vars(data: bytes) -> dict[str, str]:
    text = data.decode("utf-8", errors="replace")
    result: dict[str, str] = {}
    for match in _JS_ASSIGNMENT.finditer(text):
        name = match.group(1)
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        result[name] = value
    return result


def response_is_success(values: dict[str, str]) -> bool:
    value = values.get("result")
    if value is None:
        return False
    return value.strip().strip("'\"").lower() in {"0", "ok"}


def clean_flag(values: dict[str, str], name: str) -> str:
    return (values.get(name) or "").strip().strip("'\"")


def parse_port(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        port = int(value.strip().strip("'\""))
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def query_path(path: str, parameters: list[tuple[str, str]]) -> str:
    return f"{path}?{urllib.parse.urlencode(parameters)}"


class PpppCgiClient:
    def __init__(self, endpoint: Endpoint, seed: str, auth: AuthProfile, timeout: float) -> None:
        self.endpoint = endpoint
        self.seed = seed
        self.auth = auth
        self.timeout = timeout
        self.sequence = 0
        self.sock: socket.socket | None = None
        self.reader: TcpRecordReader | None = None

    def __enter__(self) -> "PpppCgiClient":
        self.sock = socket.create_connection(
            (self.endpoint.host, self.endpoint.port), timeout=self.timeout
        )
        self.sock.settimeout(min(1.0, self.timeout))
        self.reader = TcpRecordReader(self.sock, self.seed)
        self._send_clear(b"\xF1\xE0\x00\x00")
        self._wait_for_session_ack()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.sock is None:
            return
        try:
            self._send_clear(b"\xF1\xF0\x00\x00")
        except OSError:
            pass
        try:
            self.sock.close()
        finally:
            self.sock = None
            self.reader = None

    def _send_clear(self, clear: bytes) -> None:
        if self.sock is None:
            raise RuntimeError("PPPP session is not connected")
        self.sock.sendall(wrap_tcp(self.seed, clear))

    def _read_clear_until(self, deadline: float) -> bytes:
        if self.sock is None or self.reader is None:
            raise RuntimeError("PPPP session is not connected")
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            self.sock.settimeout(max(0.05, min(0.8, remaining)))
            try:
                clear = self.reader.read()
            except socket.timeout:
                continue
            except EOFError as error:
                raise SessionClosed("Camera closed the PPPP TCP session") from error
            if clear[:2] == b"\xF1\xF0":
                raise SessionClosed("Camera sent PPPP session-close")
            return clear
        raise TimeoutError("Timed out waiting for PPPP data")

    def _wait_for_session_ack(self) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            clear = self._read_clear_until(deadline)
            if clear[:2] == b"\xF1\xE0":
                return
            if clear[:2] == b"\xF1\xD0":
                continue
        raise TimeoutError("PPPP TCP session did not acknowledge keepalive")

    def request(self, path: str) -> tuple[bytes, dict[str, str]]:
        authenticated = self.auth.authenticated_path(path)
        clear = build_get(self.sequence, authenticated)
        self.sequence = (self.sequence + 1) & 0xFFFF
        self._send_clear(clear)
        body = self._read_cgi_body()
        return body, parse_js_vars(body)

    def _read_cgi_body(self) -> bytes:
        deadline = time.monotonic() + self.timeout
        expected_length: int | None = None
        body = bytearray()
        while time.monotonic() < deadline:
            clear = self._read_clear_until(deadline)
            if clear[:2] == b"\xF1\xE0":
                continue
            if clear[:2] != b"\xF1\xD0" or len(clear) < 8:
                continue
            outer_length = int.from_bytes(clear[2:4], "big")
            inner = clear[4 : 4 + outer_length]
            if len(inner) < 4 or inner[:2] != b"\xD1\x00":
                continue
            fragment = inner[4:]
            if expected_length is None:
                if len(fragment) < 8 or fragment[:2] != b"\x01\x0A":
                    continue
                expected_length = int.from_bytes(fragment[4:6], "little")
                if expected_length <= 0 or expected_length > MAX_CGI_RESPONSE:
                    raise RuntimeError(f"Invalid CGI response length {expected_length}")
                body.extend(fragment[8:])
            else:
                body.extend(fragment)
            if expected_length is not None and len(body) >= expected_length:
                return bytes(body[:expected_length])
        raise TimeoutError("Timed out waiting for a complete PPPP CGI response")


def read_state(client: PpppCgiClient) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    _params_body, params = client.request("get_params.cgi")
    _onvif_body, onvif = client.request("get_onvif.cgi")
    _rtsp_body, rtsp = client.request("get_rtsp.cgi")
    return params, onvif, rtsp


def verify_auth(client: PpppCgiClient) -> None:
    _body, values = client.request("get_status.cgi?name=admin")
    if not response_is_success(values):
        raise RuntimeError("Camera rejected the captured CGI authentication profile")


def request_reboot(client: PpppCgiClient) -> None:
    try:
        _body, values = client.request("reboot.cgi?next_url=index.htm")
        if not response_is_success(values):
            raise RuntimeError("reboot.cgi did not report success")
    except (SessionClosed, TimeoutError, OSError):
        return


def reconnect_after_reboot(
    camera_ip: str,
    seed: str,
    auth: AuthProfile,
    timeout: float,
    wait_seconds: float,
    discovery_port: int = DEFAULT_DISCOVERY_PORT,
) -> tuple[Endpoint, PpppCgiClient]:
    time.sleep(2.0)
    deadline = time.monotonic() + wait_seconds
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        client: PpppCgiClient | None = None
        try:
            endpoint = discover_local(
                camera_ip,
                seed,
                min(3.0, timeout + 1.0),
                discovery_port,
            )
            client = PpppCgiClient(endpoint, seed, auth, timeout)
            client.__enter__()
            verify_auth(client)
            return endpoint, client
        except Exception as error:
            last_error = error
            if client is not None:
                try:
                    client.__exit__(None, None, None)
                except Exception:
                    pass
            time.sleep(1.5)
    if last_error is None:
        raise TimeoutError("Camera did not return after reboot")
    raise TimeoutError(
        f"Camera did not return after reboot; last error was {type(last_error).__name__}"
    ) from last_error


def load_runtime(
    script_dir: Path,
    camera_ip: str,
    pcap_value: str | None,
    seed: str,
) -> tuple[Path, AuthProfile]:
    pcap = find_pcap(script_dir, pcap_value)
    auth = extract_auth_profile(pcap, camera_ip, seed)
    return pcap, auth


def enable_rtsp(
    camera_ip: str,
    pcap_value: str | None,
    script_dir: Path,
    rtsp_user: str | None,
    rtsp_password: str | None,
    rtsp_port: int | None,
    timeout: float,
    reboot_wait: float,
    seed: str = DEFAULT_SEED,
    discovery_port: int = DEFAULT_DISCOVERY_PORT,
) -> None:
    pcap, auth = load_runtime(script_dir, camera_ip, pcap_value, seed)
    selected_user = auth.camera_user if rtsp_user is None else rtsp_user
    selected_password = auth.camera_password if rtsp_password is None else rtsp_password
    if not selected_user:
        raise ValueError("RTSP username must not be empty")
    if not selected_password:
        raise ValueError("RTSP password must not be empty")

    log(f"PCAP: {pcap.name}")
    log("Captured PPPP CGI authentication profile loaded")
    endpoint = discover_local(camera_ip, seed, 5.0, discovery_port)
    log(f"PPPP endpoint: {endpoint.host}:{endpoint.port}")

    with PpppCgiClient(endpoint, seed, auth, timeout) as client:
        verify_auth(client)
        log("PPPP CGI authentication confirmed")
        params, onvif, rtsp = read_state(client)
        current_port = parse_port(rtsp.get("rtspport")) or DEFAULT_RTSP_PORT
        selected_port = current_port if rtsp_port is None else rtsp_port
        if not 1 <= selected_port <= 65535:
            raise ValueError("RTSP port must be between 1 and 65535")

        if clean_flag(onvif, "onvifenable") != "1":
            _body, values = client.request(
                query_path(
                    "set_onvif.cgi",
                    [("next_url", "rebootrtsp.htm"), ("onvifenable", "1")],
                )
            )
            if not response_is_success(values):
                raise RuntimeError("set_onvif.cgi did not report success")
            log("ONVIF enabled")
        else:
            log("ONVIF already enabled")

        _body, values = client.request(
            query_path(
                "set_rtsp.cgi",
                [
                    ("next_url", "rebootme.htm"),
                    ("rtspenable", "1"),
                    ("rtspport", str(selected_port)),
                    ("rtsp_auth_enable", "1"),
                    ("rtspuser", selected_user),
                    ("rtsppwd", selected_password),
                ],
            )
        )
        if not response_is_success(values):
            raise RuntimeError("set_rtsp.cgi did not report success")

        params, onvif, rtsp = read_state(client)
        immediate_ok = (
            clean_flag(onvif, "onvifenable") == "1"
            and clean_flag(rtsp, "rtspenable") == "1"
            and parse_port(rtsp.get("rtspport")) == selected_port
            and clean_flag(params, "rtsp_auth_enable") == "1"
            and params.get("rtsp_user") == selected_user
            and params.get("rtsp_pwd") == selected_password
        )
        if not immediate_ok:
            raise RuntimeError("RTSP settings were not confirmed by immediate readback")
        log(f"RTSP enabled in camera configuration on port {selected_port}")
        log("RTSP authentication enabled; credentials are not printed")
        request_reboot(client)
        log("Camera reboot requested")

    endpoint, client = reconnect_after_reboot(
        camera_ip, seed, auth, timeout, reboot_wait, discovery_port
    )
    try:
        params, onvif, rtsp = read_state(client)
        persistent_ok = (
            clean_flag(onvif, "onvifenable") == "1"
            and clean_flag(rtsp, "rtspenable") == "1"
            and parse_port(rtsp.get("rtspport")) == selected_port
            and clean_flag(params, "rtsp_auth_enable") == "1"
            and params.get("rtsp_user") == selected_user
            and params.get("rtsp_pwd") == selected_password
        )
        if not persistent_ok:
            raise RuntimeError("RTSP settings did not survive reboot")
        log(f"RTSP enable persisted after reboot; PPPP endpoint: {endpoint.host}:{endpoint.port}")
    finally:
        client.__exit__(None, None, None)


def disable_rtsp(
    camera_ip: str,
    pcap_value: str | None,
    script_dir: Path,
    timeout: float,
    reboot_wait: float,
    seed: str = DEFAULT_SEED,
    discovery_port: int = DEFAULT_DISCOVERY_PORT,
) -> None:
    pcap, auth = load_runtime(script_dir, camera_ip, pcap_value, seed)
    log(f"PCAP: {pcap.name}")
    log("Captured PPPP CGI authentication profile loaded")
    endpoint = discover_local(camera_ip, seed, 5.0, discovery_port)
    log(f"PPPP endpoint: {endpoint.host}:{endpoint.port}")

    with PpppCgiClient(endpoint, seed, auth, timeout) as client:
        verify_auth(client)
        log("PPPP CGI authentication confirmed")
        params, _onvif, rtsp = read_state(client)
        if clean_flag(rtsp, "rtspenable") == "0":
            log("RTSP is already disabled")
            return

        current_port = parse_port(rtsp.get("rtspport")) or DEFAULT_RTSP_PORT
        current_auth = clean_flag(params, "rtsp_auth_enable")
        if current_auth not in {"0", "1"}:
            current_auth = "0"
        current_user = params.get("rtsp_user")
        if current_user is None:
            current_user = rtsp.get("rtspuser", "")
        current_password = params.get("rtsp_pwd")
        if current_password is None:
            current_password = rtsp.get("rtsppwd", "")

        _body, values = client.request(
            query_path(
                "set_rtsp.cgi",
                [
                    ("next_url", "rebootme.htm"),
                    ("rtspenable", "0"),
                    ("rtspport", str(current_port)),
                    ("rtsp_auth_enable", current_auth),
                    ("rtspuser", current_user),
                    ("rtsppwd", current_password),
                ],
            )
        )
        if not response_is_success(values):
            raise RuntimeError("set_rtsp.cgi did not report success")

        _params, _onvif, rtsp = read_state(client)
        if clean_flag(rtsp, "rtspenable") != "0":
            raise RuntimeError("RTSP disable was not confirmed by immediate readback")
        log("RTSP disabled in camera configuration")
        request_reboot(client)
        log("Camera reboot requested")

    endpoint, client = reconnect_after_reboot(
        camera_ip, seed, auth, timeout, reboot_wait, discovery_port
    )
    try:
        _params, _onvif, rtsp = read_state(client)
        if clean_flag(rtsp, "rtspenable") != "0":
            raise RuntimeError("RTSP disable did not survive reboot")
        log(f"RTSP disable persisted after reboot; PPPP endpoint: {endpoint.host}:{endpoint.port}")
    finally:
        client.__exit__(None, None, None)
