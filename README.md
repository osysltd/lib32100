# lib32100

`lib32100` is a dependency-free Python toolkit for compatible IP cameras that expose the supported encrypted PPPP LAN transport and CGI configuration endpoints.

It can extract an authenticated CGI profile from an existing classic PCAP capture, discover the camera on the local network, communicate with its PPPP/CGI interface, enable authenticated RTSP and ONVIF persistently, disable RTSP again, and verify configuration state before and after a camera reboot.

## What it does

- Reads classic PCAP captures with Ethernet or raw IPv4 link types.
- Reassembles TCP payloads used by the supported PPPP transport.
- Decrypts and encrypts PPPP records with the configured protocol seed.
- Extracts the complete CGI authentication profile from captured authenticated requests.
- Performs the local UDP discovery handshake and resolves the camera PPPP endpoint.
- Opens an encrypted PPPP TCP session and sends CGI GET requests.
- Reads current camera, ONVIF, and RTSP configuration state.
- Enables ONVIF when needed.
- Enables RTSP with authentication, a selected username, password, and port.
- Verifies RTSP state immediately after writing it.
- Reboots the camera, reconnects, and verifies that the RTSP configuration persisted.
- Disables RTSP while preserving the current RTSP port and authentication fields.
- Exposes the low-level protocol helpers as an importable Python library.

## Compatibility

This project is generic at the product and command-line level, but it is not a universal RTSP enabler for every camera. A device must implement the PPPP record format, discovery handshake, encryption scheme, and CGI endpoints used by this library.

The default camera IP, protocol seed, discovery port, and RTSP port match the currently supported protocol profile. The camera IP, protocol seed, discovery port, and RTSP port can be overridden where applicable.

## Requirements

- Python 3.10 or newer.
- A classic PCAP capture containing an authenticated PPPP/CGI request to the target camera.
- Local network access to the camera.
- Authorization to inspect the capture and change the camera configuration.

No third-party Python packages are required at runtime.

## Installation

From the repository root:

```bash
python -m pip install .
```

For development without installation:

```bash
PYTHONPATH=src python -m lib32100 --help
```

On Windows PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m lib32100 --help
```

## Usage

### Extract the CGI authentication profile

```bash
lib32100 extract --pcap capture.pcap --camera-ip 192.168.100.2
```

The command prints the extracted profile and writes it to `lib32100_credentials.json` by default. The file contains credentials and must be protected accordingly.

If `--pcap` is omitted, the command expects exactly one `.pcap` file in the current working directory.

### Enable persistent RTSP

```bash
lib32100 enable-rtsp --pcap capture.pcap --camera-ip 192.168.100.2
```

When `--rtsp-user` and `--rtsp-password` are omitted, the camera credentials extracted from the capture are reused for RTSP. The existing RTSP port is preserved unless `--rtsp-port` is provided.

Example with explicit RTSP settings:

```bash
lib32100 enable-rtsp \
  --pcap capture.pcap \
  --camera-ip 192.168.100.2 \
  --rtsp-user viewer \
  --rtsp-password strong-password \
  --rtsp-port 10554
```

### Disable persistent RTSP

```bash
lib32100 disable-rtsp --pcap capture.pcap --camera-ip 192.168.100.2
```

The disable operation keeps the current RTSP port and authentication fields while changing only the RTSP enabled state, then verifies that the change persists after reboot.

### Override protocol parameters

For a compatible firmware variant that uses another seed or discovery port:

```bash
lib32100 enable-rtsp \
  --pcap capture.pcap \
  --camera-ip 192.168.100.2 \
  --seed custom-seed \
  --discovery-port 32108
```

Run command-specific help to see every option:

```bash
lib32100 extract --help
lib32100 enable-rtsp --help
lib32100 disable-rtsp --help
```

## Python API

The package exposes both high-level operations and the protocol helpers used by the CLI.

```python
from pathlib import Path

from lib32100 import enable_rtsp


enable_rtsp(
    camera_ip="192.168.100.2",
    pcap_value="capture.pcap",
    script_dir=Path.cwd(),
    rtsp_user=None,
    rtsp_password=None,
    rtsp_port=None,
    timeout=3.0,
    reboot_wait=90.0,
)
```

The high-level functions perform readback verification. RTSP enable and disable operations also reconnect after reboot and verify that the selected state persisted.

## Security notes

The PCAP and extracted JSON can contain live camera credentials. Do not commit captures or credential files to Git. The included `.gitignore` excludes `*.pcap` and the default credential output file.

The enable and disable commands do not print RTSP credentials. The `extract` command intentionally prints the extracted profile because credential extraction is its explicit function.

Use this software only with devices and network captures that you own or are authorized to administer.

## Limitations

- Only classic PCAP is supported. PCAPNG is not parsed.
- Only Ethernet and raw IPv4 capture link types are supported.
- TCP reassembly requires a complete, gap-free payload sequence for a flow.
- IPv6 is not supported by the capture parser or local discovery path.
- Device compatibility depends on the supported PPPP and CGI protocol behavior.

## License

MIT. See `LICENSE`.
