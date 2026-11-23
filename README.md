# tcp-dns-diagnostics

Command-line DNS lookup timer and concurrent TCP handshake tester built with **Python 3.12** standard-library sockets.

## Features

- **Host and port validation**: Accepts IPv4, IPv6, and RFC 1123 domains (stripping trailing DNS root dots) while rejecting malformed hostnames and non-integer/boolean ports cleanly.
- **Separate DNS and TCP diagnostics**: `resolve_dns()` isolates name-resolution latency (`NXDOMAIN` / resolver failures), then `build_diagnostic_report()` probes resolved addresses in parallel across ports via `ThreadPoolExecutor`.
- **Dual-stack fallback**: When DNS returns multiple A/AAAA records, ports try each candidate IP cleanly instead of failing on the first address family.
- **Distinct failure taxonomy & rollup**: Reports `CONNECTED`, `CONNECTION_REFUSED`, `TIMEOUT`, `SKIPPED_DNS_FAILURE`, and `UNREACHABLE` per port alongside a top-level `summary` (`total_ports`, `open_ports`, `unreachable_ports`, `resolved_addresses`).

## Technology Stack

- Python 3.11+ (tested on Python 3.12)
- Python standard library (`socket`, `ipaddress`, `concurrent.futures`, `argparse`)
- pytest (`unittest.mock`), Ruff

## Installation

```bash
pip install -e ".[dev]"
```

## Usage Examples

Run DNS resolution and concurrent port checks from the CLI:

```bash
tcp-dns-diag example.com --ports 80 443 8080 --timeout 2.5
```

Call diagnostics from Python:

```python
from net_diag.diagnostics import build_diagnostic_report

report = build_diagnostic_report("example.com", [80, 443], timeout_seconds=2.5)
print(report["dns"], report["tcp_checks"])
```

## Technical Implementation Details

- DNS resolution happens once inside `build_diagnostic_report()` before fan-out TCP workers run, preventing repeated resolver calls from skewing handshake latency or returning `NXDOMAIN` per port.
- `_validate_port()` rejects Python `bool` values (`True == 1`) explicitly so boolean misconfiguration raises `ValueError` rather than probing TCP port 1.

## Project Structure

```text
tcp-dns-diagnostics/
├── src/net_diag/
│   ├── __init__.py
│   └── diagnostics.py
├── tests/
│   └── test_diagnostics.py
├── pyproject.toml
└── requirements.txt
```

## Testing

All tests mock `socket.getaddrinfo` and `socket.create_connection` so the suite runs deterministically offline:

```bash
ruff check .
pytest -v
```

## Known Limitations & Future Improvements

- `socket.create_connection()` tests TCP reachability only and does not validate TLS handshakes or certificate chains; integrating an optional `ssl` probe pass for port `443` is planned.
- UDP services (DNS-over-UDP, QUIC) cannot be verified by TCP SYN/ACK handshakes.
