# tcp-dns-diagnostics

Hostname validation, DNS resolution timing, and concurrent TCP port connectivity checks built in **Python 3.12** using only the standard library (`socket`, `ipaddress`, `concurrent.futures`).

## Features

- **Host & port validation**: Checks IPv4/IPv6 addresses and domain names cleanly before touching sockets, and rejects out-of-range or boolean port arguments.
- **Single-pass DNS lookup**: `resolve_dns()` measures system resolver time via `socket.getaddrinfo()` and handles `socket.gaierror` cleanly.
- **Concurrent TCP checks**: `build_diagnostic_report()` deduplicates target ports, resolves DNS once upfront, skips port checks when DNS fails, and runs parallel TCP handshakes via `ThreadPoolExecutor` (distinguishing `CONNECTED`, `CONNECTION_REFUSED`, `TIMEOUT`, and `UNREACHABLE`).
- **Command-line runner**: Outputs structured JSON reports directly from the terminal.

## Quick Start

```bash
pip install -e ".[dev]"
ruff check .
pytest -v
```

Run from the terminal:

```bash
PYTHONPATH=src python -m net_diag.diagnostics example.com --ports 80 443 --timeout 2.0
```
