from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


@dataclass(frozen=True)
class DnsCheckResult:
    host: str
    resolved: bool
    addresses: list[str]
    elapsed_ms: float
    status: str
    explanation: str


@dataclass(frozen=True)
class TcpProbeResult:
    host: str
    port: int
    reachable: bool
    elapsed_ms: float
    status: str
    explanation: str


def _validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise ValueError(f"Port must be an integer between 1 and 65535 (got {port!r})")
    return port


def validate_host(host: str) -> str:
    cleaned = host.strip()
    if not cleaned:
        raise ValueError("Host must not be empty")
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass

    domain = cleaned.rstrip(".")
    if not domain or not HOSTNAME_RE.match(domain):
        raise ValueError(f"Invalid hostname or IP address: '{host}'")
    return domain


def resolve_dns(host: str) -> DnsCheckResult:
    cleaned = validate_host(host)
    t0 = time.perf_counter()
    try:
        infos = socket.getaddrinfo(cleaned, None, type=socket.SOCK_STREAM)
        elapsed = (time.perf_counter() - t0) * 1000.0
        addrs = sorted({str(info[4][0]) for info in infos})
        return DnsCheckResult(
            host=cleaned,
            resolved=True,
            addresses=addrs,
            elapsed_ms=round(elapsed, 2),
            status="RESOLVED",
            explanation=f"Resolved {len(addrs)} address(es) via system resolver.",
        )
    except socket.gaierror as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return DnsCheckResult(
            host=cleaned,
            resolved=False,
            addresses=[],
            elapsed_ms=round(elapsed, 2),
            status="DNS_FAILURE",
            explanation=f"DNS lookup failed ({exc}). Check domain spelling or local DNS resolver.",
        )


def check_tcp_connectivity(
    host: str,
    port: int,
    timeout_seconds: float = 3.0,
) -> TcpProbeResult:
    cleaned = validate_host(host)
    _validate_port(port)
    if timeout_seconds <= 0:
        raise ValueError("Timeout must be positive")

    t0 = time.perf_counter()
    try:
        with socket.create_connection((cleaned, port), timeout=timeout_seconds):
            elapsed = (time.perf_counter() - t0) * 1000.0
            return TcpProbeResult(
                host=cleaned,
                port=port,
                reachable=True,
                elapsed_ms=round(elapsed, 2),
                status="CONNECTED",
                explanation=f"TCP three-way handshake succeeded on port {port}.",
            )
    except TimeoutError:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TcpProbeResult(
            host=cleaned,
            port=port,
            reachable=False,
            elapsed_ms=round(elapsed, 2),
            status="TIMEOUT",
            explanation=(
                f"Connection timed out after {timeout_seconds:.1f}s. "
                "A firewall may be dropping packets or the host is offline."
            ),
        )
    except ConnectionRefusedError:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TcpProbeResult(
            host=cleaned,
            port=port,
            reachable=False,
            elapsed_ms=round(elapsed, 2),
            status="CONNECTION_REFUSED",
            explanation=(
                f"Host is online and reachable, but no service is listening on TCP port {port} (RST received)."
            ),
        )
    except OSError as exc:
        elapsed = (time.perf_counter() - t0) * 1000.0
        return TcpProbeResult(
            host=cleaned,
            port=port,
            reachable=False,
            elapsed_ms=round(elapsed, 2),
            status="UNREACHABLE",
            explanation=f"Network or routing error: {exc}",
        )


def build_diagnostic_report(
    host: str,
    ports: list[int],
    timeout_seconds: float = 3.0,
) -> dict[str, Any]:
    if timeout_seconds <= 0.0:
        raise ValueError("timeout_seconds must be positive")
    if not ports:
        raise ValueError("ports must contain at least one TCP port")

    unique_ports = [_validate_port(port) for port in dict.fromkeys(ports)]
    dns_result = resolve_dns(host)

    if dns_result.resolved and dns_result.addresses:
        connect_target = dns_result.addresses[0]
        max_workers = min(len(unique_ports), 16)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            tcp_results = list(
                pool.map(
                    lambda p: check_tcp_connectivity(
                        connect_target, p, timeout_seconds=timeout_seconds
                    ),
                    unique_ports,
                )
            )
    else:
        tcp_results = [
            TcpProbeResult(
                host=dns_result.host,
                port=port,
                reachable=False,
                elapsed_ms=0.0,
                status="SKIPPED_DNS_FAILURE",
                explanation="Skipped TCP handshake because hostname resolution failed.",
            )
            for port in unique_ports
        ]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "target_host": dns_result.host,
        "dns": asdict(dns_result),
        "tcp_checks": [asdict(r) for r in tcp_results],
        "note": (
            "TCP handshake checks give a more reliable view of port reachability "
            "than ICMP echo when firewalls filter ping traffic."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run DNS resolution timing and concurrent TCP port checks."
    )
    parser.add_argument("host", help="Hostname or IPv4/IPv6 address to inspect")
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=[80, 443],
        help="TCP ports to check (default: 80 443)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Socket timeout in seconds per port (default: 3.0)",
    )
    args = parser.parse_args(argv)

    report = build_diagnostic_report(
        args.host,
        args.ports,
        timeout_seconds=args.timeout,
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
