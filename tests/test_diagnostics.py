from __future__ import annotations

import json
import socket
from unittest.mock import MagicMock, patch

import pytest

from net_diag.diagnostics import (
    build_diagnostic_report,
    check_tcp_connectivity,
    main,
    resolve_dns,
    validate_host,
)


def test_validate_host_accepts_valid_domains_and_ips_and_rejects_invalid() -> None:
    assert validate_host("example.org") == "example.org"
    assert validate_host("example.org.") == "example.org"
    assert validate_host("127.0.0.1") == "127.0.0.1"
    assert validate_host("::1") == "::1"

    with pytest.raises(ValueError):
        validate_host("")
    with pytest.raises(ValueError):
        validate_host("-invalid-hostname-.com")


def test_resolve_dns_handles_success_and_gaierror() -> None:
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
    ]
    with patch("socket.getaddrinfo", return_value=fake_addrinfo):
        res = resolve_dns("example.com")
        assert res.resolved is True
        assert res.addresses == ["93.184.216.34"]
        assert res.status == "RESOLVED"

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        fail = resolve_dns("nonexistent.example.invalid")
        assert fail.resolved is False
        assert fail.status == "DNS_FAILURE"


def test_tcp_connectivity_distinguishes_outcomes_and_rejects_boolean_ports() -> None:
    with pytest.raises(ValueError, match="integer between 1 and 65535"):
        check_tcp_connectivity("example.com", True)  # type: ignore[arg-type]

    mock_conn = MagicMock()
    with patch("socket.create_connection", return_value=mock_conn):
        ok = check_tcp_connectivity("example.com", 443)
        assert ok.reachable is True
        assert ok.status == "CONNECTED"

    with patch("socket.create_connection", side_effect=TimeoutError()):
        timed_out = check_tcp_connectivity("example.com", 443, timeout_seconds=1.0)
        assert timed_out.reachable is False
        assert timed_out.status == "TIMEOUT"

    with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
        refused = check_tcp_connectivity("example.com", 8080)
        assert refused.reachable is False
        assert refused.status == "CONNECTION_REFUSED"


def test_build_diagnostic_report_and_dns_skip_and_cli(capsys: pytest.CaptureFixture[str]) -> None:
    fake_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]
    with (
        patch("socket.getaddrinfo", return_value=fake_addrinfo),
        patch("socket.create_connection", return_value=MagicMock()),
    ):
        report = build_diagnostic_report("localhost", [80, 443, 80])
        assert report["dns"]["resolved"] is True
        assert report["summary"]["open_ports"] == 2
        assert len(report["tcp_checks"]) == 2
        assert [c["port"] for c in report["tcp_checks"]] == [80, 443]
        assert report["tcp_checks"][0]["status"] == "CONNECTED"

        assert main(["localhost", "--ports", "443"]) == 0
        cli_json = json.loads(capsys.readouterr().out)
        assert cli_json["tcp_checks"][0]["port"] == 443

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
        skipped = build_diagnostic_report("missing.example.invalid", [80, 443])
        assert skipped["dns"]["resolved"] is False
        assert all(c["status"] == "SKIPPED_DNS_FAILURE" for c in skipped["tcp_checks"])

    with pytest.raises(ValueError, match="must contain at least one"):
        build_diagnostic_report("localhost", [])
    with pytest.raises(ValueError, match="integer between 1 and 65535"):
        build_diagnostic_report("localhost", [70000])

    dual_stack = [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
    ]

    def dual_connect(addr: tuple[str, int], timeout: float = 3.0) -> MagicMock:
        host, _ = addr
        if host == "::1":
            raise ConnectionRefusedError()
        return MagicMock()

    with (
        patch("socket.getaddrinfo", return_value=dual_stack),
        patch("socket.create_connection", side_effect=dual_connect),
    ):
        report = build_diagnostic_report("localhost", [443])
        assert report["tcp_checks"][0]["reachable"] is True
        assert report["tcp_checks"][0]["host"] == "127.0.0.1"
