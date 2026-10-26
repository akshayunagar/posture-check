"""Open-port check.

A plain TCP connect scan — no raw sockets, so it needs no privileges and runs
the same in CI as it does on a laptop. The judgement is in the policy below:
an open port is only a finding if it should not have been open.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..models import Finding, Severity, Target
from .base import CheckError

DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445,
    1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
)


@dataclass(frozen=True, slots=True)
class PortRule:
    service: str
    severity: Severity
    why: str
    fix: str


# Ports that are a problem when exposed, and why. Anything not listed is
# reported as informational rather than guessed at.
EXPOSURE_POLICY: dict[int, PortRule] = {
    21: PortRule("FTP", Severity.HIGH, "FTP transmits credentials in clear text.",
                 "Replace with SFTP or SCP and close port 21."),
    23: PortRule("Telnet", Severity.CRITICAL, "Telnet transmits credentials in clear text.",
                 "Disable telnet and use SSH."),
    135: PortRule("MSRPC", Severity.HIGH,
                  "Windows RPC should never face the internet.",
                  "Restrict to the internal network with a firewall rule."),
    139: PortRule("NetBIOS", Severity.HIGH, "SMB/NetBIOS exposure is a common entry point.",
                  "Block at the perimeter."),
    445: PortRule("SMB", Severity.CRITICAL,
                  "Exposed SMB has been the vector for widespread ransomware.",
                  "Block 445 at the perimeter immediately."),
    1433: PortRule("MSSQL", Severity.CRITICAL, "A database should not be reachable from outside.",
                   "Restrict to application hosts only."),
    1521: PortRule("Oracle", Severity.CRITICAL, "A database should not be reachable from outside.",
                   "Restrict to application hosts only."),
    2375: PortRule("Docker API (unencrypted)", Severity.CRITICAL,
                   "The unauthenticated Docker API grants root on the host.",
                   "Disable the TCP socket; use the local socket or enable TLS "
                   "with client certificates."),
    3306: PortRule("MySQL", Severity.CRITICAL, "A database should not be reachable from outside.",
                   "Restrict to application hosts only."),
    3389: PortRule("RDP", Severity.HIGH,
                   "Exposed RDP is continuously brute-forced.",
                   "Put behind a VPN and require MFA."),
    5432: PortRule("PostgreSQL", Severity.CRITICAL,
                   "A database should not be reachable from outside.",
                   "Restrict to application hosts only."),
    5900: PortRule("VNC", Severity.HIGH, "VNC often ships with weak or no authentication.",
                   "Tunnel over SSH or remove."),
    6379: PortRule("Redis", Severity.CRITICAL, "Redis defaults to no authentication.",
                   "Bind to localhost, require a password, and firewall the port."),
    9200: PortRule("Elasticsearch", Severity.CRITICAL,
                   "An open Elasticsearch endpoint usually means the whole index is readable.",
                   "Enable authentication and restrict network access."),
    27017: PortRule("MongoDB", Severity.CRITICAL,
                    "MongoDB has historically shipped unauthenticated.",
                    "Enable authentication and firewall the port."),
    25: PortRule("SMTP", Severity.MEDIUM, "An open relay can be abused to send mail as you.",
                 "Confirm relaying is restricted to authenticated senders."),
    8080: PortRule("HTTP (alt)", Severity.MEDIUM,
                   "Admin interfaces are often left on 8080 without authentication.",
                   "Confirm what is listening and whether it requires authentication."),
}


def probe(host: str, port: int, timeout: float = 1.5) -> bool:
    """Return True if a TCP connection succeeds.

    A failure to connect is not an error — it is the normal case for a closed
    port. A failure to *resolve* is an error, and is raised by `resolve()`
    before any probing starts.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def resolve(host: str) -> str:
    """Resolve `host` once up front, so an unresolvable target is reported as a
    check that could not run rather than as a host with nothing open."""
    try:
        return socket.gethostbyname(host)
    except OSError as exc:
        raise CheckError(f"could not resolve {host}: {exc}") from exc


def evaluate(host: str, open_ports: list[int]) -> list[Finding]:
    """Pure function: given open ports, decide what is a problem."""
    findings: list[Finding] = []
    for port in sorted(open_ports):
        rule = EXPOSURE_POLICY.get(port)
        if rule is None:
            findings.append(
                Finding(
                    target=host,
                    check="open-ports",
                    rule="port-open",
                    title=f"Port {port} is open",
                    severity=Severity.INFO,
                    detail=f"TCP {port} accepted a connection. No policy rule covers this port.",
                    remediation="Confirm this port is intentionally open and documented.",
                    evidence={"port": port},
                )
            )
            continue
        findings.append(
            Finding(
                target=host,
                check="open-ports",
                rule=f"exposed-{rule.service.split()[0].lower()}",
                title=f"{rule.service} exposed on port {port}",
                severity=rule.severity,
                detail=f"TCP {port} ({rule.service}) accepted a connection. {rule.why}",
                remediation=rule.fix,
                evidence={"port": port, "service": rule.service},
            )
        )
    return findings


class OpenPortsCheck:
    name = "open-ports"

    def __init__(self, timeout: float = 1.5, workers: int = 32) -> None:
        self.timeout = timeout
        self.workers = workers

    def applies_to(self, target: Target) -> bool:
        return True

    def run(self, target: Target) -> list[Finding]:
        address = resolve(target.host)
        ports = target.ports or DEFAULT_PORTS
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            results = list(pool.map(lambda p: (p, probe(address, p, self.timeout)), ports))
        return evaluate(target.host, [p for p, is_open in results if is_open])
