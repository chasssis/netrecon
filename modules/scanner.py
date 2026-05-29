"""
modules/scanner.py
Core scanning logic
"""

import ipaddress
import logging
import re
import socket
import ssl
import subprocess
import sys
import concurrent.futures
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── Input validation ──────────────────────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]
_BLOCKED_HOSTS = {"localhost", "localhost.localdomain"}
_HOST_RE = re.compile(r"^[a-zA-Z0-9._\-]+$")

# ── Port definitions ──────────────────────────────────────────────────────────

COMMON_PORTS = {
    # Remote access
    21: "FTP", 22: "SSH", 23: "Telnet",
    # Mail
    25: "SMTP", 110: "POP3", 143: "IMAP",
    465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S",
    # DNS
    53: "DNS",
    # Web
    70: "Gopher",
    80: "HTTP", 81: "HTTP-Alt",
    8000: "HTTP-Alt", 8001: "HTTP-Alt",
    8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "PHP-FPM",
    9090: "Prometheus",
    3000: "Dev-Server", 4000: "Dev-Server", 5000: "Dev-Server",
    # HTTPS
    443: "HTTPS",
    # Windows / Microsoft
    88: "Kerberos", 135: "MSRPC",
    139: "NetBIOS-SSN", 445: "SMB",
    3389: "RDP", 49152: "Dynamic-MSRPC",
    # Databases
    1433: "MSSQL", 1521: "Oracle-DB",
    3306: "MySQL", 5432: "PostgreSQL",
    5984: "CouchDB", 6379: "Redis",
    9200: "Elasticsearch", 9300: "Elasticsearch-Cluster",
    11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB-Shard", 28017: "MongoDB-Web",
    # Container / cloud
    2375: "Docker-API", 2376: "Docker-TLS",
    2379: "etcd", 6443: "Kubernetes-API",
    10250: "Kubelet",
    # Directory / auth
    389: "LDAP", 636: "LDAPS", 464: "Kerberos-Kpasswd",
    # Message brokers
    4369: "Erlang-EPMD",
    5671: "AMQPS", 5672: "RabbitMQ",
    9092: "Kafka", 15672: "RabbitMQ-UI",
    # Proxy / tunneling
    1080: "SOCKS", 1723: "PPTP", 3128: "Squid",
    # Remote desktop / GUI
    5800: "VNC-HTTP", 5900: "VNC",
    # File sharing / printing
    111: "RPCbind", 2049: "NFS",
    512: "rexec", 513: "rlogin", 514: "RSH",
    515: "LPD-Print", 631: "IPP",
    # App servers
    7001: "WebLogic", 7002: "WebLogic-SSL",
    # Misc
    179: "BGP", 6000: "X11",
    31337: "Custom/BackOrifice",
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

PORT_RISK_NOTES = {
    21:    "FTP transmits credentials in plaintext. Check for anonymous login.",
    22:    "SSH exposed — ensure key-based auth only; disable password auth.",
    23:    "Telnet transmits all data in plaintext. Disable immediately.",
    25:    "SMTP exposed — verify it's not an open relay.",
    80:    "Plain HTTP — all traffic unencrypted. Enforce HTTPS redirect.",
    88:    "Kerberos — exposure can enable AS-REP roasting or ticket attacks.",
    111:   "RPCbind exposed — can be used to enumerate NFS shares.",
    135:   "MSRPC exposed — common lateral movement vector on Windows.",
    139:   "NetBIOS-SSN exposed — legacy Windows file sharing, disable if unused.",
    389:   "LDAP exposed in plaintext — use LDAPS (636) instead.",
    445:   "SMB exposed — vulnerable to EternalBlue/MS17-010 if unpatched.",
    512:   "rexec transmits credentials in plaintext. Disable.",
    513:   "rlogin — legacy protocol with weak auth. Disable.",
    514:   "RSH — unauthenticated remote shell. Disable immediately.",
    1080:  "SOCKS proxy exposed — may be used for traffic tunneling/anonymisation.",
    1433:  "MSSQL exposed — restrict to localhost unless explicitly needed.",
    1521:  "Oracle DB exposed — restrict to trusted networks only.",
    1723:  "PPTP VPN — uses weak MPPE encryption, deprecated protocol.",
    2049:  "NFS exposed — misconfigured exports can allow full filesystem access.",
    2375:  "Docker API exposed WITHOUT TLS — full host compromise risk.",
    2376:  "Docker API (TLS) — verify client certificate authentication is enforced.",
    2379:  "etcd exposed — may leak Kubernetes secrets without authentication.",
    3000:  "Development server port — should not be exposed in production.",
    3306:  "MySQL exposed — restrict to localhost or trusted networks.",
    3389:  "RDP exposed — high-value brute-force target; use NLA and VPN.",
    4000:  "Development server port — should not be exposed in production.",
    5000:  "Development server port — should not be exposed in production.",
    5432:  "PostgreSQL exposed — restrict to localhost or trusted networks.",
    5672:  "RabbitMQ exposed — verify authentication is configured.",
    5900:  "VNC exposed — encrypt with SSH tunnel; disable if unused.",
    5984:  "CouchDB exposed — default installs may have open admin interface.",
    6000:  "X11 exposed — allows remote screen capture and input injection.",
    6379:  "Redis exposed — no authentication by default; data exfiltration risk.",
    6443:  "Kubernetes API exposed — verify RBAC and authentication are enforced.",
    7001:  "WebLogic exposed — historically critical CVEs (e.g. CVE-2020-14882).",
    9000:  "PHP-FPM or SonarQube — verify this port is intentionally exposed.",
    9200:  "Elasticsearch exposed — no auth by default; full data access risk.",
    10250: "Kubelet API — anonymous access can allow RCE on Kubernetes nodes.",
    11211: "Memcached exposed — no authentication; DDoS amplification risk.",
    15672: "RabbitMQ management UI — ensure default credentials are changed.",
    27017: "MongoDB exposed — no authentication by default; full data access risk.",
    28017: "MongoDB web interface — deprecated, disable this port.",
    31337: "Non-standard high port open — investigate what service is running.",
    49152: "Dynamic MSRPC port range — typical on Windows domain controllers.",
}

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "default", "google", "mail", "dkim", "smtp",
    "selector1", "selector2",   # Microsoft 365
    "k1", "k2",                 # Klaviyo / Mailchimp
    "s1", "s2",
    "mimecast",
    "pm",                       # Protonmail
    "dkimrulez",
]

# Ports where an HTTP GET probe gives better banner info than a raw recv
_HTTP_PROBE_PORTS = {
    70, 80, 81, 8000, 8001, 8008, 8080, 8081,
    3000, 4000, 5000, 8888, 9000, 9090, 15672,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize_target(target: str) -> str:
    """Strip scheme/path from target, returning bare hostname or IP."""
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    return parsed.hostname or target


def validate_target(raw: str) -> Optional[str]:
    """
    Normalize and validate a scan target.
    Returns the cleaned hostname/IP, or None if invalid or disallowed.
    Rejects empty input, localhost, private IP ranges, and illegal characters.
    """
    target = normalize_target(raw)
    if not target:
        return None
    if target.lower() in _BLOCKED_HOSTS:
        return None
    if not _HOST_RE.match(target):
        return None
    try:
        addr = ipaddress.ip_address(target)
        if any(addr in net for net in _PRIVATE_NETS):
            return None
    except ValueError:
        pass  # hostname — not an IP, that's fine
    return target


def _ssl_warnings(days_left, protocol):
    warnings = []
    if days_left is not None and days_left < 0:
        warnings.append("Certificate has EXPIRED.")
    elif days_left is not None and days_left <= 30:
        warnings.append(f"Certificate expires in {days_left} days.")
    if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        warnings.append(f"Deprecated protocol in use: {protocol}. Upgrade to TLS 1.2+.")
    return warnings


# ── Scanner ───────────────────────────────────────────────────────────────────

class ReconScanner:
    def __init__(self, target: str):
        self.raw_target = target
        self.target = normalize_target(target)
        self.timestamp = datetime.utcnow().isoformat()

    # ── Port scanner ──────────────────────────────────────────────────────────

    def scan_ports(self, timeout: float = 0.75) -> dict:
        """
        TCP connect scan across all ports in COMMON_PORTS using a thread pool.
        Returns open ports with service labels, banners, and risk notes.
        """
        logger.debug("Port scan starting: target=%s ports=%d", self.target, len(COMMON_PORTS))
        open_ports = []

        def check_port(port):
            try:
                with socket.create_connection((self.target, port), timeout=timeout):
                    return {
                        "port": port,
                        "service": COMMON_PORTS.get(port, "Unknown"),
                        "state": "open",
                        "banner": self._grab_banner(port),
                        "risk_note": PORT_RISK_NOTES.get(port),
                    }
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_port, p): p for p in COMMON_PORTS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])

        return {
            "target": self.target,
            "open_ports": open_ports,
            "total_scanned": len(COMMON_PORTS),
            "total_open": len(open_ports),
            "risk_count": sum(1 for p in open_ports if p["risk_note"]),
        }

    def _grab_banner(self, port: int, timeout: float = 1.5) -> Optional[str]:
        """
        Protocol-aware banner grab.
        Sends an HTTP GET on web ports for richer service info;
        falls back to a raw recv on all other ports.
        """
        try:
            if port in _HTTP_PROBE_PORTS:
                with socket.create_connection((self.target, port), timeout=timeout) as s:
                    s.sendall(
                        f"GET / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()
                    )
                    s.settimeout(timeout)
                    resp = s.recv(1024).decode("utf-8", errors="ignore")
                    for line in resp.splitlines():
                        if line.lower().startswith("server:"):
                            return line.split(":", 1)[-1].strip()[:120]
                    first = resp.splitlines()[0] if resp else None
                    return first[:120] if first else None
            else:
                with socket.create_connection((self.target, port), timeout=timeout) as s:
                    s.settimeout(timeout)
                    banner = s.recv(512).decode("utf-8", errors="ignore").strip()
                    return banner[:120] if banner else None
        except Exception:
            return None

    # ── WHOIS ─────────────────────────────────────────────────────────────────

    def whois_lookup(self) -> dict:
        """Fetch WHOIS registration data for the target domain."""
        if not WHOIS_AVAILABLE:
            return self._fallback_whois()

        try:
            w = python_whois.whois(self.target)
            creation   = w.creation_date
            expiration = w.expiration_date
            if isinstance(creation, list):   creation   = creation[0]
            if isinstance(expiration, list): expiration = expiration[0]

            return {
                "domain":          self.target,
                "registrar":       str(w.registrar) if w.registrar else "N/A",
                "creation_date":   str(creation)    if creation    else "N/A",
                "expiration_date": str(expiration)  if expiration  else "N/A",
                "name_servers":    list(w.name_servers) if w.name_servers else [],
                "status":          w.status if isinstance(w.status, list) else [str(w.status)],
                "org":             str(w.org)     if hasattr(w, "org")     and w.org     else "N/A",
                "country":         str(w.country) if hasattr(w, "country") and w.country else "N/A",
            }
        except Exception as e:
            return {"error": f"WHOIS lookup failed: {e}"}

    def _fallback_whois(self) -> dict:
        """Use the system whois binary as fallback (Unix only)."""
        if sys.platform == "win32":
            return {
                "error": (
                    "WHOIS requires the python-whois library on Windows. "
                    "Run: pip install python-whois"
                )
            }
        try:
            result = subprocess.run(
                ["whois", self.target],
                capture_output=True, text=True, timeout=10
            )
            parsed = {}
            for line in result.stdout.splitlines():
                for field in ["Registrar:", "Creation Date:", "Registry Expiry Date:",
                              "Name Server:", "Registrant Country:"]:
                    if line.strip().startswith(field):
                        key = field.rstrip(":").replace(" ", "_").lower()
                        parsed.setdefault(key, line.split(":", 1)[-1].strip())
            parsed["raw_available"] = True
            return parsed
        except FileNotFoundError:
            return {"error": "System 'whois' binary not found. Run: pip install python-whois"}
        except Exception as e:
            return {"error": str(e)}

    # ── HTTP headers ──────────────────────────────────────────────────────────

    def analyze_headers(self) -> dict:
        """
        Fetch HTTP response headers and score the security posture (A–F).
        """
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not installed"}

        url = f"https://{self.target}"
        logger.debug("HTTP header analysis: target=%s", self.target)
        try:
            resp = requests.get(url, timeout=8, allow_redirects=True, verify=False)
        except requests.exceptions.SSLError:
            try:
                url = f"http://{self.target}"
                resp = requests.get(url, timeout=8, allow_redirects=True)
            except Exception as e:
                return {"error": str(e)}
        except Exception as e:
            return {"error": str(e)}

        headers = dict(resp.headers)
        header_keys_lower = {k.lower() for k in headers}
        present = [h for h in SECURITY_HEADERS if h.lower() in header_keys_lower]
        missing = [h for h in SECURITY_HEADERS if h.lower() not in header_keys_lower]

        score = int((len(present) / len(SECURITY_HEADERS)) * 100)
        grade = (
            "A" if score >= 85 else
            "B" if score >= 70 else
            "C" if score >= 50 else
            "D" if score >= 30 else "F"
        )

        return {
            "url":                      url,
            "status_code":              resp.status_code,
            "server":                   headers.get("Server", headers.get("server", "Hidden")),
            "x_powered_by":             headers.get("X-Powered-By", headers.get("x-powered-by", "Not disclosed")),
            "security_headers_present": present,
            "security_headers_missing": missing,
            "security_score":           score,
            "grade":                    grade,
            "redirect_chain":           [str(r.url) for r in resp.history],
            "content_type":             headers.get("Content-Type", "N/A"),
        }

    # ── DNS enumeration ───────────────────────────────────────────────────────

    def dns_enum(self) -> dict:
        """
        Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME).
        Flags SPF/DMARC in TXT and probes common DKIM selectors.
        """
        logger.debug("DNS enumeration: target=%s", self.target)

        if not DNS_AVAILABLE:
            return self._socket_dns_fallback()

        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(self.target, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []

        # dnspython wraps TXT values in quotes — strip them before matching
        txt_analysis = {"spf": None, "dmarc": None}
        for txt in records.get("TXT", []):
            clean = txt.strip('"')
            if clean.startswith("v=spf1"):
                txt_analysis["spf"] = clean

        # DMARC lives at _dmarc.<domain>, not the domain's own TXT records
        try:
            dmarc_ans = dns.resolver.resolve(f"_dmarc.{self.target}", "TXT", lifetime=5)
            for r in dmarc_ans:
                val = str(r).strip('"')
                if "v=DMARC1" in val:
                    txt_analysis["dmarc"] = val
                    break
        except Exception:
            pass

        return {
            "domain":        self.target,
            "records":       records,
            "ip_addresses":  records.get("A", []),
            "ipv6_addresses":records.get("AAAA", []),
            "mail_servers":  records.get("MX", []),
            "name_servers":  records.get("NS", []),
            "txt_analysis":  txt_analysis,
            "dkim_records":  self._probe_dkim_selectors(),
        }

    def _probe_dkim_selectors(self) -> list:
        """Try common DKIM selectors and return those that resolve."""
        found = []
        for selector in DKIM_SELECTORS:
            dkim_host = f"{selector}._domainkey.{self.target}"
            try:
                if DNS_AVAILABLE:
                    answers = dns.resolver.resolve(dkim_host, "TXT", lifetime=2)
                    for r in answers:
                        found.append({"selector": selector, "record": str(r)[:200]})
                        break
                else:
                    socket.getaddrinfo(dkim_host, None, socket.AF_INET)
                    found.append({"selector": selector, "record": "(present)"})
            except Exception:
                pass
        return found

    def _socket_dns_fallback(self) -> dict:
        """Minimal DNS using socket when dnspython is unavailable."""
        try:
            ip = socket.gethostbyname(self.target)
            return {
                "domain":       self.target,
                "ip_addresses": [ip],
                "note":         "Full DNS library not available — only A record resolved",
            }
        except Exception as e:
            return {"error": str(e)}

    # ── SSL / TLS ─────────────────────────────────────────────────────────────

    def ssl_check(self) -> dict:
        """
        Inspect the SSL/TLS certificate: expiry, issuer, SANs, protocol version.
        """
        logger.debug("SSL/TLS check: target=%s", self.target)
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((self.target, 443), timeout=8),
                server_hostname=self.target,
            ) as ssock:
                cert     = ssock.getpeercert()
                protocol = ssock.version()

            not_after  = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")

            try:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry_dt - datetime.utcnow()).days
            except Exception:
                days_left = None

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer  = dict(x[0] for x in cert.get("issuer", []))
            sans    = [e[1] for e in cert.get("subjectAltName", []) if e[0] == "DNS"]

            return {
                "common_name":       subject.get("commonName", "N/A"),
                "issuer":            issuer.get("organizationName", "N/A"),
                "valid_from":        not_before,
                "valid_until":       not_after,
                "days_remaining":    days_left,
                "protocol_version":  protocol,
                "subject_alt_names": sans,
                "expired":           days_left is not None and days_left < 0,
                "expiring_soon":     days_left is not None and 0 <= days_left <= 30,
                "warnings":          _ssl_warnings(days_left, protocol),
            }
        except ssl.SSLError as e:
            return {"error": f"SSL error: {e}"}
        except Exception as e:
            return {"error": str(e)}

    # ── IP Information ────────────────────────────────────────────────────────

    def ip_info(self) -> dict:
        """
        Resolve target to IP, then fetch geolocation, ASN, and ISP data
        from ipapi.co (free, no API key required).
        """
        logger.debug("IP info lookup: target=%s", self.target)
        if not REQUESTS_AVAILABLE:
            return {"error": "requests library not installed"}

        try:
            ip = socket.gethostbyname(self.target)
        except socket.gaierror as e:
            return {"error": f"Could not resolve hostname: {e}"}

        try:
            resp = requests.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=8,
                headers={"User-Agent": "NetRecon/1.0 (educational/authorized use)"},
            )
            data = resp.json()
            if data.get("error"):
                return {"ip": ip, "error": data.get("reason", "IP lookup failed")}

            return {
                "ip":           ip,
                "hostname":     self.target,
                "org":          data.get("org", "N/A"),
                "asn":          data.get("asn", "N/A"),
                "city":         data.get("city", "N/A"),
                "region":       data.get("region", "N/A"),
                "country":      data.get("country_name", "N/A"),
                "country_code": data.get("country_code", ""),
                "postal":       data.get("postal", "N/A"),
                "timezone":     data.get("timezone", "N/A"),
                "latitude":     data.get("latitude"),
                "longitude":    data.get("longitude"),
            }
        except Exception as e:
            return {"ip": ip, "error": f"IP info lookup failed: {e}"}
