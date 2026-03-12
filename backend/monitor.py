import requests
import socket
import ssl
import time
import json
import hashlib
import threading
from datetime import datetime, timezone
from urllib.parse import urlparse
from collections import deque


requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

WEBSITES = {
    "himatika": {
        "name": "himatikafmipaunhas",
        "url": "https://himatikafmipaunhas.id",
        "fallback_urls": [
            "http://himatikafmipaunhas.id",
            "https://www.himatikafmipaunhas.id",
            "http://www.himatikafmipaunhas.id",
        ],
        "color": "#00d4ff",
    },
    "fotografi": {
        "name": "ukmfotografiunhas.com",
        "url": "https://ukmfotografiunhas.com",
        "fallback_urls": [
            "http://ukmfotografiunhas.com",
            "https://www.ukmfotografiunhas.com",
            "http://www.ukmfotografiunhas.com",
        ],
        "color": "#a855f7",
    },
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]


class WebsiteMonitor:

    def __init__(self):
        self.history = {key: deque(maxlen=500) for key in WEBSITES}
        self.latest = {}
        self.uptime_tracker = {key: {"total": 0, "up": 0} for key in WEBSITES}
        self.security_events = deque(maxlen=200)
        self.scan_logs = deque(maxlen=300)
        self._lock = threading.Lock()
        self._content_hashes = {}

    def scan_website(self, site_key):
        site = WEBSITES[site_key]
        result = {
            "key": site_key,
            "name": site["name"],
            "url": site["url"],
            "color": site["color"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "offline",
            "status_code": 0,
            "response_time_ms": 0,
            "ssl": {},
            "headers": {},
            "security_headers": {},
            "security_score": 0,
            "content_length": 0,
            "server": "Unknown",
            "technologies": [],
            "dns": {},
            "content_changed": False,
            "redirect_chain": [],
        }

        urls_to_try = [site["url"]] + site.get("fallback_urls", [])
        response = None
        working_url = None

        for url in urls_to_try:
            try:
                resp = requests.get(
                    url,
                    timeout=15,
                    allow_redirects=True,
                    verify=False,
                    headers={
                        "User-Agent": "SOC-Dashboard-Monitor/1.0 (Security Check)"
                    },
                )
                response = resp
                working_url = url
                break
            except requests.RequestException:
                continue

        if response is not None:
            result["status"] = "online"
            result["status_code"] = response.status_code
            result["response_time_ms"] = round(response.elapsed.total_seconds() * 1000)
            result["content_length"] = len(response.content)
            result["url"] = working_url
            result["server"] = response.headers.get("Server", "Unknown")
            result["headers"] = dict(response.headers)

            sec_headers = {}
            present_count = 0
            for h in SECURITY_HEADERS:
                val = response.headers.get(h)
                sec_headers[h] = {
                    "present": val is not None,
                    "value": val or "Missing",
                }
                if val is not None:
                    present_count += 1
            result["security_headers"] = sec_headers
            result["security_score"] = round(
                (present_count / len(SECURITY_HEADERS)) * 100
            )

            techs = []
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                techs.append(powered_by)
            server = response.headers.get("Server", "")
            if server:
                techs.append(server)
            if "wp-content" in response.text[:5000]:
                techs.append("WordPress")
            if "laravel" in response.text[:5000].lower():
                techs.append("Laravel")
            if "joomla" in response.text[:5000].lower():
                techs.append("Joomla")
            result["technologies"] = techs

            if response.history:
                result["redirect_chain"] = [
                    {"url": r.url, "status": r.status_code} for r in response.history
                ]

            content_hash = hashlib.sha256(response.content).hexdigest()
            if site_key in self._content_hashes:
                if self._content_hashes[site_key] != content_hash:
                    result["content_changed"] = True
                    self._generate_event(
                        site_key,
                        "info",
                        "Content Change Detected",
                        f"Website content hash changed for {site['name']}",
                    )
            self._content_hashes[site_key] = content_hash

            self._analyze_security(site_key, result)

        else:
            result["status"] = "offline"
            result["response_time_ms"] = 0
            self._generate_event(
                site_key,
                "critical",
                "Website Unreachable",
                f"{site['name']} is not responding on any URL",
            )

        result["ssl"] = self._check_ssl(site_key)
        result["dns"] = self._check_dns(site_key)

        with self._lock:
            self.uptime_tracker[site_key]["total"] += 1
            if result["status"] == "online":
                self.uptime_tracker[site_key]["up"] += 1
            tracker = self.uptime_tracker[site_key]
            result["uptime_percent"] = round(
                (tracker["up"] / tracker["total"]) * 100, 2
            ) if tracker["total"] > 0 else 0

            self.latest[site_key] = result
            self.history[site_key].append(
                {
                    "timestamp": result["timestamp"],
                    "status": result["status"],
                    "response_time_ms": result["response_time_ms"],
                    "status_code": result["status_code"],
                    "security_score": result["security_score"],
                }
            )

        self._add_log(
            "info" if result["status"] == "online" else "critical",
            "Monitor",
            f"Scan complete: {site['name']} — {result['status'].upper()} "
            f"({result['status_code']}) — {result['response_time_ms']}ms",
        )

        return result

    def _check_ssl(self, site_key):
        site = WEBSITES[site_key]
        parsed = urlparse(site["url"])
        hostname = parsed.hostname

        ssl_info = {
            "valid": False,
            "issuer": "N/A",
            "subject": "N/A",
            "expires": "N/A",
            "days_remaining": 0,
            "protocol": "N/A",
            "cipher": "N/A",
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info["valid"] = True
                    ssl_info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    ssl_info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    ssl_info["protocol"] = ssock.version()
                    cipher = ssock.cipher()
                    ssl_info["cipher"] = cipher[0] if cipher else "N/A"

                    expires_str = cert.get("notAfter", "")
                    if expires_str:
                        from email.utils import parsedate_to_datetime

                        expires_dt = parsedate_to_datetime(expires_str)
                        ssl_info["expires"] = expires_dt.isoformat()
                        days_left = (
                            expires_dt - datetime.now(timezone.utc)
                        ).days
                        ssl_info["days_remaining"] = days_left

                        if days_left < 30:
                            self._generate_event(
                                site_key,
                                "warning",
                                "SSL Certificate Expiring Soon",
                                f"Certificate for {site['name']} expires in {days_left} days",
                            )
                        if days_left < 7:
                            self._generate_event(
                                site_key,
                                "critical",
                                "SSL Certificate Critical",
                                f"Certificate for {site['name']} expires in {days_left} days!",
                            )

        except ssl.SSLCertVerificationError as e:
            ssl_info["error"] = f"Certificate verification failed: {e}"
            ssl_info["valid"] = False
            self._generate_event(
                site_key,
                "critical",
                "SSL Certificate Invalid",
                f"SSL verification failed for {site['name']}: {e}",
            )
        except Exception as e:
            ssl_info["error"] = str(e)
            ssl_info["valid"] = False

        return ssl_info

    def _check_dns(self, site_key):
        site = WEBSITES[site_key]
        parsed = urlparse(site["url"])
        hostname = parsed.hostname

        dns_result = {"resolved": False, "ip_addresses": [], "resolution_time_ms": 0}

        try:
            start = time.time()
            ips = socket.getaddrinfo(hostname, None)
            elapsed = (time.time() - start) * 1000
            unique_ips = list(set(addr[4][0] for addr in ips))
            dns_result["resolved"] = True
            dns_result["ip_addresses"] = unique_ips
            dns_result["resolution_time_ms"] = round(elapsed)
        except socket.gaierror as e:
            dns_result["error"] = str(e)
            self._generate_event(
                site_key,
                "critical",
                "DNS Resolution Failed",
                f"Cannot resolve {hostname}: {e}",
            )

        return dns_result

    def _analyze_security(self, site_key, result):
        site = WEBSITES[site_key]
        sec = result["security_headers"]

        critical_missing = []
        for header_name, info in sec.items():
            if not info["present"]:
                critical_missing.append(header_name)

        if not sec.get("Strict-Transport-Security", {}).get("present"):
            self._generate_event(
                site_key,
                "high",
                "Missing HSTS Header",
                f"{site['name']} does not enforce HSTS — vulnerable to downgrade attacks",
            )

        if not sec.get("Content-Security-Policy", {}).get("present"):
            self._generate_event(
                site_key,
                "high",
                "Missing Content-Security-Policy",
                f"{site['name']} lacks CSP header — increased XSS risk",
            )

        if not sec.get("X-Frame-Options", {}).get("present"):
            self._generate_event(
                site_key,
                "medium",
                "Missing X-Frame-Options",
                f"{site['name']} vulnerable to clickjacking attacks",
            )

        if not sec.get("X-Content-Type-Options", {}).get("present"):
            self._generate_event(
                site_key,
                "medium",
                "Missing X-Content-Type-Options",
                f"{site['name']} vulnerable to MIME sniffing attacks",
            )

        if result["security_score"] < 30:
            self._generate_event(
                site_key,
                "critical",
                "Very Low Security Score",
                f"{site['name']} security header score: {result['security_score']}% — critical risk",
            )
        elif result["security_score"] < 60:
            self._generate_event(
                site_key,
                "warning",
                "Low Security Score",
                f"{site['name']} security header score: {result['security_score']}% — needs improvement",
            )

        if result["redirect_chain"]:
            for redir in result["redirect_chain"]:
                if redir["url"].startswith("http://"):
                    self._generate_event(
                        site_key,
                        "warning",
                        "HTTP Redirect Detected",
                        f"{site['name']} redirects through insecure HTTP: {redir['url']}",
                    )

        if result["status_code"] >= 500:
            self._generate_event(
                site_key,
                "critical",
                "Server Error Detected",
                f"{site['name']} returned HTTP {result['status_code']}",
            )
        elif result["status_code"] >= 400:
            self._generate_event(
                site_key,
                "warning",
                "Client Error Response",
                f"{site['name']} returned HTTP {result['status_code']}",
            )

        if result["response_time_ms"] > 5000:
            self._generate_event(
                site_key,
                "warning",
                "Very Slow Response",
                f"{site['name']} response time: {result['response_time_ms']}ms — possible issue",
            )

    def _generate_event(self, site_key, severity, title, description):
        event = {
            "id": f"EVT-{int(time.time() * 1000) % 1000000}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "site_key": site_key,
            "site_name": WEBSITES[site_key]["name"],
            "severity": severity,
            "title": title,
            "description": description,
        }
        with self._lock:
            self.security_events.appendleft(event)
        return event

    def _add_log(self, level, source, message):
        log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "source": source,
            "message": message,
        }
        with self._lock:
            self.scan_logs.appendleft(log)

    def get_latest(self):
        with self._lock:
            return dict(self.latest)

    def get_history(self, site_key, limit=100):
        with self._lock:
            data = list(self.history.get(site_key, []))
            return data[-limit:]

    def get_all_history(self, limit=100):
        with self._lock:
            return {k: list(v)[-limit:] for k, v in self.history.items()}

    def get_events(self, limit=50, site_filter=None):
        with self._lock:
            events = list(self.security_events)
        if site_filter and site_filter != "all":
            events = [e for e in events if e["site_key"] == site_filter]
        return events[:limit]

    def get_logs(self, limit=100):
        with self._lock:
            return list(self.scan_logs)[:limit]

    def get_dashboard_summary(self):
        latest = self.get_latest()
        events = self.get_events(200)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "warning": 0, "low": 0, "info": 0}
        for ev in events:
            sev = ev["severity"]
            if sev in severity_counts:
                severity_counts[sev] += 1

        total_events = len(events)

        if severity_counts["critical"] > 5:
            threat_level = "CRITICAL"
        elif severity_counts["critical"] > 2 or severity_counts["high"] > 5:
            threat_level = "HIGH"
        elif severity_counts["high"] > 2 or severity_counts["warning"] > 5:
            threat_level = "ELEVATED"
        else:
            threat_level = "LOW"

        return {
            "websites": latest,
            "total_events": total_events,
            "severity_counts": severity_counts,
            "threat_level": threat_level,
            "monitored_assets": len(WEBSITES),
            "events_recent": self.get_events(20),
        }

    def scan_all(self):
        results = {}
        for key in WEBSITES:
            results[key] = self.scan_website(key)
        return results
