"""Fixed, read-only probes. No Docker socket, config, secrets, or shell access."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from site_policy import SITES
import http.client
import json
import re
import socket
import ssl
import subprocess
import time


@dataclass(frozen=True)
class Service:
    key: str
    name: str
    metadata: str
    icon: str
    unit: str = ""
    port: int = 0
    path: str = ""


SERVICES = (
    Service("manager", "Wazuh Manager", "Port 55000", "security-high-symbolic", "wazuh-manager"),
    Service("indexer", "Wazuh Indexer", "Port 9200", "drive-harddisk-symbolic", "wazuh-indexer"),
    Service("dashboard", "Wazuh Dashboard", "Port 443", "view-grid-symbolic", "wazuh-dashboard"),
    Service("misp", "MISP", "Port 9445", "network-workgroup-symbolic", port=9445, path="/users/heartbeat"),
    Service("cortex", "Cortex", "Port 9444", "applications-science-symbolic", port=9444, path="/api/status"),
    Service("docker", "Docker Engine", "Container service", "application-x-addon-symbolic", "docker"),
)
STATES = ("running", "partial", "stopped", "starting", "unhealthy", "unknown")
OVERVIEW_SERVICES = (
    Service("wazuh", "Wazuh", "Manager · Indexer · Dashboard", "security-high-symbolic"),
    *SERVICES[3:],
)
TIMEOUT = 2.0


@dataclass(frozen=True)
class Result:
    key: str
    state: str
    detail: str
    uptime: float | None = None
    display_status: str = ""


def summarize(results):
    """Collapse Wazuh without hiding failed or unverified components."""
    by_key = {item.key: item for item in results}
    components = tuple(by_key.get(s.key, Result(s.key, "unknown", "No result")) for s in SERVICES[:3])
    count = sum(item.state == "running" for item in components)
    states = {item.state for item in components}
    uptime = None
    if count == 3:
        state, title = "running", "Running — 3/3"
        if all(item.uptime is not None for item in components):
            uptime = min(item.uptime for item in components)
    elif "unknown" in states:
        state, title = "unknown", f"Unverified — {count}/3 running"
    elif count:
        state, title = "partial", f"Partially running — {count}/3"
    elif states == {"stopped"}:
        state, title = "stopped", "Stopped — 0/3"
    elif "unhealthy" in states:
        state, title = "unhealthy", "Unhealthy — 0/3 running"
    elif "starting" in states:
        state, title = "starting", "Starting — 0/3 running"
    else:
        state, title = "unknown", "Unverified — 0/3 running"
    detail = "\n".join(f"{name}: {item.state.capitalize()}" for name, item in zip(("Manager", "Indexer", "Dashboard"), components))
    wazuh = Result("wazuh", state, detail, uptime, title)
    return (wazuh, *(by_key.get(s.key, Result(s.key, "unknown", "No result")) for s in OVERVIEW_SERVICES[1:]))


def _command(args):
    try:
        return subprocess.run(
            args, shell=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=TIMEOUT, check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                 "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"},
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def _systemd(service):
    reply = _command(["/usr/bin/systemctl", "is-active", service.unit])
    if reply is None:
        return Result(service.key, "unknown", "System status check unavailable")
    raw = reply.stdout.strip()
    mapping = {
        "active": ("running", "Service active"),
        "reloading": ("running", "Service reloading"),
        "activating": ("starting", "Service starting"),
        "inactive": ("stopped", "Service inactive"),
        "failed": ("unhealthy", "Service failed"),
        "deactivating": ("unknown", "Service stopping"),
    }
    if raw not in mapping or reply.returncode not in (0, 3):
        return Result(service.key, "unknown", "Service missing or status unavailable")
    state, detail = mapping[raw]
    # LoadState avoids misclassifying an absent unit as an inactive service.
    props = _command([
        "/usr/bin/systemctl", "show", service.unit, "--no-pager",
        "--property=LoadState,ActiveState,ActiveEnterTimestampMonotonic",
    ])
    uptime = None
    if props is not None and props.returncode == 0:
        values = dict(line.split("=", 1) for line in props.stdout.splitlines() if "=" in line)
        if values.get("LoadState") == "not-found":
            return Result(service.key, "unknown", "Service is not installed")
        # Hide uptime if the state changed between the two commands.
        if state == "running" and values.get("ActiveState") in ("active", "reloading"):
            try:
                activated = int(values.get("ActiveEnterTimestampMonotonic", "0")) / 1_000_000
                elapsed = time.monotonic() - activated
                if activated > 0 and elapsed >= 0:
                    uptime = elapsed
            except ValueError:
                pass
    return Result(service.key, state, detail, uptime)


def _http_result(service, status, content_type, body):
    if status >= 500:
        return Result(service.key, "unhealthy", f"Local endpoint returned HTTP {status}")
    if status in (401, 403):
        return Result(service.key, "unknown", f"{service.path}: HTTP {status}; authentication required")
    if 300 <= status < 400:
        return Result(service.key, "unknown", f"{service.path}: HTTP {status}; redirected")
    if status != 200:
        return Result(service.key, "unknown", f"Health unconfirmed (HTTP {status})")
    if len(body) > 16384:
        return Result(service.key, "unknown", "Unexpected health response")
    if service.key == "misp":
        # The configured heartbeat may have an empty response. Reject login and
        # proxy HTML pages: a 200 login page is not a successful heartbeat.
        if "html" in content_type.lower() or body.lstrip().startswith(b"<"):
            return Result(service.key, "unknown", "HTML response; heartbeat unconfirmed")
        if body.strip() and body.strip().lower() != b"ok":
            try:
                payload = json.loads(body)
            except (ValueError, UnicodeError):
                return Result(service.key, "unknown", "Unrecognized heartbeat response")
            if not isinstance(payload, dict) or payload.get("status") not in ("ok", "OK", "healthy"):
                return Result(service.key, "unknown", "Unrecognized heartbeat response")
        return Result(service.key, "running", "Heartbeat responded; availability only")
    try:
        payload = json.loads(body)
        versions = payload.get("versions", {}) if isinstance(payload, dict) else {}
        identified = isinstance(versions, dict) and any(str(k).lower() == "cortex" for k in versions)
    except (ValueError, UnicodeError):
        identified = False
    if not identified:
        return Result(service.key, "unknown", "Cortex status response unconfirmed")
    return Result(service.key, "running", "Cortex responded; availability only")


def _request(service, path, limit):
    # Only literal loopback, fixed ports and paths. No proxy, redirects,
    # credentials, cookies, DNS, environment configuration, or response logging.
    # Local installations may use self-signed certificates: skip verification
    # only here, never for remote URLs. This is availability, not TLS validation.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    connection = http.client.HTTPSConnection("127.0.0.1", service.port, timeout=TIMEOUT, context=context)
    try:
        headers = {
            "Accept": "application/json", "Connection": "close",
            "User-Agent": "AthenaSec-Service-Panel/3.0",
        }
        if service.key == "misp":
            # Address the configured virtual host while connecting only locally.
            headers["Host"] = urlsplit(SITES["misp"][1]).netloc
            if path == "/users/login":
                headers["Accept"] = "text/html"
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        # read1 performs at most one buffered read per call. Keep an overall
        # body deadline as well as socket timeouts to bound slow responses.
        body = bytearray()
        deadline = time.monotonic() + TIMEOUT
        while len(body) <= limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            chunk = response.read1(min(4096, limit + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        return response.status, response.getheader("Content-Type", ""), bytes(body)
    except ConnectionRefusedError:
        return Result(service.key, "unknown", f"127.0.0.1:{service.port}: connection refused")
    except (TimeoutError, socket.timeout):
        return Result(service.key, "unknown", f"{path}: local HTTPS request timed out")
    except (OSError, http.client.HTTPException, ValueError):
        return Result(service.key, "unknown", f"{path}: local HTTPS connection failed")
    finally:
        connection.close()


class _MispLoginParser(HTMLParser):
    """Require MISP's named login form and its email/password controls."""
    def __init__(self):
        super().__init__()
        self.in_login = False
        self.fields = set()
        self.identified = False
        self.misp_brand = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "img" and re.search(r"\bmisp\b", attrs.get("alt", ""), re.I):
            self.misp_brand = True
        if tag == "form":
            self.in_login = attrs.get("id") == "UserLoginForm"
            self.fields = set()
        elif self.in_login and tag == "input":
            identity = attrs.get("id", "")
            kind = attrs.get("type", "text").lower()
            if identity == "UserEmail" and kind in ("text", "email"):
                self.fields.add("email")
            if identity == "UserPassword" and kind == "password":
                self.fields.add("password")

    def handle_endtag(self, tag):
        if tag == "form" and self.in_login:
            self.identified = self.identified or self.fields == {"email", "password"}
            self.in_login = False

    def handle_data(self, data):
        if re.search(r"\bmisp\b", data, re.I):
            self.misp_brand = True


def _misp_login_result(response):
    if isinstance(response, Result):
        return response
    status, content_type, body = response
    if status >= 500:
        return Result("misp", "unhealthy", f"/users/login: HTTP {status}")
    if status != 200:
        return Result("misp", "unknown", f"/users/login: HTTP {status}; page unconfirmed")
    if len(body) > 131072:
        return Result("misp", "unknown", "/users/login: response exceeds 128 KiB")
    parser = _MispLoginParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, RecursionError):
        pass
    if parser.identified and parser.misp_brand:
        return Result("misp", "running", "MISP login page responded; web availability only", display_status="Available")
    return Result("misp", "unknown", "/users/login: HTTP 200; MISP login form not identified")


def _https(service):
    response = _request(service, service.path, 16384)
    if isinstance(response, Result):
        return response
    result = _http_result(service, *response)
    if service.key != "misp" or result.state != "unknown":
        return result
    # Do not hide an explicit negative health response behind an available UI.
    try:
        payload = json.loads(response[2])
    except (ValueError, UnicodeError):
        payload = None
    if payload is False or (isinstance(payload, dict) and (payload.get("status") in ("failed", "error", "unhealthy") or payload.get("success") is False)):
        return Result("misp", "unhealthy", "Heartbeat explicitly reports failure")
    login = _misp_login_result(_request(service, "/users/login", 131072))
    return Result("misp", login.state, f"{result.detail}.\n{login.detail}", display_status=login.display_status)


def check(service):
    if service not in SERVICES:
        raise ValueError("Service is not allowlisted")
    try:
        return _systemd(service) if service.unit else _https(service)
    except Exception:
        # Never expose command errors, response bodies, or traceback data in UI.
        return Result(service.key, "unknown", "Status check unavailable")


def collect():
    with ThreadPoolExecutor(max_workers=6) as workers:
        return tuple(workers.map(check, SERVICES))


def format_uptime(seconds):
    minutes = int(seconds) // 60
    days, minutes = divmod(minutes, 1440)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"
