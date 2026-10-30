"""Embedded service pages with independent, session-only WebKit storage."""
import hashlib
import ssl
from urllib.parse import urlsplit

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("WebKit", "6.0")
from gi.repository import Gtk, WebKit

from site_policy import SITES, allowed_uri


class ServicePage(Gtk.Box):
    def __init__(self, key):
        if key not in SITES:
            raise ValueError("Service is not allowlisted")
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.handlers = []
        self.key = key
        self.name, self.home = SITES[key]
        self.pending_certificate = None
        self.had_failure = False
        self.closed = False
        self.certificate_exception = False
        # Separate sessions avoid cookies crossing services on the same IP.
        self.session = WebKit.NetworkSession.new_ephemeral()
        self.session.set_persistent_credential_storage_enabled(False)
        self.session.set_proxy_settings(WebKit.NetworkProxyMode.NO_PROXY, None)
        self.handlers.append((self.session, self.session.connect("download-started", self.download_started)))
        self.view = WebKit.WebView(network_session=self.session)
        self.view.set_hexpand(True)
        self.view.set_vexpand(True)
        settings = self.view.get_settings()
        settings.set_hardware_acceleration_policy(WebKit.HardwareAccelerationPolicy.NEVER)
        settings.set_enable_developer_extras(False)
        settings.set_javascript_can_open_windows_automatically(False)
        self.handlers.append((self.view, self.view.connect("decide-policy", self.decide_policy)))
        self.handlers.append((self.view, self.view.connect("create", self.create_window)))
        self.handlers.append((self.view, self.view.connect("permission-request", self.permission_requested)))
        self.handlers.append((self.view, self.view.connect("load-failed-with-tls-errors", self.tls_failed)))
        self.handlers.append((self.view, self.view.connect("load-failed", self.load_failed)))
        self.handlers.append((self.view, self.view.connect("load-changed", self.load_changed)))
        self.handlers.append((self.view, self.view.connect("web-process-terminated", self.process_terminated)))
        self.handlers.append((self.view, self.view.connect("notify::estimated-load-progress", self.progress_changed)))

        toolbar = Gtk.Box(spacing=8)
        toolbar.add_css_class("web-toolbar")
        self.back = Gtk.Button(label="Back")
        self.back.set_sensitive(False)
        self.back.connect("clicked", lambda *_: self.view.go_back())
        toolbar.append(self.back)
        for title, callback in (("Reload", self.reload), ("Home", self.go_home)):
            button = Gtk.Button(label=title)
            button.connect("clicked", callback)
            toolbar.append(button)
        # Show only the fixed origin, never tokens in paths or query strings.
        origin = Gtk.Label(label=self.home, xalign=0)
        origin.set_hexpand(True)
        origin.add_css_class("muted")
        toolbar.append(origin)
        self.append(toolbar)
        self.progress = Gtk.ProgressBar()
        self.append(self.progress)
        self.notice = Gtk.Label(label="", xalign=0, wrap=True)
        self.notice.add_css_class("web-notice")
        self.notice.set_visible(False)
        self.append(self.notice)
        self.stack = Gtk.Stack()
        self.stack.set_vexpand(True)
        self.stack.add_named(self.view, "page")
        error_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=18)
        error_box.set_halign(Gtk.Align.CENTER)
        error_box.set_valign(Gtk.Align.CENTER)
        for edge in ("top", "bottom", "start", "end"):
            getattr(error_box, "set_margin_" + edge)(28)
        self.error_title = Gtk.Label(label="Unable to load service", xalign=0)
        self.error_title.add_css_class("service-name")
        error_box.append(self.error_title)
        self.error_detail = Gtk.Label(xalign=0, wrap=True, max_width_chars=70, selectable=True)
        self.error_detail.add_css_class("muted")
        error_box.append(self.error_detail)
        self.trust = Gtk.Button(label="Trust this certificate for this session")
        self.trust.add_css_class("refresh")
        self.trust.connect("clicked", self.trust_certificate)
        self.trust.set_visible(False)
        error_box.append(self.trust)
        retry = Gtk.Button(label="Retry service home")
        retry.connect("clicked", self.go_home)
        error_box.append(retry)
        self.stack.add_named(error_box, "error")
        self.append(self.stack)
        self.go_home()

    def show_notice(self, message):
        self.notice.set_text(message)
        self.notice.set_visible(True)

    def show_error(self, title, message, certificate=False):
        if self.closed:
            return
        self.had_failure = True
        self.error_title.set_text(title)
        self.error_detail.set_text(message)
        self.trust.set_visible(certificate)
        self.stack.set_visible_child_name("error")

    def decide_policy(self, _view, decision, kind):
        if kind in (WebKit.PolicyDecisionType.NAVIGATION_ACTION, WebKit.PolicyDecisionType.NEW_WINDOW_ACTION):
            request = decision.get_navigation_action().get_request()
            uri = request.get_uri()
            if not allowed_uri(self.key, uri):
                decision.ignore()
                self.show_notice("This link is outside the selected service and was not opened.")
                return True
            if kind == WebKit.PolicyDecisionType.NEW_WINDOW_ACTION:
                # Do not turn a popup POST into a GET or open an external browser.
                decision.ignore()
                if request.get_http_method() == "GET":
                    self.view.load_uri(uri)
                else:
                    self.show_notice("This popup action cannot be opened here.")
                return True
            decision.use()
            return True
        if kind == WebKit.PolicyDecisionType.RESPONSE:
            if not decision.is_mime_type_supported():
                decision.ignore()
                self.show_notice("File downloads are not enabled in this version.")
                return True
        return False

    def create_window(self, *_):
        self.show_notice("Additional windows are not enabled in this panel.")
        return None

    def download_started(self, _session, download):
        download.cancel()
        self.show_notice("File downloads are not enabled in this version.")

    def permission_requested(self, _view, request):
        request.deny()
        self.show_notice("Device and location permissions are not enabled in this panel.")
        return True

    def tls_failed(self, _view, uri, certificate, _errors):
        if not allowed_uri(self.key, uri):
            self.show_error("Certificate error", "The destination is outside this service.")
            return True
        self.pending_certificate = (uri, certificate)
        try:
            pem = certificate.get_property("certificate-pem")
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
            fingerprint = ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))
        except (TypeError, ValueError, AttributeError):
            fingerprint = "Unavailable"
        self.show_error(
            "Verify this service's certificate",
            f"The certificate for {self.home} could not be verified. If this is your service's expected certificate, you can trust it for this session.\n\nSHA-256 fingerprint:\n{fingerprint}",
            certificate=True,
        )
        return True

    def trust_certificate(self, *_):
        if self.pending_certificate is None or self.closed:
            return
        uri, certificate = self.pending_certificate
        if not allowed_uri(self.key, uri):
            return
        self.session.allow_tls_certificate_for_host(certificate, urlsplit(uri).hostname)
        self.certificate_exception = True
        self.pending_certificate = None
        self.view.load_uri(uri)

    def load_failed(self, _view, _event, _uri, _error):
        if self.closed or self.pending_certificate is not None:
            return True
        # User cancellation (reload, home or back) is not a connection failure.
        if _error.matches(WebKit.network_error_quark(), WebKit.NetworkError.CANCELLED):
            return True
        self.show_error("Unable to load " + self.name, f"Check that {self.home} is reachable from this Ubuntu machine, then retry. The Overview page remains available.")
        return True

    def load_changed(self, _view, event):
        if self.closed:
            return
        if event == WebKit.LoadEvent.STARTED:
            self.pending_certificate = None
            self.had_failure = False
            self.stack.set_visible_child_name("page")
            self.notice.set_visible(False)
            if self.certificate_exception:
                self.show_notice("A certificate exception is active for this service during this session.")
        self.progress.set_visible(event != WebKit.LoadEvent.FINISHED)
        self.back.set_sensitive(self.view.can_go_back())

    def progress_changed(self, *_):
        if not self.closed:
            self.progress.set_fraction(self.view.get_estimated_load_progress())

    def process_terminated(self, *_):
        self.show_error("Service page stopped", "The embedded page process exited. Use Retry service home to load it again.")

    def reload(self, *_):
        if self.had_failure:
            self.go_home()
        else:
            self.view.reload()

    def go_home(self, *_):
        self.pending_certificate = None
        self.view.load_uri(self.home)

    def close_page(self):
        if self.closed:
            return
        self.closed = True
        self.pending_certificate = None
        self.view.stop_loading()
        for owner, handler in self.handlers:
            owner.disconnect(handler)
        self.handlers.clear()
        self.stack.remove(self.view)
        self.view = None
        self.session = None
