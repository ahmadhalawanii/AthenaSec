#!/usr/bin/python3
"""Native GTK4 service monitor; run as the logged-in desktop user."""
from datetime import datetime
from pathlib import Path
import threading
import sys

import gi
gi.require_version("Gtk", "4.0")
gi.require_version("Gdk", "4.0")
from gi.repository import Gdk, Gio, GLib, Gtk, Pango

from services import SERVICES, OVERVIEW_SERVICES, STATES, Result, collect, summarize, format_uptime
from site_policy import SITES
from auth import ADMIN_EMAIL, authenticate
from metrics import Sampler, Usage

ROOT = Path(__file__).resolve().parent


def label(text, css=None):
    widget = Gtk.Label(label=text, xalign=0)
    if css:
        widget.add_css_class(css)
    return widget


class LoginWindow(Gtk.ApplicationWindow):
    """Startup screen; only a successful local mock check creates the panel."""
    def __init__(self, app):
        super().__init__(application=app, title="AthenaSec — Sign in")
        self.add_css_class("panel")
        self.set_default_size(560, 580)
        self.set_size_request(440, 480)
        header = Gtk.HeaderBar()
        header.set_title_widget(label("ATHENASEC", "brand"))
        self.set_titlebar(header)
        form = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        form.add_css_class("login-card")
        form.set_halign(Gtk.Align.CENTER)
        form.set_valign(Gtk.Align.CENTER)
        form.set_size_request(340, -1)
        form.append(label("Admin sign in", "title"))
        form.append(label("Sign in to open the Service Panel", "subtitle"))
        form.append(label("Email", "metadata"))
        self.email = Gtk.Entry()
        self.email.set_placeholder_text("Admin email")
        self.email.set_input_purpose(Gtk.InputPurpose.EMAIL)
        self.email.set_max_length(254)
        self.email.connect("activate", lambda *_: self.password.grab_focus())
        form.append(self.email)
        form.append(label("Password", "metadata"))
        self.password = Gtk.PasswordEntry()
        self.password.set_show_peek_icon(True)
        self.password.connect("activate", self.submit)
        form.append(self.password)
        self.error = label("", "login-error")
        self.error.set_wrap(True)
        self.error.set_visible(False)
        form.append(self.error)
        button = Gtk.Button(label="Sign in")
        button.add_css_class("refresh")
        button.connect("clicked", self.submit)
        form.append(button)
        form.append(label("Demo admin account · Local mock sign-in", "muted"))
        self.set_child(form)

    def submit(self, *_):
        valid = authenticate(self.email.get_text(), self.password.get_text())
        self.password.set_text("")
        if not valid:
            self.error.set_text("Email or password is incorrect.")
            self.error.set_visible(True)
            self.password.grab_focus()
            return
        self.get_application().open_panel(self)


class ResourceUsage(Gtk.Box):
    """Compact machine-wide usage, visible alongside every service page."""
    def __init__(self):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.add_css_class("resource-usage")
        self.append(label("THIS DEVICE", "sidebar-heading"))
        self.cpu = label("CPU —", "metadata")
        self.cpu_bar = Gtk.ProgressBar()
        self.ram = label("RAM —", "metadata")
        self.ram_bar = Gtk.ProgressBar()
        self.memory_detail = label("Sampling…", "muted")
        for widget in (self.cpu, self.cpu_bar, self.ram, self.ram_bar, self.memory_detail):
            self.append(widget)
        self.set_tooltip_text("Machine running this panel. In VirtualBox this is the Ubuntu guest, not the physical host. Samples every 2 seconds.")

    def update(self, usage):
        self.cpu.set_text(f"CPU {usage.cpu_percent:.1f}%" if usage.cpu_percent is not None else "CPU — " + usage.cpu_detail)
        self.ram.set_text(f"RAM {usage.memory_percent:.1f}%" if usage.memory_percent is not None else "RAM — Unavailable")
        for bar, value in ((self.cpu_bar, usage.cpu_percent), (self.ram_bar, usage.memory_percent)):
            bar.set_fraction(value / 100 if value is not None else 0)
            bar.set_sensitive(value is not None)
        self.memory_detail.set_text(usage.memory_detail)


class Card(Gtk.Box):
    def __init__(self, service):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.add_css_class("service-card")
        self.key = service.key
        self.set_hexpand(True)
        self.set_size_request(260, 230)
        icon = Gtk.Image.new_from_icon_name(service.icon)
        icon.set_pixel_size(28)
        icon.set_halign(Gtk.Align.START)
        icon.add_css_class("service-icon")
        self.append(icon)
        self.append(label(service.name, "service-name"))
        self.status = label("●  Unknown", "status")
        self.append(self.status)
        self.detail = label("Waiting for first check", "muted")
        self.detail.set_wrap(True)
        self.detail.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        self.detail.set_max_width_chars(30)
        self.detail.set_vexpand(True)
        self.detail.set_valign(Gtk.Align.START)
        self.append(self.detail)
        self.uptime = label("", "muted")
        self.uptime.set_visible(False)
        self.append(self.uptime)
        self.append(Gtk.Separator())
        self.append(label(service.metadata, "metadata"))

    def update(self, result):
        for state in STATES:
            self.status.remove_css_class(state)
        self.status.add_css_class(result.state)
        self.status.set_text("●  " + (result.display_status or result.state.capitalize()))
        self.detail.set_text(result.detail)
        self.uptime.set_visible(result.uptime is not None)
        if result.uptime is not None:
            prefix = "All active for: " if self.key == "wazuh" else "Uptime: "
            self.uptime.set_text(prefix + format_uptime(result.uptime))


class Panel(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="AthenaSec Service Panel")
        self.set_default_size(1280, 850)
        self.set_size_request(1100, 650)
        self.add_css_class("panel")
        self.busy = False
        self.closed = False
        self.last_check = None
        self.connect("close-request", self.close_panel)
        header = Gtk.HeaderBar()
        header.set_title_widget(label("ATHENASEC", "brand"))
        self.set_titlebar(header)
        shell = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.set_child(shell)
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        sidebar.add_css_class("sidebar")
        sidebar.set_size_request(205, -1)
        sidebar.append(label("WORKSPACE", "sidebar-heading"))
        self.nav = {}
        self.pages = {}
        self.page_stack = Gtk.Stack()
        self.page_stack.set_hexpand(True)
        self.page_stack.set_vexpand(True)
        self.page_stack.set_hhomogeneous(False)
        self.page_stack.set_vhomogeneous(False)
        for key, title in (("overview", "Overview"), ("wazuh", "Wazuh"), ("cortex", "Cortex"), ("misp", "MISP")):
            button = Gtk.Button(label=title)
            button.add_css_class("nav-button")
            button.connect("clicked", lambda _button, selected=key: self.navigate(selected))
            sidebar.append(button)
            self.nav[key] = button
        spacer = Gtk.Box()
        spacer.set_vexpand(True)
        sidebar.append(spacer)
        self.usage = ResourceUsage()
        sidebar.append(self.usage)
        sidebar.append(Gtk.Separator())
        account = label(ADMIN_EMAIL, "muted")
        account.set_ellipsize(Pango.EllipsizeMode.END)
        account.set_max_width_chars(23)
        account.set_tooltip_text(ADMIN_EMAIL)
        sidebar.append(account)
        logout = Gtk.Button(label="Sign out")
        logout.add_css_class("nav-button")
        logout.connect("clicked", lambda *_: self.get_application().sign_out(self))
        sidebar.append(logout)
        sidebar.append(label("Service Panel · v3", "muted"))
        shell.append(sidebar)
        shell.append(self.page_stack)
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.page_stack.add_named(scroll, "overview")
        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=22)
        for edge in ("top", "bottom", "start", "end"):
            getattr(content, "set_margin_" + edge)(28)
        scroll.set_child(content)
        heading = Gtk.Box(spacing=20)
        titles = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        titles.set_hexpand(True)
        titles.append(label("Service Panel", "title"))
        titles.append(label("Running services overview", "subtitle"))
        heading.append(titles)
        self.refresh_button = Gtk.Button(label="Refresh", valign=Gtk.Align.CENTER)
        self.refresh_button.add_css_class("refresh")
        self.refresh_button.connect("clicked", lambda *_: self.refresh())
        heading.append(self.refresh_button)
        content.append(heading)
        summary = Gtk.Box(spacing=16, homogeneous=True)
        self.counts = []
        for title, initial in (("Total Services", "4"), ("Running", "—"), ("Issues", "—")):
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            box.add_css_class("summary")
            box.append(label(title, "muted"))
            value = label(initial, "count")
            box.append(value)
            self.counts.append(value)
            summary.append(box)
        summary.set_tooltip_text("Four logical services. Issues includes partially running, stopped, starting, unhealthy, and unknown.")
        content.append(summary)
        grid = Gtk.Grid(column_spacing=16, row_spacing=16, column_homogeneous=True, row_homogeneous=True)
        self.cards = {}
        for index, service in enumerate(OVERVIEW_SERVICES):
            card = Card(service)
            self.cards[service.key] = card
            grid.attach(card, index % 3, index // 3, 1, 1)
        content.append(grid)
        self.updated = label("Checking services…", "muted")
        content.append(self.updated)
        note = label("Six checks · Four service groups · MISP and Cortex show endpoint availability", "muted")
        note.set_wrap(True)
        content.append(note)
        self.navigate("overview")
        self.timer = GLib.timeout_add_seconds(5, self.tick)
        self.metrics_busy = False
        self.sampler = Sampler()
        self.metrics_timer = GLib.timeout_add_seconds(2, self.refresh_metrics)
        self.refresh_metrics()
        self.refresh()

    def navigate(self, key):
        if key != "overview" and key not in SITES:
            return
        if key != "overview" and key not in self.pages:
            try:
                from browser import ServicePage
                page = ServicePage(key)
            except (ImportError, ValueError):
                page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
                page.set_halign(Gtk.Align.CENTER)
                page.set_valign(Gtk.Align.CENTER)
                page.append(label("WebKitGTK is required", "service-name"))
                page.append(label("Install gir1.2-webkit-6.0, then close and reopen the panel.", "muted"))
            self.pages[key] = page
            self.page_stack.add_named(page, key)
        self.page_stack.set_visible_child_name(key)
        for name, button in self.nav.items():
            if name == key:
                button.add_css_class("selected")
            else:
                button.remove_css_class("selected")

    def tick(self):
        if self.closed:
            return GLib.SOURCE_REMOVE
        self.refresh()
        return GLib.SOURCE_CONTINUE

    def refresh(self):
        if self.busy or self.closed:
            return
        self.busy = True
        self.refresh_button.set_sensitive(False)
        self.refresh_button.set_label("Checking…")
        self.updated.set_text("Checking services…" + (f" Last results: {self.last_check}" if self.last_check else ""))
        threading.Thread(target=self.work, daemon=True, name="status-refresh").start()

    def work(self):
        try:
            results = collect()
        except Exception:
            results = tuple(Result(s.key, "unknown", "Status check unavailable") for s in SERVICES)
        GLib.idle_add(self.apply_results, results)

    def apply_results(self, results):
        if self.closed:
            return GLib.SOURCE_REMOVE
        results = summarize(results)
        for result in results:
            self.cards[result.key].update(result)
        running = sum(r.state == "running" for r in results)
        self.counts[1].set_text(str(running))
        self.counts[2].set_text(str(len(OVERVIEW_SERVICES) - running))
        self.last_check = datetime.now().strftime("%H:%M:%S")
        self.updated.set_text(f"Last checked {self.last_check} · Refreshes every 5 seconds")
        self.refresh_button.set_sensitive(True)
        self.refresh_button.set_label("Refresh")
        self.busy = False
        return GLib.SOURCE_REMOVE

    def refresh_metrics(self):
        if self.closed:
            return GLib.SOURCE_REMOVE
        if not self.metrics_busy:
            self.metrics_busy = True
            threading.Thread(target=self.work_metrics, daemon=True, name="usage-refresh").start()
        return GLib.SOURCE_CONTINUE

    def work_metrics(self):
        try:
            usage = self.sampler.sample()
        except Exception:
            usage = Usage(cpu_detail="Unavailable")
        GLib.idle_add(self.apply_usage, usage)

    def apply_usage(self, usage):
        if not self.closed:
            self.usage.update(usage)
            self.metrics_busy = False
        return GLib.SOURCE_REMOVE

    def close_panel(self, *_):
        if self.closed:
            return False
        self.closed = True
        GLib.source_remove(self.timer)
        GLib.source_remove(self.metrics_timer)
        for page in self.pages.values():
            if hasattr(page, "close_page"):
                page.close_page()
            self.page_stack.remove(page)
        self.pages.clear()
        return False


class Application(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.athenasec.ServicePanel", flags=Gio.ApplicationFlags.DEFAULT_FLAGS)

    def do_activate(self):
        window = self.get_active_window()
        if window is None:
            provider = Gtk.CssProvider()
            provider.load_from_path(str(ROOT / "ui" / "style.css"))
            Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            window = LoginWindow(self)
        window.present()

    def open_panel(self, login):
        window = Panel(self)
        window.present()
        login.destroy()

    def sign_out(self, panel):
        panel.close_panel()
        login = LoginWindow(self)
        login.present()
        panel.destroy()


if __name__ == "__main__":
    raise SystemExit(Application().run(sys.argv))
