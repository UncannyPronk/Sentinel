import sys
import requests
import re
from PyQt5.QtGui import QFont, QKeySequence
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin

AD_KEYWORDS = [
    "ads", "ad_", "ad-", "advert", "sponsor", "banner", "promoted",
    "affiliate", "doubleclick", "googlesyndication", "tracking",
    "popunder", "clickserve", "outbrain", "taboola", "metrics"
]

def remove_ads_from_html(html):
    # Remove known ad-serving iframes and images
    html = re.sub(
        r'<iframe[^>]+(ad|banner|sponsor|doubleclick|googlesyndication)[^>]*>.*?</iframe>',
        '', html, flags=re.DOTALL | re.IGNORECASE
    )
    html = re.sub(
        r'<img[^>]+(ad|promo|sponsor|banner)[^>]*>',
        '', html, flags=re.IGNORECASE
    )

    # Remove divs with ad-related classes or IDs
    html = re.sub(
        r'<div[^>]+(id|class)\s*=\s*["\'].*?(%s).*?["\'][^>]*>.*?</div>' % "|".join(AD_KEYWORDS),
        '', html, flags=re.DOTALL | re.IGNORECASE
    )

    # Remove scripts that reference ad networks
    html = re.sub(
        r'<script[^>]+(ad|doubleclick|googlesyndication|tracking)[^>]*>.*?</script>',
        '', html, flags=re.DOTALL | re.IGNORECASE
    )

    return html

def _get_base_domain(host: str) -> str:
    """Return a simple registrable base domain: last two labels (best-effort)."""
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host.lower()
    return ".".join(parts[-2:]).lower()

def _is_ascii_hostname(host: str) -> bool:
    """Return False for punycode or any non-ascii host (simple homograph defense)."""
    if not host:
        return False
    # punycode starts with 'xn--'
    try:
        return host.isascii() and not host.lower().startswith("xn--")
    except Exception:
        return False

def is_ascii_url(url: str) -> bool:
    """Return True if the entire URL (including query) is plain ASCII — no punycode, emojis, or homoglyphs."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Reject punycode or non-ascii hostnames
        if not host.isascii() or host.lower().startswith("xn--"):
            return False
        # Allow ASCII-only paths and queries (no special unicode)
        return all(ord(ch) < 128 for ch in parsed.path + parsed.query)
    except Exception:
        return False

def is_cross_domain_submit(base_url: str, target_url: str) -> bool:
    """
    Blocks only true cross-domain or encoded phishing submissions.
    Allows relative and same-domain URLs.
    """
    try:
        # ✅ Decode percent-encoded URLs first
        target_url = unquote(target_url or "")

        base = urlparse(base_url)
        target = urlparse(target_url)

        # ✅ Allow relative URLs
        if not target.netloc:
            return False

        base_host = (base.hostname or "").lower().lstrip("www.")
        target_host = (target.hostname or "").lower().lstrip("www.")

        # ✅ Allow same host or subdomains
        if base_host == target_host or target_host.endswith("." + base_host) or base_host.endswith("." + target_host):
            return False

        # 🚫 Block if encoded malicious domain (punycode / IDN / non-ascii)
        if not all(ord(c) < 128 for c in target_host):
            return True
        if target_host.startswith("xn--"):  # punycode
            return True

        # 🚫 Block if root domains differ
        base_parts = base_host.split(".")
        target_parts = target_host.split(".")
        if len(base_parts) >= 2 and len(target_parts) >= 2:
            base_root = ".".join(base_parts[-2:])
            target_root = ".".join(target_parts[-2:])
            if base_root != target_root:
                return True

        return False

    except Exception:
        return False

def is_suspicious_domain(domain: str) -> bool:
    """
    Flags domains that *look* like common phishing attempts.
    For example: instagram-login.com, goog1e.com, etc.
    """
    if not domain:
        return False

    domain = domain.lower()

    # Basic phishing indicators (adjust as needed)
    suspicious_keywords = [
        "login", "verify", "update", "secure", "signin", "account", "password"
    ]
    known_brands = [
        "google", "facebook", "instagram", "paypal", "twitter", "amazon"
    ]

    # If domain combines brand + phishing word, it's suspicious
    for brand in known_brands:
        for word in suspicious_keywords:
            if brand in domain and word in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
                return True

    # If domain contains brand name but is not the official one
    for brand in known_brands:
        if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
            return True

    return False

# ------------------------
# Blocklist
# ------------------------
blocklist_sources = [
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://mirror.cedia.org.ec/malwaredomains/justdomains",
    "https://urlhaus.abuse.ch/downloads/text/"
]

blocked_domains = []
for url in blocklist_sources:
    try:
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line and not line.startswith("#") and not line.startswith("127.") and not line.startswith("::1"):
                    parts = line.split()
                    domain = parts[-1] if len(parts) > 0 else None
                    if domain and "." in domain:
                        blocked_domains.append(domain)
    except:
        pass

AD_DOMAINS = {
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google.com",
    "ads.yahoo.com",
    "taboola.com",
    "outbrain.com",
    "revcontent.com",
    "facebook.net",
    "scorecardresearch.com"
}
blocked_domains.extend(AD_DOMAINS)

def check_safety(url, blocklist=[]):
    return any(bad_url in url for bad_url in blocklist)

def sanitize_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url

# ------------------------
# HTML Parser
# ------------------------
class Node:
    def __init__(self, tag="", attrs=None, text="", parent=None):
        self.tag = tag
        self.attrs = attrs or {}
        self.text = text
        self.children = []
        self.parent = parent

class TreeHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.root = Node("root")

    def handle_starttag(self, tag, attrs):
        parent = self.stack[-1] if self.stack else None
        node = Node(tag, dict(attrs), parent=parent)
        if parent:
            parent.children.append(node)
        else:
            self.root.children.append(node)
        self.stack.append(node)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1].tag == tag:
            self.stack.pop()

    def handle_data(self, data):
        if data.strip():
            node = Node(text=data.strip())
            if self.stack:
                self.stack[-1].children.append(node)
            else:
                self.root.children.append(node)


# ------------------------
# Worker Thread for Page Loading
# ------------------------
class PageLoader(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            r = requests.get(self.url, timeout=7, headers={"User-Agent": "SentinelBrowser/0.1"})
            if r.status_code == 200:
                html = re.sub(r"<(script|style).*?>.*?</\1>", "", r.text, flags=re.DOTALL)
                html = remove_ads_from_html(html)
                self.finished.emit(html)
            else:
                self.error.emit(f"<h1>Error {r.status_code}</h1>")
        except Exception as e:
            self.error.emit(f"<h1>Connection Error</h1><p>{e}</p>")


# ------------------------
# Browser Widget
# ------------------------
class BrowserWidget(QWidget):
    def __init__(self, html="<h1>Welcome to Sentinel Browser Engine</h1>"):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setAlignment(Qt.AlignTop)
        self.layout.setSpacing(10)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.setHtml(html)

    def clear_layout(self):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def setHtml(self, html):
        self.clear_layout()
        parser = TreeHTMLParser()
        parser.feed(html)
        self.root_node = parser.root
        self.render_nodes(self.root_node)

    def show_loading(self):
        self.clear_layout()
        lbl = QLabel("⏳ Loading...")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("font-size: 18px; color: #555; padding: 20px;")
        self.layout.addWidget(lbl)

    def find_form(node):
        while node:
            if node.tag == "form":
                return node
            node = node.parent
        return None

    def on_return_pressed():
        form_node = find_form(child)
        # gather live values from bound widgets (if any)
        data = {}
        def collect_inputs(n):
            for c in n.children:
                if c.tag == "input" and "name" in c.attrs:
                    widget = c.attrs.get("_widget")
                    if isinstance(widget, QLineEdit):
                        data[c.attrs["name"]] = widget.text()
                    else:
                        data[c.attrs["name"]] = c.attrs.get("value", "")
                collect_inputs(c)
        if form_node:
            collect_inputs(form_node)
            # build action (resolve relative with base)
            action = form_node.attrs.get("action", "")
            method = form_node.attrs.get("method", "get").lower()
            from urllib.parse import urlencode, urljoin
            main_window = self.window()
            base_url = main_window.url_bar.text().strip()
            action_url = urljoin(base_url if base_url else "", action or "")
            if method == "get":
                query = urlencode(data)
                target = f"{action_url}?{query}" if query else action_url
            else:
                target = action_url
        else:
            # fallback: if no form, treat this as a direct search using current page as base
            val = entry.text().strip()
            if not val:
                print("[Enter pressed — empty]")
                return
            # For simple behavior: navigate to base + "?q=value" if base has path else treat as search term
            main_window = self.window()
            base_url = main_window.url_bar.text().strip()
            if base_url:
                target = urljoin(base_url if base_url.startswith(("http://","https://")) else "https://"+base_url, f"?q={val}")
            else:
                # if no base, use the typed text as an URL-like target (will be resolved by secure_navigate)
                target = val

        # Use the central navigator instead of goto_url directly
        main_window = self.window()
        main_window.secure_navigate(target, base_url=main_window.url_bar.text().strip())

    def render_nodes(self, node):
        for child in node.children:
            tag = child.tag.lower() if child.tag else ""

            if tag == "button":
                text = child.text or child.attrs.get("value", "Button")
                button = QPushButton(text)
                button.setStyleSheet("""
                    QPushButton {
                        border: 2px solid #555;
                        border-radius: 6px;
                        padding: 8px 16px;
                        background-color: #f2f2f2;
                        font-size: 14px;
                    }
                    QPushButton:hover {
                        background-color: #e6e6e6;
                    }
                    QPushButton:pressed {
                        background-color: #d9d9d9;
                    }
                """)

                def find_form(node):
                    while node:
                        if node.tag == "form":
                            return node
                        node = node.parent
                    return None

                def on_button_clicked():
                    form_node = find_form(child)
                    data = {}
                    def collect_inputs(n):
                        for c in n.children:
                            if c.tag == "input" and "name" in c.attrs:
                                widget = c.attrs.get("_widget")
                                if isinstance(widget, QLineEdit):
                                    data[c.attrs["name"]] = widget.text()
                                else:
                                    data[c.attrs["name"]] = c.attrs.get("value", "")
                            collect_inputs(c)
                    if form_node:
                        collect_inputs(form_node)
                        action = form_node.attrs.get("action", "")
                        method = form_node.attrs.get("method", "get").lower()
                        from urllib.parse import urlencode, urljoin
                        main_window = self.window()
                        base_url = main_window.url_bar.text().strip()
                        action_url = urljoin(base_url if base_url.startswith(("http://","https://")) else "https://"+base_url, action or "")
                        if method == "get":
                            query = urlencode(data)
                            target = f"{action_url}?{query}" if query else action_url
                        else:
                            target = action_url
                        main_window.secure_navigate(target, base_url=base_url)
                    else:
                        print(f"[Clicked <button>: {text}] (no form found)")

            elif tag == "input":
                input_type = child.attrs.get("type", "text").lower()
                if input_type in ["text", "search"]:
                    entry = QLineEdit()
                    entry.setPlaceholderText(child.attrs.get("placeholder", ""))
                    entry.setStyleSheet("""
                        QLineEdit {
                            border: 2px solid #aaa;
                            border-radius: 4px;
                            padding: 6px;
                            font-size: 14px;
                        }
                        QLineEdit:focus {
                            border-color: #448aff;
                        }
                    """)

                    # Bind this QLineEdit to its HTML node
                    child.attrs["_widget"] = entry

                    def find_form(node):
                        while node:
                            if node.tag == "form":
                                return node
                            node = node.parent
                        return None

                    def on_return_pressed():
                        form_node = find_form(child)
                        if form_node:
                            action = form_node.attrs.get("action", "")
                            method = form_node.attrs.get("method", "get").lower()

                            # Gather all inputs from this form
                            data = {}
                            def collect_inputs(n):
                                for c in n.children:
                                    if c.tag == "input" and "name" in c.attrs:
                                        # If widget exists, use its live value
                                        widget = c.attrs.get("_widget")
                                        if isinstance(widget, QLineEdit):
                                            data[c.attrs["name"]] = widget.text()
                                        else:
                                            data[c.attrs["name"]] = c.attrs.get("value", "")
                                    collect_inputs(c)
                            collect_inputs(form_node)

                            from urllib.parse import urlencode, urljoin
                            main_window = self.window()
                            if not hasattr(main_window, "goto_url"):
                                print("[Error] Could not find main window to submit form.")
                                return

                            base_url = main_window.url_bar.text().strip()
                            if not base_url.startswith("http"):
                                base_url = "https://" + base_url

                            action_url = urljoin(base_url, action or "")

                            if method == "get":
                                query = urlencode(data)
                                target = f"{action_url}?{query}" if query else action_url
                                main_window.url_bar.setText(target)
                                main_window.goto_url()
                            else:
                                main_window.url_bar.setText(action_url)
                                main_window.goto_url()
                        else:
                            print("[Enter pressed — no form found]")

                    # Connect Return key
                    entry.returnPressed.connect(on_return_pressed)
                    self.layout.addWidget(entry)

                elif input_type in ["button", "submit"]:
                    text = child.attrs.get("value", child.text or "Button")
                    button = QPushButton(text)
                    button.setStyleSheet("""
                        QPushButton {
                            border: 2px solid #555;
                            border-radius: 6px;
                            padding: 8px 16px;
                            background-color: #f2f2f2;
                            font-size: 14px;
                        }
                        QPushButton:hover {
                            background-color: #e6e6e6;
                        }
                        QPushButton:pressed {
                            background-color: #d9d9d9;
                        }
                    """)

                    def find_form(node):
                        while node:
                            if node.tag == "form":
                                return node
                            node = node.parent
                        return None

                    def on_button_clicked():
                        form_node = find_form(child)
                        data = {}
                        def collect_inputs(n):
                            for c in n.children:
                                if c.tag == "input" and "name" in c.attrs:
                                    widget = c.attrs.get("_widget")
                                    if isinstance(widget, QLineEdit):
                                        data[c.attrs["name"]] = widget.text()
                                    else:
                                        data[c.attrs["name"]] = c.attrs.get("value", "")
                                collect_inputs(c)
                        if form_node:
                            collect_inputs(form_node)
                            action = form_node.attrs.get("action", "")
                            method = form_node.attrs.get("method", "get").lower()
                            from urllib.parse import urlencode, urljoin
                            main_window = self.window()
                            base_url = main_window.url_bar.text().strip()
                            action_url = urljoin(base_url if base_url.startswith(("http://","https://")) else "https://"+base_url, action or "")
                            if method == "get":
                                query = urlencode(data)
                                target = f"{action_url}?{query}" if query else action_url
                            else:
                                target = action_url
                            main_window.secure_navigate(target, base_url=base_url)
                        else:
                            print(f"[Clicked <input> button: {text}] — no form found")

                    button.clicked.connect(on_button_clicked)
                    self.layout.addWidget(button)

            elif tag in ["h1", "h2", "h3", "p", "b", "i", "u"]:
                label = QLabel(child.text)
                label.setWordWrap(True)
                font = label.font()

                if tag == "h1":
                    font.setPointSize(32)
                    font.setBold(True)
                elif tag == "h2":
                    font.setPointSize(26)
                    font.setBold(True)
                elif tag == "h3":
                    font.setPointSize(22)
                    font.setBold(True)
                elif tag == "b":
                    font.setBold(True)
                elif tag == "i":
                    font.setItalic(True)
                elif tag == "u":
                    label.setText(f"<u>{child.text}</u>")

                label.setFont(font)
                self.layout.addWidget(label)

            elif child.text:
                lbl = QLabel(child.text)
                lbl.setWordWrap(True)
                self.layout.addWidget(lbl)

            # Recursive render
            if child.children:
                self.render_nodes(child)


# ------------------------
# Browser Tab
# ------------------------
class BrowserTab(QWidget):
    def __init__(self, name="New Tab"):
        super().__init__()
        layout = QVBoxLayout(self)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.browser = BrowserWidget()
        self.scroll_area.setWidget(self.browser)
        layout.addWidget(self.scroll_area)


# ------------------------
# Main Window
# ------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel Browser")
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setMinimumSize(900, 600)

        # ---- Custom Title Bar ----
        title_bar = QWidget()
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(5, 2, 5, 2)
        title_layout.setSpacing(10)

        title_label = QLabel("🛰 Sentinel Browser")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: white;")

        btn_min = QPushButton("—")
        btn_max = QPushButton("⬜")
        btn_close = QPushButton("✕")

        for b in [btn_min, btn_max, btn_close]:
            b.setFixedSize(30, 30)
            b.setStyleSheet("""
                QPushButton {
                    color: white;
                    background-color: #444;
                    border: none;
                    font-size: 14px;
                }
                QPushButton:hover { background-color: #666; }
                QPushButton:pressed { background-color: #222; }
            """)

        btn_min.clicked.connect(self.showMinimized)
        btn_max.clicked.connect(self.toggle_maximize)
        btn_close.clicked.connect(self.close)

        title_layout.addWidget(title_label)
        title_layout.addStretch()
        title_layout.addWidget(btn_min)
        title_layout.addWidget(btn_max)
        title_layout.addWidget(btn_close)

        # ---- Navigation Toolbar ----
        navbar = QToolBar()
        navbar.setMovable(False)

        self.back_btn = QAction("←", self)
        self.forward_btn = QAction("→", self)
        self.reload_btn = QAction("⟳", self)

        self.back_btn.triggered.connect(self.go_back)
        self.forward_btn.triggered.connect(self.go_forward)
        self.reload_btn.triggered.connect(self.reload_page)

        navbar.addAction(self.back_btn)
        navbar.addAction(self.forward_btn)
        navbar.addAction(self.reload_btn)

        self.url_bar = QLineEdit()
        self.url_bar.returnPressed.connect(self.goto_url)
        navbar.addWidget(self.url_bar)

        # ---- Tabs ----
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.South)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.tabBarClicked.connect(self.handle_plus_tab)
        self.tab_history = {}

        # ---- Layout ----
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(title_bar)
        main_layout.addWidget(navbar)
        main_layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # ---- Threads and Tabs ----
        self.loader_thread = None
        self.add_new_tab("Home")
        self.add_plus_tab()

        # Shortcuts
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(lambda: self.add_new_tab("New Tab"))
        QShortcut(QKeySequence("Ctrl+W"), self).activated.connect(lambda: self.close_tab(self.tabs.currentIndex()))

        # ---- Title Bar Dragging ----
        title_bar.mousePressEvent = self.mousePressEvent
        title_bar.mouseMoveEvent = self.mouseMoveEvent
        self.offset = None

    def secure_navigate(self, target_url: str, base_url: str = ""):
        """Centralized safe navigation with security checks."""
        from urllib.parse import urlparse, urljoin

        if not base_url:
            base_url = self.url_bar.text().strip()
        if not base_url.startswith("http"):
            base_url = "https://" + base_url

        target_url = urljoin(base_url, target_url)
        parsed_domain = urlparse(target_url).netloc

        # --- Security checks ---
        if is_cross_domain_submit(base_url, target_url):
            warning_html = f"""
            <h1>⚠️ Suspicious Form Submission</h1>
            <p>This form tries to submit to another domain:</p>
            <p><b>{target_url}</b></p>
            <p>This could be phishing. Submission has been blocked.</p>
            """
            self.current_browser().setHtml(warning_html)
            return

        if is_suspicious_domain(parsed_domain):
            warning_html = f"""
            <h1>⚠️ Suspicious Domain Detected</h1>
            <p>The domain <b>{parsed_domain}</b> looks suspicious or fake.</p>
            <p>This might be an imitation of a known service.</p>
            """
            self.current_browser().setHtml(warning_html)
            return

        # --- If passed checks ---
        print(f"[Safe Navigation] {target_url}")
        self.url_bar.setText(target_url)
        self.goto_url()


    # --- Window Dragging ---
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.offset = event.pos()

    def mouseMoveEvent(self, event):
        if self.offset is not None and event.buttons() == Qt.LeftButton:
            self.move(self.pos() + event.pos() - self.offset)

    def toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    # --------------------------
    # Browser Logic
    # --------------------------
    def current_browser(self):
        current_widget = self.tabs.currentWidget()
        if isinstance(current_widget, BrowserTab):
            return current_widget.browser
        return None

    def goto_url(self, add_to_history=True):
        browser = self.current_browser()
        if not browser:
            return

        url_string = sanitize_url(self.url_bar.text().strip())
        if not url_string:
            browser.setHtml("<h1>Invalid URL</h1>")
            return

        # ---- Homograph protection ----
        if not is_ascii_url(url_string):
            browser.setHtml("<h1>⚠️ Potential homograph attack detected!</h1><p>The URL contains non-ASCII characters and may be unsafe.</p>")
            return

        # ---- Domain safety check ----
        if check_safety(url_string, blocked_domains):
            browser.setHtml("<h1>This domain is blocked as malicious!</h1>")
            return

        # ---- Begin loading ----
        browser.show_loading()
        self.url_bar.setDisabled(True)

        # ---- Add to history ----
        if add_to_history:
            idx = self.tabs.currentIndex()
            if idx not in self.tab_history:
                self.tab_history[idx] = {"urls": [], "pos": -1}
            hist = self.tab_history[idx]
            hist["urls"] = hist["urls"][: hist["pos"] + 1]  # cut forward history
            hist["urls"].append(url_string)
            hist["pos"] += 1
            self.update_nav_buttons()

        self.loader_thread = PageLoader(url_string)
        self.loader_thread.finished.connect(lambda html: self.display_page(browser, html))
        self.loader_thread.error.connect(lambda err: self.display_page(browser, err))
        self.loader_thread.start()

    def display_page(self, browser, html):
        browser.setHtml(html)
        self.url_bar.setDisabled(False)
        self.loader_thread = None
    
    def update_nav_buttons(self):
        idx = self.tabs.currentIndex()
        if idx not in self.tab_history:
            self.back_btn.setEnabled(False)
            self.forward_btn.setEnabled(False)
            return
        hist = self.tab_history[idx]
        self.back_btn.setEnabled(hist["pos"] > 0)
        self.forward_btn.setEnabled(hist["pos"] < len(hist["urls"]) - 1)

    def go_back(self):
        idx = self.tabs.currentIndex()
        if idx not in self.tab_history:
            return
        hist = self.tab_history[idx]
        if hist["pos"] > 0:
            hist["pos"] -= 1
            prev_url = hist["urls"][hist["pos"]]
            self.url_bar.setText(prev_url)
            self.goto_url(add_to_history=False)
        self.update_nav_buttons()
    
    def go_forward(self):
        idx = self.tabs.currentIndex()
        if idx not in self.tab_history:
            return
        hist = self.tab_history[idx]
        if hist["pos"] < len(hist["urls"]) - 1:
            hist["pos"] += 1
            next_url = hist["urls"][hist["pos"]]
            self.url_bar.setText(next_url)
            self.goto_url(add_to_history=False)
        self.update_nav_buttons()
    
    def reload_page(self):
        current_url = self.url_bar.text().strip()
        if current_url:
            self.goto_url(add_to_history=False)

    # --------------------------
    # Tabs
    # --------------------------
    def add_new_tab(self, name="New Tab", switch=True):
        new_tab = BrowserTab(name)
        idx = self.tabs.insertTab(self.tabs.count() - 1, new_tab, name)
        self.tab_history[idx] = {"urls": [], "pos": -1}
        if switch:
            self.tabs.setCurrentIndex(idx)

    def close_tab(self, index):
        # Prevent closing "+" tab
        if self.tabs.tabText(index) == "+":
            return
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)

    def add_plus_tab(self):
        plus_widget = QWidget()
        idx = self.tabs.addTab(plus_widget, "+")
        # Make sure "+" tab has no close button
        self.tabs.tabBar().setTabButton(idx, QTabBar.RightSide, None)

    def handle_plus_tab(self, index):
        if self.tabs.tabText(index) == "+":
            self.add_new_tab("New Tab")
            self.tabs.setCurrentIndex(self.tabs.count() - 2)

# ------------------------
# Run App
# ------------------------
app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec_()
