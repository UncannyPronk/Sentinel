from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from urllib.parse import urlparse
from core.utils import sanitize_url
from core.security import (
    is_ascii_url, check_safety, blocked_domains,
    is_cross_domain_submit, is_suspicious_domain
)
from core.page_loader import PageLoader
from ui.browser_tab import BrowserTab
import html as html_lib

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel Browser")
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setMinimumSize(900, 600)

        title_bar = QWidget()
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(5, 2, 5, 2)
        title_layout.setSpacing(10)

        title_label = QLabel("🛰 Sentinel Browser")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: grey;")

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

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.South)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.tabBarClicked.connect(self.handle_plus_tab)
        self.tabs.currentChanged.connect(self.on_tab_changed)
        self.tab_history = {}

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        main_layout.addWidget(title_bar)
        main_layout.addWidget(navbar)
        main_layout.addWidget(self.tabs)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.loader_thread = None
        self.add_new_tab("Home")
        self.add_plus_tab()

        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(lambda: self.add_new_tab("New Tab"))
        QShortcut(QKeySequence("Ctrl+W"), self).activated.connect(lambda: self.close_tab(self.tabs.currentIndex()))

        title_bar.mousePressEvent = self.mousePressEvent
        title_bar.mouseMoveEvent = self.mouseMoveEvent
        self.offset = None

    def secure_navigate(self, target_url: str, base_url: str = ""):
        from urllib.parse import urlparse, urljoin

        if not base_url:
            base_url = self.url_bar.text().strip()
        if not base_url.startswith("http"):
            base_url = "https://" + base_url

        target_url = urljoin(base_url, target_url)
        parsed_domain = urlparse(target_url).netloc

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

        print(f"[Safe Navigation] {target_url}")
        self.url_bar.setText(target_url)
        self.load_page(target_url, method="GET")

    def load_page(self, url, method="GET", data=None):
        """Unified loader for GET and POST so forms work properly."""
        browser = self.current_browser()
        if not browser:
            return

        browser.show_loading()
        self.url_bar.setDisabled(True)

        self.loader_thread = PageLoader(url, method=method, data=data)
        self.loader_thread.finished.connect(lambda result: self.display_page(browser, result))
        self.loader_thread.error.connect(lambda err: self.display_page(browser, err))
        self.loader_thread.start()

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

        if not is_ascii_url(url_string):
            browser.setHtml("<h1>⚠️ Potential homograph attack detected!</h1><p>The URL contains non-ASCII characters and may be unsafe.</p>")
            return

        if check_safety(url_string, blocked_domains):
            browser.setHtml("<h1>This domain is blocked as malicious!</h1>")
            return

        browser.show_loading()
        self.url_bar.setDisabled(True)

        if add_to_history:
            idx = self.tabs.currentIndex()
            if idx not in self.tab_history:
                self.tab_history[idx] = {"urls": [], "pos": -1}
            hist = self.tab_history[idx]
            hist["urls"] = hist["urls"][: hist["pos"] + 1]
            hist["urls"].append(url_string)
            hist["pos"] += 1
            self.update_nav_buttons()

        self.loader_thread = PageLoader(url_string)
        self.loader_thread.finished.connect(lambda result: self.display_page(browser, result))
        self.loader_thread.error.connect(lambda err: self.display_page(browser, err))
        self.loader_thread.start()

    def display_page(self, browser, result):
        html, title = result
        browser.current_url = self.url_bar.text().strip()

        # fallback to parsing cleaned HTML
        if not title:
            title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else "Untitled"

        if len(title) > 60:
            title = title[:60] + "…"

        # Update tab name
        idx = self.tabs.currentIndex()
        self.tabs.setTabText(idx, title)

        browser.base_url = self.url_bar.text().strip()
        browser.setHtml(html)
        self.url_bar.setDisabled(False)

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

    def add_new_tab(self, name="New Tab", switch=True):
        new_tab = BrowserTab(name)
        idx = self.tabs.insertTab(self.tabs.count() - 1, new_tab, name)
        self.tab_history[idx] = {"urls": [], "pos": -1}
        if switch:
            self.tabs.setCurrentIndex(idx)

    def close_tab(self, index):
        if self.tabs.tabText(index) == "+":
            return
        if self.tabs.count() > 1:
            self.tabs.removeTab(index)

    def add_plus_tab(self):
        plus_widget = QWidget()
        idx = self.tabs.addTab(plus_widget, "+")
        self.tabs.tabBar().setTabButton(idx, QTabBar.RightSide, None)

    def handle_plus_tab(self, index):
        if self.tabs.tabText(index) == "+":
            self.add_new_tab("New Tab")
            self.tabs.setCurrentIndex(self.tabs.count() - 2)

    def on_tab_changed(self, index):
        browser = self.current_browser()

        # Case 1: No browser (e.g., plus-tab)
        if not browser:
            self.url_bar.setText("")
            return

        # Case 2: Browser exists → restore last known URL for that tab
        url = getattr(browser, "current_url", "")
        self.url_bar.setText(url)
