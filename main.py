import sys
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import QApplication, QMainWindow, QToolBar, QLineEdit, QAction, QTabWidget, QWidget, QVBoxLayout, QPushButton, QLabel, QShortcut, QTabBar

from network import PageLoader, sanitize_url, check_safety, blocked_domains
from browser_widget import BrowserTab
from security import is_ascii_url, is_cross_domain_submit, is_suspicious_domain


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel Browser")
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setMinimumSize(900, 600)

        # ---- Title Bar ----
        title_bar = QWidget()
        title_layout = QVBoxLayout(title_bar)
        title_label = QLabel("🛰 Sentinel Browser")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; color: grey;")
        title_layout.addWidget(title_label)

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
        main_layout.addWidget(title_bar)
        main_layout.addWidget(navbar)
        main_layout.addWidget(self.tabs)
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # ---- Tabs ----
        self.add_new_tab("Home")
        self.add_plus_tab()

        # ---- Shortcuts ----
        QShortcut(QKeySequence("Ctrl+T"), self).activated.connect(lambda: self.add_new_tab("New Tab"))
        QShortcut(QKeySequence("Ctrl+W"), self).activated.connect(lambda: self.close_tab(self.tabs.currentIndex()))

        self.loader_thread = None

    # ---------- Navigation ----------
    def current_browser(self):
        current_widget = self.tabs.currentWidget()
        from browser_widget import BrowserTab
        if isinstance(current_widget, BrowserTab):
            return current_widget.browser
        return None

    def secure_navigate(self, target_url, base_url=""):
        from urllib.parse import urlparse, urljoin
        if not base_url:
            base_url = self.url_bar.text().strip()
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        target_url = urljoin(base_url, target_url)
        parsed_domain = urlparse(target_url).netloc

        # --- Security checks ---
        if is_cross_domain_submit(base_url, target_url):
            self.current_browser().setHtml(
                f"<h1>⚠️ Suspicious submission</h1><p>Form tries to submit to another domain: {target_url}</p>"
            )
            return

        if is_suspicious_domain(parsed_domain):
            self.current_browser().setHtml(
                f"<h1>⚠️ Suspicious Domain</h1><p>The domain <b>{parsed_domain}</b> looks unsafe.</p>"
            )
            return

        self.url_bar.setText(target_url)
        self.goto_url()

    def goto_url(self, add_to_history=True):
        browser = self.current_browser()
        if not browser:
            return

        url_string = sanitize_url(self.url_bar.text().strip())
        if not url_string:
            browser.setHtml("<h1>Invalid URL</h1>")
            return

        if not is_ascii_url(url_string):
            browser.setHtml("<h1>⚠️ Homograph warning!</h1>")
            return

        if check_safety(url_string, blocked_domains):
            browser.setHtml("<h1>This domain is blocked.</h1>")
            return

        browser.show_loading()
        self.url_bar.setDisabled(True)

        if add_to_history:
            idx = self.tabs.currentIndex()
            self.tab_history.setdefault(idx, {"urls": [], "pos": -1})
            hist = self.tab_history[idx]
            hist["urls"] = hist["urls"][: hist["pos"] + 1]
            hist["urls"].append(url_string)
            hist["pos"] += 1
            self.update_nav_buttons()

        self.loader_thread = PageLoader(url_string)
        self.loader_thread.finished.connect(lambda html: self.display_page(browser, html))
        self.loader_thread.error.connect(lambda err: self.display_page(browser, err))
        self.loader_thread.start()

    def display_page(self, browser, html):
        browser.base_url = self.url_bar.text().strip()
        browser.setHtml(html)
        self.url_bar.setDisabled(False)
        self.loader_thread = None

    # ---------- Navigation buttons ----------
    def update_nav_buttons(self):
        idx = self.tabs.currentIndex()
        hist = self.tab_history.get(idx)
        if not hist:
            self.back_btn.setEnabled(False)
            self.forward_btn.setEnabled(False)
            return
        self.back_btn.setEnabled(hist["pos"] > 0)
        self.forward_btn.setEnabled(hist["pos"] < len(hist["urls"]) - 1)

    def go_back(self):
        idx = self.tabs.currentIndex()
        hist = self.tab_history.get(idx)
        if not hist or hist["pos"] <= 0:
            return
        hist["pos"] -= 1
        self.url_bar.setText(hist["urls"][hist["pos"]])
        self.goto_url(add_to_history=False)

    def go_forward(self):
        idx = self.tabs.currentIndex()
        hist = self.tab_history.get(idx)
        if not hist or hist["pos"] >= len(hist["urls"]) - 1:
            return
        hist["pos"] += 1
        self.url_bar.setText(hist["urls"][hist["pos"]])
        self.goto_url(add_to_history=False)

    def reload_page(self):
        if self.url_bar.text().strip():
            self.goto_url(add_to_history=False)

    # ---------- Tabs ----------
    def add_new_tab(self, name="New Tab", switch=True):
        tab = BrowserTab(name)
        idx = self.tabs.insertTab(self.tabs.count() - 1, tab, name)
        self.tab_history[idx] = {"urls": [], "pos": -1}
        if switch:
            self.tabs.setCurrentIndex(idx)

    def add_plus_tab(self):
        plus = QWidget()
        idx = self.tabs.addTab(plus, "+")
        self.tabs.tabBar().setTabButton(idx, QTabBar.RightSide, None)

    def close_tab(self, index):
        if self.tabs.tabText(index) != "+" and self.tabs.count() > 1:
            self.tabs.removeTab(index)

    def handle_plus_tab(self, index):
        if self.tabs.tabText(index) == "+":
            self.add_new_tab()
            self.tabs.setCurrentIndex(self.tabs.count() - 2)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
