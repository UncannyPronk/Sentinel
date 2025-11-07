from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QScrollArea, QPushButton, QLineEdit
from PyQt5.QtCore import Qt
import re, requests
from html_parser import TreeHTMLParser
from css_utils import collect_css, parse_css_rules, translate_css_to_qt

class BrowserWidget(QWidget):
    def __init__(self, html="<h1>Welcome to Sentinel</h1>"):
        super().__init__()
        self.container = QWidget()
        self.page_layout = QVBoxLayout(self.container)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.container)
        layout = QVBoxLayout(self)
        layout.addWidget(self.scroll)
        self.setHtml(html)

    def clear_layout(self):
        while self.page_layout.count():
            item = self.page_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def setHtml(self, html):
        self.clear_layout()
        parser = TreeHTMLParser()
        parser.feed(html)
        self.root_node = parser.root

        base_url = getattr(self, "base_url", "")
        inline_css, linked_css = collect_css(self.root_node, base_url)
        all_css = "\n".join(inline_css)
        for css_url in linked_css:
            try:
                r = requests.get(css_url, timeout=5)
                if r.status_code == 200:
                    all_css += "\n" + r.text
            except:
                pass

        parsed = parse_css_rules(all_css)
        self.css_rules = translate_css_to_qt(parsed)
        self.render_nodes(self.root_node)

    def show_loading(self):
        self.clear_layout()
        lbl = QLabel("⏳ Loading...")
        lbl.setAlignment(Qt.AlignCenter)
        self.page_layout.addWidget(lbl)

    def render_nodes(self, node):
        for child in node.children:
            tag = child.tag.lower() if child.tag else ""
            if tag in ["style", "head"]:
                continue
            if tag.startswith("h") or tag == "p":
                label = QLabel(child.text)
                label.setWordWrap(True)
                self.page_layout.addWidget(label)
            elif tag == "button":
                btn = QPushButton(child.text or "Button")
                self.page_layout.addWidget(btn)
            elif tag == "input":
                entry = QLineEdit()
                entry.setPlaceholderText(child.attrs.get("placeholder", ""))
                self.page_layout.addWidget(entry)
            if child.children:
                self.render_nodes(child)

class BrowserTab(QWidget):
    def __init__(self, name="New Tab"):
        super().__init__()
        layout = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.browser = BrowserWidget()
        scroll.setWidget(self.browser)
        layout.addWidget(scroll)
