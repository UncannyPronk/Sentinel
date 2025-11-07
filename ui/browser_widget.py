import re
import requests
from urllib.parse import urljoin
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QLabel, QPushButton, QLineEdit
from PyQt5.QtCore import Qt
from core.html_parser import TreeHTMLParser


class BrowserWidget(QWidget):
    def __init__(self, html="<h1>Welcome to Sentinel Browser Engine</h1>"):
        super().__init__()

        self.container = QWidget()
        self.page_layout = QVBoxLayout(self.container)
        self.page_layout.setAlignment(Qt.AlignTop)
        self.page_layout.setSpacing(10)
        self.page_layout.setContentsMargins(20, 20, 20, 20)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.container)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(self.scroll)

        self.root_node = None
        self.inline_css = []
        self.linked_css = []
        self.css_rules = {}

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

        self.inline_css = []
        self.linked_css = []

        def collect_css(node):
            if node.tag == "style" and node.text.strip():
                self.inline_css.append(node.text.strip())
            elif node.tag == "link" and node.attrs.get("rel") == "stylesheet":
                href = node.attrs.get("href")
                if href:
                    self.linked_css.append(href)
            for c in node.children:
                collect_css(c)

        collect_css(self.root_node)
        print(f"[Found {len(self.inline_css)} inline CSS blocks, {len(self.linked_css)} linked CSS files]")

        base_url = getattr(self, "base_url", "")
        for css_url in self.linked_css:
            full_url = urljoin(base_url, css_url)
            try:
                r = requests.get(full_url, timeout=5)
                if r.status_code == 200:
                    parsed = parse_css_rules(r.text)
                    self.css_rules.update(translate_css_to_qt(parsed))
                    print(f"[Loaded external CSS: {css_url}]")
            except Exception as e:
                print(f"[Failed to load external CSS: {css_url}] {e}")

        for href in self.linked_css:
            try:
                r = requests.get(href, timeout=3)
                if r.status_code == 200:
                    self.inline_css.append(r.text)
                    print(f"[CSS loaded successfully from {href}]")
            except Exception as e:
                print(f"[Error loading CSS from {href}: {e}]")

        def parse_css_rules(css_text):
            rules = {}
            pattern = re.compile(r'([^{]+){([^}]+)}')
            for selector, body in pattern.findall(css_text):
                selector = selector.strip()
                body = body.strip()
                rules[selector] = body
            return rules

        def translate_css_to_qt(css_rules):
            qt_rules = {}
            for selector, body in css_rules.items():
                if selector in ["body", "html"]:
                    qt_selector = "*"
                elif selector.startswith("input"):
                    qt_selector = "QLineEdit"
                elif selector.startswith("button"):
                    qt_selector = "QPushButton"
                elif selector.startswith("p"):
                    qt_selector = "QLabel"
                elif selector.startswith("h"):
                    qt_selector = "QLabel"
                else:
                    qt_selector = selector
                qt_style = f"{qt_selector} {{\n{body}\n}}"
                qt_rules[selector] = qt_style
            return qt_rules

        self.css_rules = {}
        for css_text in self.inline_css:
            parsed = parse_css_rules(css_text)
            self.css_rules.update(translate_css_to_qt(parsed))

        if self.css_rules:
            print(f"[Loaded {len(self.css_rules)} CSS rules]")
        else:
            print("[No CSS rules found]")

        body_bg_color = None
        if hasattr(self, "css_rules") and "body" in self.css_rules:
            body_style = self.css_rules["body"]
            match = re.search(r'background-color\s*:\s*([^;]+);?', body_style)
            if match:
                body_bg_color = match.group(1).strip()
                print(f"[Detected page background color: {body_bg_color}]")

        if "body" in self.css_rules:
            bg_match = re.search(r'background-color\s*:\s*([^;]+);?', self.css_rules["body"], re.IGNORECASE)
            if bg_match:
                color_value = bg_match.group(1).strip()
                self.container.setStyleSheet(f"background-color: {color_value};")
                print(f"[Applied background color: {color_value}]")

        if body_bg_color:
            self.setStyleSheet(f"background-color: {body_bg_color};")

        self.render_nodes(self.root_node)

    def show_loading(self):
        self.clear_layout()
        self.container.setStyleSheet("background-color: #f0f0f0;")
        self.setStyleSheet("background-color: #f0f0f0;")
        lbl = QLabel("⏳ Loading...")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("font-size: 18px; color: #555; padding: 20px;")
        self.page_layout.addWidget(lbl)

    def render_nodes(self, node):
        for child in node.children:
            tag = child.tag.lower() if child.tag else ""
            if tag in ["style", "head"]:
                continue

            if tag == "button":
                text = child.text or child.attrs.get("value", "Button")
                button = QPushButton(text)
                button.setStyleSheet(
                    "QPushButton {border: 2px solid #555; border-radius: 6px; padding: 8px 16px; "
                    "background-color: #f2f2f2; font-size: 14px;} "
                    "QPushButton:hover {background-color: #e6e6e6;} "
                    "QPushButton:pressed {background-color: #d9d9d9;}"
                )
                if "style" in child.attrs:
                    button.setStyleSheet(button.styleSheet() + "\n" + child.attrs["style"])
                if hasattr(self, "css_rules") and tag in self.css_rules:
                    button.setStyleSheet(self.css_rules[tag])

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
                        action_url = urljoin(
                            base_url if base_url.startswith(("http://", "https://")) else "https://" + base_url,
                            action or ""
                        )
                        if method == "get":
                            query = urlencode(data)
                            target = f"{action_url}?{query}" if query else action_url
                        else:
                            target = action_url
                        main_window.secure_navigate(target, base_url=base_url)
                    else:
                        print(f"[Clicked <button>: {text}] (no form found)")

                button.clicked.connect(on_button_clicked)
                self.page_layout.addWidget(button)

            elif tag == "input":
                input_type = child.attrs.get("type", "text").lower()
                # if input_type == "hidden":
                #     entry = QLineEdit()
                #     entry.setText(child.attrs.get("value", ""))
                #     entry.setReadOnly(True)
                #     entry.setStyleSheet("""
                #         QLineEdit {
                #             background-color: #333;
                #             color: #fff;
                #             border: 1px solid #555;
                #             border-radius: 4px;
                #             padding: 6px;
                #             font-size: 14px;
                #         }
                #     """)
                #     child.attrs["_widget"] = entry
                #     self.page_layout.addWidget(entry)
                #     continue 

                if input_type in ["text", "search", "hidden"]:
                    entry = QLineEdit()
                    entry.setPlaceholderText(child.attrs.get("placeholder", ""))
                    entry.setStyleSheet(
                        "QLineEdit {border: 2px solid #aaa; border-radius: 4px; padding: 6px; font-size: 14px;} "
                        "QLineEdit:focus {border-color: #448aff;}"
                    )
                    if "style" in child.attrs:
                        entry.setStyleSheet(entry.styleSheet() + "\n" + child.attrs["style"])
                    if hasattr(self, "css_rules") and "input" in self.css_rules:
                        entry.setStyleSheet(self.css_rules["input"])

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

                            collect_inputs(form_node)
                            from urllib.parse import urlencode, urljoin
                            main_window = self.window()
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

                    entry.returnPressed.connect(on_return_pressed)
                    self.page_layout.addWidget(entry)

                elif input_type in ["button", "submit"]:
                    text = child.attrs.get("value", child.text or "Button")
                    button = QPushButton(text)
                    button.setStyleSheet(
                        "QPushButton {border: 2px solid #555; border-radius: 6px; padding: 8px 16px; "
                        "background-color: #f2f2f2; font-size: 14px;} "
                        "QPushButton:hover {background-color: #e6e6e6;} "
                        "QPushButton:pressed {background-color: #d9d9d9;}"
                    )
                    if "style" in child.attrs:
                        button.setStyleSheet(button.styleSheet() + "\n" + child.attrs["style"])
                    if hasattr(self, "css_rules") and "input[type=submit]" in self.css_rules:
                        button.setStyleSheet(self.css_rules["input[type=submit]"])

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
                            action_url = urljoin(
                                base_url if base_url.startswith(("http://", "https://")) else "https://" + base_url,
                                action or ""
                            )
                            if method == "get":
                                query = urlencode(data)
                                target = f"{action_url}?{query}" if query else action_url
                            else:
                                target = action_url
                            main_window.secure_navigate(target, base_url=base_url)
                        else:
                            print(f"[Clicked <input> button: {text}] — no form found")

                    button.clicked.connect(on_button_clicked)
                    self.page_layout.addWidget(button)

            elif tag in ["h1", "h2", "h3", "h4", "h5", "h6", "p", "b", "i", "u"]:
                label = QLabel(child.text)
                label.setWordWrap(True)
                font = label.font()
                if tag == "h1":
                    font.setPointSize(36)
                    font.setBold(True)
                elif tag == "h2":
                    font.setPointSize(32)
                    font.setBold(True)
                elif tag == "h3":
                    font.setPointSize(28)
                    font.setBold(True)
                elif tag == "h4":
                    font.setPointSize(24)
                    font.setBold(True)
                elif tag == "h5":
                    font.setPointSize(20)
                    font.setBold(True)
                elif tag == "h6":
                    font.setPointSize(16)
                    font.setBold(True)
                elif tag == "b":
                    font.setBold(True)
                elif tag == "i":
                    font.setItalic(True)
                elif tag == "u":
                    label.setText(f"<u>{child.text}</u>")

                label.setFont(font)
                if hasattr(self, "css_rules") and tag in self.css_rules:
                    label.setStyleSheet(self.css_rules[tag])
                self.page_layout.addWidget(label)

            elif child.text:
                lbl = QLabel(child.text)
                lbl.setWordWrap(True)
                applied_style = None
                parent_tag = child.parent.tag.lower() if child.parent and child.parent.tag else None
                if hasattr(self, "css_rules"):
                    if parent_tag and parent_tag in self.css_rules:
                        applied_style = self.css_rules[parent_tag]
                    elif "body" in self.css_rules:
                        applied_style = self.css_rules["body"]
                if applied_style:
                    lbl.setStyleSheet(applied_style)
                self.page_layout.addWidget(lbl)

            if child.children:
                self.render_nodes(child)
