import re, requests
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QScrollArea, QLabel, QPushButton, QLineEdit
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from core.html_parser import TreeHTMLParser
from core.security import is_suspicious_domain
from bs4 import BeautifulSoup

class BrowserWidget(QWidget):
    def __init__(self, html="<h1>Welcome to Sentinel</h1>"):
        super().__init__()

        # --- Container for webpage content ---
        self.container = QWidget()
        self.page_layout = QVBoxLayout(self.container)
        self.page_layout.setAlignment(Qt.AlignTop)
        self.page_layout.setSpacing(10)
        self.page_layout.setContentsMargins(20, 20, 20, 20)

        # --- Scrollable area ---
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setWidget(self.container)

        # --- Outer layout ---
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(self.scroll)

        # --- Data storage ---
        self.root_node = None
        self.inline_css = []
        self.linked_css = []
        self.css_rules = {}

        # --- Load default HTML ---
        self.setHtml(html)

    # ------------------- Utility -------------------
    def clear_layout(self):
        while self.page_layout.count():
            item = self.page_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    # ================= IMAGE URL HELPERS =================
    def resolve_image_url(self, base_url, src):
        """Universal image URL resolver (standard-compliant)."""
        from urllib.parse import urljoin

        src = src.strip()

        # Data URL
        if src.startswith("data:"):
            return src

        # Absolute URL
        if src.startswith("http://") or src.startswith("https://"):
            return src

        # Protocol-relative
        if src.startswith("//"):
            return "https:" + src

        # Absolute path
        if src.startswith("/"):
            return urljoin(base_url, src)

        # Relative path
        if not base_url.endswith("/"):
            base_url = base_url + "/"

        return urljoin(base_url, src)

    def fix_wikipedia_static_url(self, img_url, src, base_url):
        """Wikipedia-specific fallback for static files."""
        if "wikipedia.org" not in base_url:
            return img_url  # Do not modify for other sites

        # Wikipedia stores all static assets on en.wikipedia.org
        if src.startswith("/static/"):
            if "m.wikipedia.org" in base_url:
                return "https://en.m.wikipedia.org" + src
            else:
                return "https://en.wikipedia.org" + src

        return img_url

    # ------------------- CSS Helpers -------------------
    def parse_css_rules(self, css_text):
        """Parse simple CSS into a dict: {selector: style_string}"""
        rules = {}
        pattern = re.compile(r'([^{]+)\{([^}]+)\}')
        for sel, block in pattern.findall(css_text):
            sel = sel.strip()
            block = block.strip().replace('\n', ' ')
            rules[sel] = block
        return rules

    def load_external_css(self, html, base_url):
        """Extract inline <style> and external <link rel='stylesheet'> CSS."""
        soup = BeautifulSoup(html, "html.parser")
        css_rules = {}

        inline_styles = soup.find_all("style")
        css_links = soup.find_all("link", rel="stylesheet")

        print(f"[Found {len(inline_styles)} inline CSS blocks, {len(css_links)} linked CSS files]")

        # Inline styles
        for style_tag in inline_styles:
            try:
                css_text = style_tag.get_text()
                rules = self.parse_css_rules(css_text)
                css_rules.update(rules)
            except Exception as e:
                print(f"[Failed to parse inline CSS] {e}")

        # Linked stylesheets
        for link_tag in css_links:
            href = link_tag.get("href")
            if not href:
                continue
            full_url = urljoin(base_url, href)
            try:
                r = requests.get(full_url, timeout=5)
                if r.status_code == 200:
                    css_text = r.text
                    rules = self.parse_css_rules(css_text)
                    css_rules.update(rules)
                    print(f"[Loaded external CSS: {full_url}]")
                else:
                    print(f"[Failed to load external CSS: {full_url}] status={r.status_code}")
            except Exception as e:
                print(f"[Failed to load external CSS: {href}] {e}")

        print(f"[Loaded {len(css_rules)} CSS rules]")
        return css_rules

    # ------------------- Main HTML Renderer -------------------
    def setHtml(self, html):
        self.clear_layout()

        # Base URL for resolving relative CSS links
        base_url = ""
        if hasattr(self.window(), "url_bar"):
            base_url = self.window().url_bar.text().strip()
        if not base_url.startswith("http"):
            base_url = "https://" + base_url

        # ✅ Load CSS before parsing HTML
        self.css_rules = self.load_external_css(html, base_url)

        parser = TreeHTMLParser()
        parser.feed(html)
        self.root_node = parser.root

        # Apply background color if CSS says so
        if "body" in self.css_rules:
            match = re.search(r'background-color\s*:\s*([^;]+);?', self.css_rules["body"], re.IGNORECASE)
            if match:
                bg_color = match.group(1).strip()
                self.container.setStyleSheet(f"background-color: {bg_color};")
                print(f"[Detected background color: {bg_color}]")

        # Render the HTML elements
        self.render_nodes(self.root_node)

    # ------------------- Loading State -------------------
    def show_loading(self):
        self.clear_layout()
        self.container.setStyleSheet("background-color: #f0f0f0;")
        lbl = QLabel("⏳ Loading...")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("font-size: 18px; color: #555; padding: 20px;")
        self.page_layout.addWidget(lbl)
    
    def safe_render(self, func, *args, **kwargs):
        """Wrapper to prevent a single render failure from crashing everything."""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"[RenderError] {e}")
            placeholder = QLabel(f"[Render error: {str(e)}]")
            placeholder.setStyleSheet("color: red; font-size: 12px;")
            self.page_layout.addWidget(placeholder)

    def _render_single_node(self, child):
        """Render a single HTML node. All previous logic remains EXACTLY the same."""
        tag = child.tag.lower() if child.tag else ""

        if tag in ["style", "head", "textarea"]:
            return

        # ---------------- IMAGE (<img>) ----------------
        if tag == "img":
            src = child.attrs.get("src", "").strip()
            alt = child.attrs.get("alt", "")

            if not src:
                return

            main_window = self.window()
            base_url = getattr(main_window, "url_bar").text().strip()

            # Normalize base_url
            if base_url and not base_url.startswith(("http://", "https://")):
                base_url = "https://" + base_url

            # Resolve relative → absolute
            resolved = urljoin(base_url, src)

            # Fix known patterns (httpcats, wikipedia, etc)
            final_url = self.resolve_image_url(base_url, resolved)
            final_url = self.fix_wikipedia_static_url(final_url, src, base_url)

            print(f"[IMG] raw: {src}")
            print(f"[IMG] base: {base_url}")
            print(f"[IMG] resolved: {resolved}")
            print(f"[IMG] final: {final_url}")

            # Load the image
            try:
                r = requests.get(final_url, timeout=7)
                if r.status_code == 200:
                    from PyQt5.QtGui import QPixmap
                    pix = QPixmap()
                    pix.loadFromData(r.content)

                    img_label = QLabel()

                    # Set natural pixmap first
                    img_label.setPixmap(pix)

                    # KEEP aspect ratio
                    img_label.setScaledContents(False)

                    # Auto-resize QLabel to image's natural size
                    img_label.adjustSize()

                    # Optional: limit huge images (prevent breaking layout)
                    max_width = 600  # you can tune this
                    if pix.width() > max_width:
                        scaled = pix.scaledToWidth(max_width, Qt.SmoothTransformation)
                        img_label.setPixmap(scaled)

                    img_label.setStyleSheet("margin: 8px;")
                    self.page_layout.addWidget(img_label)
                else:
                    print(f"[IMG] Failed: status {r.status_code}")
            except Exception as e:
                print(f"[IMG] Error loading image: {e}")

            return

        # ---------------- BUTTON ----------------
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
                QPushButton:hover { background-color: #e6e6e6; }
                QPushButton:pressed { background-color: #d9d9d9; }
            """)
            if "style" in child.attrs:
                button.setStyleSheet(button.styleSheet() + "\n" + child.attrs["style"])
            self.apply_css(button, tag, child)

            def find_form(n):
                while n:
                    if n.tag == "form":
                        return n
                    n = n.parent
                return None

            def on_button_clicked():
                form_node = find_form(child)
                if form_node:
                    self.submit_form(form_node)
                else:
                    print(f"[Clicked <button>: {text}] (no form found)")

            button.clicked.connect(on_button_clicked)
            self.page_layout.addWidget(button)
            return

        # ---------------- INPUT ----------------
        if tag == "input":
            input_type = (child.attrs.get("type") or "").strip().lower() or "text"

            if input_type in ["text", "search", "hidden"]:
                entry = QLineEdit()
                entry.setPlaceholderText(child.attrs.get("placeholder", child.attrs.get("title", "")))
                entry.setText(child.attrs.get("value", ""))
                entry.setFixedWidth(300)
                entry.setStyleSheet("""
                    QLineEdit {
                        border: 2px solid #aaa;
                        border-radius: 4px;
                        padding: 6px;
                        font-size: 14px;
                        background-color: #fff;
                        color: #000;
                    }
                    QLineEdit:focus { border-color: #448aff; }
                """)

                if "style" in child.attrs:
                    entry.setStyleSheet(entry.styleSheet() + "\n" + child.attrs["style"])

                self.apply_css(entry, tag, child)
                child.attrs["_widget"] = entry
                self.page_layout.addWidget(entry)

                def find_form(n):
                    while n:
                        if n.tag == "form":
                            return n
                        n = n.parent
                    return None

                def on_return_pressed():
                    form_node = find_form(child)
                    if form_node:
                        self.submit_form(form_node, trigger_input=child)
                    else:
                        print("[Enter pressed — no form found]")

                entry.returnPressed.connect(on_return_pressed)
                return

        # ---------------- LINK (<a>) ----------------
        if tag == "a":
            text = child.text or child.attrs.get("href", "")
            href = child.attrs.get("href", "")

            # Render as clickable anchor
            link = QLabel(f"<a href='#'>{text}</a>")
            link.setTextInteractionFlags(Qt.TextBrowserInteraction)
            link.setOpenExternalLinks(False)
            link.setStyleSheet("color: #0066cc; text-decoration: underline;")

            def on_click():
                main_window = self.window()
                base_url = main_window.url_bar.text().strip()

                # Resolve relative → absolute normally
                resolved = urljoin(base_url, href)

                # -----------------------------------------
                # 🦆 DuckDuckGo Lite redirect cleanup
                # -----------------------------------------
                if "duckduckgo.com/l/" in resolved:
                    try:
                        qs = parse_qs(urlparse(resolved).query)
                        if "uddg" in qs:
                            real_url = unquote(qs["uddg"][0])
                            print(f"[DDG] Clean redirect → {real_url}")
                            resolved = real_url
                    except Exception as e:
                        print(f"[DDG] Failed to extract uddg: {e}")

                # Navigate safely
                main_window.url_bar.setText(resolved)
                main_window.goto_url()

            link.mousePressEvent = lambda e: on_click()

            self.apply_css(link, tag, child)
            self.page_layout.addWidget(link)
            return

        # ---------------- TEXT ELEMENTS ----------------
        if tag in ["h1", "h2", "h3", "h4", "h5", "h6", "p", "b", "i", "u"]:
            label = QLabel(child.text)
            label.setWordWrap(True)
            font = label.font()
            size_map = {"h1":36,"h2":32,"h3":28,"h4":24,"h5":20,"h6":16}
            if tag in size_map:
                font.setPointSize(size_map[tag])
                font.setBold(True)
            if tag == "b": font.setBold(True)
            if tag == "i": font.setItalic(True)
            if tag == "u": label.setText(f"<u>{child.text}</u>")

            label.setFont(font)
            self.apply_css(label, tag, child)
            self.page_layout.addWidget(label)
            return

        # ---------------- RAW TEXT ----------------
        if child.text:
            lbl = QLabel(child.text)
            lbl.setWordWrap(True)
            self.apply_css(lbl, tag, child)
            self.page_layout.addWidget(lbl)
            return

    # ------------------- Render HTML Nodes -------------------
    def render_nodes(self, node, depth=0):
        """Crash-safe HTML render loop with recursion protection."""
        if depth > 50:
            print("[Render] Max depth reached, skipping subtree")
            return

        for child in node.children:
            # Render this node safely
            self.safe_render(self._render_single_node, child)

            # Recurse safely
            if child.children:
                self.safe_render(self.render_nodes, child, depth + 1)

    def sanitize_qss(self, css_block: str) -> str:
        """Filter out unsupported CSS properties for Qt (Render-Fallback Mode)."""
        supported_props = [
            "color", "background-color", "font-size", "font-weight", "font-style",
            "border", "border-color", "border-width", "border-radius",
            "padding", "margin", "text-align", "width", "height",
            "min-width", "min-height", "max-width", "max-height",
            "outline", "outline-color", "outline-width",
        ]

        # 🚫 Never hide input/button elements accidentally
        if "display:none" in css_block.replace(" ", "").lower():
            print("[RenderFallback] Ignored 'display:none' to keep form controls visible.")
            return ""

        cleaned_lines = []
        for line in css_block.split(";"):
            line = line.strip()
            if not line:
                continue
            key_val = line.split(":", 1)
            if len(key_val) != 2:
                continue
            prop, val = key_val
            prop = prop.strip().lower()
            if prop in supported_props:
                cleaned_lines.append(f"{prop}: {val.strip()};")
        return "\n".join(cleaned_lines)

    # ------------------- CSS Application -------------------
    def apply_css(self, widget, tag, node):
        """Apply cleaned CSS rules safely, ensuring widgets remain visible."""
        if not hasattr(self, "css_rules"):
            return

        # ✅ Force visibility for key form widgets (so they're never hidden)
        widget.setVisible(True)

        for selector, style in self.css_rules.items():
            safe_style = self.sanitize_qss(style)
            if not safe_style:
                continue

            # Match element type
            if selector == tag:
                widget.setStyleSheet(widget.styleSheet() + "\n" + safe_style)

            # Match CSS class
            elif selector.startswith(".") and selector[1:] in node.attrs.get("class", "").split():
                widget.setStyleSheet(widget.styleSheet() + "\n" + safe_style)

            # Match ID
            elif selector.startswith("#") and selector[1:] == node.attrs.get("id", ""):
                widget.setStyleSheet(widget.styleSheet() + "\n" + safe_style)

    def submit_form(self, form_node, trigger_input=None):
        """Manually simulate a <form> submission (no JS needed)."""
        if not form_node:
            print("[Form] No form node found.")
            return

        # ---------------- Collect form inputs ----------------
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

        # ---------------- Extract action + method ----------------
        action = form_node.attrs.get("action", "")
        method = form_node.attrs.get("method", "get").lower().strip() or "get"

        from urllib.parse import urlencode, urljoin
        main_window = self.window()

        base_url = main_window.url_bar.text().strip()
        if not base_url.startswith("http"):
            base_url = "https://" + base_url

        action_url = urljoin(base_url, action or "")

        print(f"[Form] Submitting to: {action_url} ({method.upper()}) with data={data}")

        # ----------------------------------------------------------
        # 🦆 DUCKDUCKGO LITE FIX → FORCE GET
        # DuckDuckGo Lite ignores POST and ALWAYS expects GET query.
        # ----------------------------------------------------------
        if "duckduckgo.com/lite" in action_url:
            print("[DuckDuckGoLite] Forcing GET instead of POST")
            method = "get"

        # ---------------- Handle GET submission ----------------
        if method == "get":
            query = urlencode(data)
            target = f"{action_url}?{query}" if query else action_url
            main_window.url_bar.setText(target)
            main_window.goto_url()
            return

        # ---------------- Handle POST submission ----------------
        print(f"[Form] POST → handing off to loader: {action_url}")

        try:
            # Let MainWindow handle POST requests
            main_window.load_page(action_url, method="POST", data=data)
        except Exception as e:
            print(f"[Form] Failed POST: {e}")
