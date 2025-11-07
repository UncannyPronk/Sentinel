import re, requests
from urllib.parse import urljoin

def collect_css(root, base_url=""):
    inline_css, linked_css = [], []
    def walk(node):
        if node.tag == "style" and node.text.strip():
            inline_css.append(node.text.strip())
        elif node.tag == "link" and node.attrs.get("rel") == "stylesheet":
            href = node.attrs.get("href")
            if href:
                if not href.startswith(("http://", "https://")) and base_url:
                    href = urljoin(base_url, href)
                linked_css.append(href)
        for c in node.children:
            walk(c)
    walk(root)
    return inline_css, linked_css

def parse_css_rules(css_text):
    pattern = re.compile(r'([^{]+){([^}]+)}')
    rules = {}
    for selector, body in pattern.findall(css_text):
        rules[selector.strip()] = body.strip()
    return rules

def translate_css_to_qt(css_rules):
    qt_rules = {}
    for selector, body in css_rules.items():
        qt_selector = {
            "body": "*", "html": "*",
            "input": "QLineEdit",
            "button": "QPushButton",
            "p": "QLabel"
        }.get(selector, selector)
        qt_rules[selector] = f"{qt_selector} {{\n{body}\n}}"
    return qt_rules
