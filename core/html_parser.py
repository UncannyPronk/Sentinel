from html.parser import HTMLParser
import re

class Node:
    def __init__(self, tag="", attrs=None, text="", parent=None):
        self.tag = tag
        self.attrs = attrs or {}
        self.text = text or ""
        self.children = []
        self.parent = parent


class TreeHTMLParser(HTMLParser):
    SELF_CLOSING_TAGS = {
        "br", "hr", "img", "input", "meta", "link", "source",
        "embed", "area", "base", "col", "param", "track", "wbr"
    }

    def __init__(self):
        super().__init__()
        self.stack = []
        self.root = Node("root")

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        node = Node(tag, dict(attrs))

        if self.stack:
            parent = self.stack[-1]
            parent.children.append(node)
            node.parent = parent
        else:
            self.root.children.append(node)

        # ✅ Self-closing tags (like <input>, <img>, etc.)
        if tag not in self.SELF_CLOSING_TAGS:
            self.stack.append(node)

    def handle_endtag(self, tag):
        tag = tag.lower()
        # Pop until we find the matching tag
        while self.stack:
            node = self.stack.pop()
            if node.tag == tag:
                return

    def handle_data(self, data):
        data = data.strip()
        if not data:
            return
        if self.stack:
            self.stack[-1].text += data + "\n"
        else:
            # Orphan text directly under root
            self.root.children.append(Node(tag="text", text=data))
