from html.parser import HTMLParser

class Node:
    def __init__(self, tag="", attrs=None, text="", parent=None):
        self.tag = tag
        self.attrs = attrs or {}
        self.text = ""
        self.children = []
        self.parent = parent

class TreeHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.root = Node("root")

    def handle_starttag(self, tag, attrs):
        node = Node(tag.lower(), dict(attrs))
        if self.stack:
            self.stack[-1].children.append(node)
            node.parent = self.stack[-1]
        else:
            self.root.children.append(node)
        self.stack.append(node)

    def handle_endtag(self, tag):
        tag = tag.lower()
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
            self.root.children.append(Node(text=data))
