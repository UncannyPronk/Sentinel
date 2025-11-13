from PyQt5.QtWidgets import QWidget, QVBoxLayout, QScrollArea
from ui.browser_widget import BrowserWidget, HOME_HTML

class BrowserTab(QWidget):
    def __init__(self, name, load_home=False):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if load_home:
            self.browser = BrowserWidget(HOME_HTML)
            self.browser.current_url = ""
        else:
            self.browser = BrowserWidget("")  # empty tab
            self.browser.current_url = ""

        layout.addWidget(self.browser)
