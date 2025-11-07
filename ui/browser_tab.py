from PyQt5.QtWidgets import QWidget, QVBoxLayout, QScrollArea
from ui.browser_widget import BrowserWidget

class BrowserTab(QWidget):
    def __init__(self, name="New Tab"):
        super().__init__()
        layout = QVBoxLayout(self)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)

        self.browser = BrowserWidget()
        self.scroll_area.setWidget(self.browser)

        layout.addWidget(self.scroll_area)
