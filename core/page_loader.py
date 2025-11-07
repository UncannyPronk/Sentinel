from PyQt5.QtCore import QThread, pyqtSignal
import requests, re
from .utils import remove_ads_from_html

class PageLoader(QThread):
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        try:
            r = requests.get(self.url, timeout=7, headers={"User-Agent": "SentinelBrowser/0.1"})
            if r.status_code == 200:
                html = re.sub(r"<(script).*?>.*?</\1>", "", r.text, flags=re.DOTALL)
                html = remove_ads_from_html(html)
                self.finished.emit(html)
            else:
                self.error.emit(f"<h1>Error {r.status_code}</h1>")
        except Exception as e:
            self.error.emit(f"<h1>Connection Error</h1><p>{e}</p>")
