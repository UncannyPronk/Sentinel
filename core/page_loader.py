from PyQt5.QtCore import QThread, pyqtSignal
import requests, re
from .utils import remove_ads_from_html


class PageLoader(QThread):
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, url, method="GET", data=None):
        super().__init__()
        self.url = url
        self.method = method.upper()
        self.data = data or {}

    def clean_html(self, html):
        """Strip JS, ads, etc."""
        html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)

        html = remove_ads_from_html(html)
        return html

    def run(self):
        try:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }

            session = requests.Session()

            # Follow redirects manually (to catch non-200 intermediate results)
            if self.method == "POST":
                response = session.post(
                    self.url,
                    data=self.data,
                    headers=headers,
                    timeout=10,
                    allow_redirects=True,
                )
            else:
                response = session.get(
                    self.url,
                    headers=headers,
                    timeout=10,
                    allow_redirects=True,
                )

            if not (200 <= response.status_code < 400):
                self.error.emit(f"<h1>Error {response.status_code}</h1>")
                return
            
            raw_html = response.text

            # Extract title BEFORE cleaning
            title_match = re.search(r"<title>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
            self.page_title = title_match.group(1).strip() if title_match else None

            # Clean page
            html = self.clean_html(raw_html)

            print("[PageLoader] len(html) after clean:", len(html))

            if "<input" in html.lower():
                print("[PageLoader] ✓ found <input> tags")
            else:
                print("[PageLoader] ⚠ no <input> tags found!")

            self.finished.emit((html, self.page_title))

        except Exception as e:
            self.error.emit(
                f"<h1>Connection Error</h1><p>{e}</p>"
            )
