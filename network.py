import re, requests
from PyQt5.QtCore import QThread, pyqtSignal

def sanitize_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http"):
        url = "https://" + url
    return url

def remove_ads_from_html(html):
    html = re.sub(r'<iframe[^>]+ad[^>]*>.*?</iframe>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<img[^>]+ad[^>]*>', '', html, flags=re.IGNORECASE)
    return html

blocklist_sources = [
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
]
blocked_domains = []
for url in blocklist_sources:
    try:
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            for line in r.text.splitlines():
                if line and not line.startswith("#") and "." in line:
                    blocked_domains.append(line.split()[-1])
    except:
        pass

def check_safety(url, blocklist):
    return any(bad in url for bad in blocklist)

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
