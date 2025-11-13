import os
import re
import requests
from PyQt5.QtWidgets import QMessageBox

SAFE_DIR = os.path.expanduser("~/Downloads/Sentinel")
os.makedirs(SAFE_DIR, exist_ok=True)

DANGEROUS_EXT = {
    ".exe", ".msi", ".bat", ".cmd", ".sh",
    ".apk", ".jar", ".scr", ".dll", ".ps1"
}

def sanitize_filename(name: str) -> str:
    name = name.strip().replace("..", "")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name[:80] or "download"

def detect_filename(response, url):
    # Content-Disposition header
    cd = response.headers.get("Content-Disposition", "")
    match = re.search(r'filename="?([^"]+)"?', cd)
    if match:
        return sanitize_filename(match.group(1))

    # URL basename
    base = os.path.basename(url)
    return sanitize_filename(base)

def is_dangerous(name):
    _, ext = os.path.splitext(name.lower())
    return ext in DANGEROUS_EXT

def download_file(url, parent=None):
    try:
        r = requests.get(url, stream=True, timeout=10)
        if r.status_code != 200:
            QMessageBox.warning(parent, "Download Failed",
                                f"Server returned status {r.status_code}")
            return

        filename = detect_filename(r, url)

        if is_dangerous(filename):
            QMessageBox.warning(
                parent,
                "Blocked Unsafe Download",
                f"Downloading executable files is not allowed:\n\n{filename}"
            )
            return

        save_path = os.path.join(SAFE_DIR, filename)
        with open(save_path, "wb") as f:
            for chunk in r.iter_content(4096):
                f.write(chunk)

        QMessageBox.information(
            parent, "Download Complete",
            f"File saved as:\n{save_path}"
        )

    except Exception as e:
        QMessageBox.warning(parent, "Download Error", str(e))
