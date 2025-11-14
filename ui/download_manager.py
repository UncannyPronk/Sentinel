import os
import requests
import mimetypes

DOWNLOAD_DIR = os.path.expanduser("~/Downloads/Sentinel")

if not os.path.exists(DOWNLOAD_DIR):
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)

SAFE_EXTS = [
    ".pdf", ".txt", ".csv", ".json", ".xml",
    ".png", ".jpg", ".jpeg", ".gif",
    ".zip", ".tar", ".gz"
]

DANGEROUS_EXTS = [
    ".exe", ".bat", ".cmd", ".sh", ".js",
    ".jar", ".apk", ".msi", ".scr"
]


def sanitize_filename(name: str):
    """Remove unsafe characters and normalize the filename."""
    name = name.replace("/", "_").replace("\\", "_")
    return name.strip() or "downloaded_file"


def guess_filename(url, headers):
    """Extract filename from Content-Disposition or fallback to URL."""
    cd = headers.get("Content-Disposition", "")
    if "filename=" in cd:
        filename = cd.split("filename=")[-1].strip().strip("\"'")
        return sanitize_filename(filename)

    # fallback → get from URL
    name = url.split("/")[-1].split("?")[0] or "file"
    return sanitize_filename(name)


def is_dangerous(filename):
    """Detect if file extension is dangerous."""
    ext = os.path.splitext(filename)[1].lower()
    return ext in DANGEROUS_EXTS


def save_file(response, filename):
    """Save streamed response to disk."""
    path = os.path.join(DOWNLOAD_DIR, filename)

    with open(path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    return path


def download_url(url):
    """Download a URL safely, inspecting headers."""
    try:
        resp = requests.get(url, stream=True, allow_redirects=True, timeout=10)
    except Exception as e:
        return False, f"Network error: {e}", None

    filename = guess_filename(url, resp.headers)

    # block dangerous files
    if is_dangerous(filename):
        return False, f"Blocked dangerous file type: {filename}", None

    # content type detection (fallback)
    content_type = resp.headers.get("Content-Type", "").lower()
    if "text/html" in content_type:
        # not a download
        return False, "Not a file (HTML page)", None

    path = save_file(resp, filename)
    return True, filename, path
