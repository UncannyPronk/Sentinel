import requests
from urllib.parse import urlparse, unquote

def _get_base_domain(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host.lower()
    return ".".join(parts[-2:]).lower()

def _is_ascii_hostname(host: str) -> bool:
    if not host:
        return False
    try:
        return host.isascii() and not host.lower().startswith("xn--")
    except Exception:
        return False

def is_ascii_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host.isascii() or host.lower().startswith("xn--"):
            return False
        return all(ord(ch) < 128 for ch in parsed.path + parsed.query)
    except Exception:
        return False

def is_cross_domain_submit(base_url: str, target_url: str) -> bool:
    try:
        target_url = unquote(target_url or "")
        base = urlparse(base_url)
        target = urlparse(target_url)
        if not target.netloc:
            return False
        base_host = (base.hostname or "").lower().lstrip("www.")
        target_host = (target.hostname or "").lower().lstrip("www.")
        if base_host == target_host or target_host.endswith("." + base_host) or base_host.endswith("." + target_host):
            return False
        if not all(ord(c) < 128 for c in target_host):
            return True
        if target_host.startswith("xn--"):
            return True
        base_parts = base_host.split(".")
        target_parts = target_host.split(".")
        if len(base_parts) >= 2 and len(target_parts) >= 2:
            base_root = ".".join(base_parts[-2:])
            target_root = ".".join(target_parts[-2:])
            if base_root != target_root:
                return True
        return False
    except Exception:
        return False

def is_suspicious_domain(domain: str) -> bool:
    if not domain:
        return False
    domain = domain.lower()
    suspicious_keywords = ["login", "verify", "update", "secure", "signin", "account", "password"]
    known_brands = ["google", "facebook", "instagram", "paypal", "twitter", "amazon"]
    for brand in known_brands:
        for word in suspicious_keywords:
            if brand in domain and word in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
                return True
    for brand in known_brands:
        if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
            return True
    return False

blocklist_sources = [
    "https://someonewhocares.org/hosts/zero/hosts",
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://mirror.cedia.org.ec/malwaredomains/justdomains",
    "https://urlhaus.abuse.ch/downloads/text/"
]

blocked_domains = []
for url in blocklist_sources:
    try:
        response = requests.get(url, timeout=4)
        if response.status_code == 200:
            for line in response.text.splitlines():
                if line and not line.startswith("#") and not line.startswith("127.") and not line.startswith("::1"):
                    parts = line.split()
                    domain = parts[-1] if len(parts) > 0 else None
                    if domain and "." in domain:
                        blocked_domains.append(domain)
    except:
        pass

AD_DOMAINS = {
    "doubleclick.net", "googlesyndication.com", "adservice.google.com",
    "ads.yahoo.com", "taboola.com", "outbrain.com", "revcontent.com",
    "facebook.net", "scorecardresearch.com"
}
blocked_domains.extend(AD_DOMAINS)

def check_safety(url, blocklist=[]):
    return any(bad_url in url for bad_url in blocklist)
