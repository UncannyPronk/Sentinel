from urllib.parse import urlparse, unquote

def is_ascii_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.isascii() and not host.startswith("xn--")
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
        if base_host == target_host:
            return False
        return base_host.split(".")[-2:] != target_host.split(".")[-2:]
    except:
        return False

def is_suspicious_domain(domain: str) -> bool:
    domain = domain.lower()
    suspicious = ["login", "verify", "account", "secure"]
    brands = ["google", "facebook", "paypal", "twitter"]
    for b in brands:
        for s in suspicious:
            if b in domain and s in domain and not domain.endswith(f"{b}.com"):
                return True
    return False
