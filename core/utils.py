import re
from urllib.parse import urlparse

AD_KEYWORDS = [
    "ads", "ad_", "ad-", "advert", "sponsor", "banner", "promoted",
    "affiliate", "doubleclick", "googlesyndication", "tracking",
    "popunder", "clickserve", "outbrain", "taboola", "metrics"
]

def remove_ads_from_html(html):
    html = re.sub(
        r'<iframe[^>]+(ad|banner|sponsor|doubleclick|googlesyndication)[^>]*>.*?</iframe>',
        '', html, flags=re.DOTALL | re.IGNORECASE
    )
    html = re.sub(
        r'<img[^>]+(ad|promo|sponsor|banner)[^>]*>',
        '', html, flags=re.IGNORECASE
    )
    html = re.sub(
        r'<div[^>]+(id|class)\s*=\s*["\'].*?(%s).*?["\'][^>]*>.*?</div>' % "|".join(AD_KEYWORDS),
        '', html, flags=re.DOTALL | re.IGNORECASE
    )
    html = re.sub(
        r'<script[^>]+(ad|doubleclick|googlesyndication|tracking)[^>]*>.*?</script>',
        '', html, flags=re.DOTALL | re.IGNORECASE
    )
    return html


def sanitize_url(url):
    url = url.strip()
    if not url:
        return None
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url
