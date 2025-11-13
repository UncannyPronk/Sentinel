# 🛰️ Sentinel Browser
A Secure, Minimal, JavaScript-Free Browser Engine Built in Python + PyQt5

Sentinel Browser is a lightweight, privacy-focused browser engine written entirely in Python.

It does NOT execute JavaScript, making it ideal for:

- Secure browsing
- Research
- Low-resource systems
- Technical reading
- Security labs
- Testing HTML rendering

Despite being minimal, it supports forms, hyperlinks, images, CSS fallback and safe navigation filtering.

⭐ KEY FEATURES
============================================================

🔐 SECURITY-FIRST DESIGN
- Homograph protection
- Cross-domain form submission detection
- Suspicious domain classifier (phishing detection)
- Blocklist filtering via:
  - StevenBlack
  - Phishing Army
  - URLHaus
- Sanitized hyperlink navigation
- Blocks malicious/malware domains
- ALL JavaScript removed
- CSS sanitized (prevents phishing UI tricks)

------------------------------------------------------------

🖼️ IMAGE RENDERING
- Loads <img> safely
- Wikipedia static URL fixer
- Handles relative + absolute paths
- Preserves aspect ratio
- Supports PNG, JPG, GIF*, SVG*
(*SVG rendered via Qt)

------------------------------------------------------------

🔗 HYPERLINK NAVIGATION
- Full support for <a href="">
- Relative to absolute resolution
- Sanitized before navigation
- Blocks suspicious domains

------------------------------------------------------------

📝 FORM SUBMISSION
- GET → Converts inputs into query string
- POST → Sent via PageLoader
- Hidden input support
- DuckDuckGo Lite redirect support
- Cross-domain POST warnings
- Phishing-safe behavior

------------------------------------------------------------

📄 SAFE HTML RENDERING
Implemented using a custom DOM parser.

Supported tags:
- h1 to h6
- p, b, i, u
- button
- input type="text", search, hidden
- img
- a
- text nodes

Includes:
- Crash-safe HTML renderer
- Error markers instead of crashes

------------------------------------------------------------

🎨 CSS FALLBACK MODE
Allows a safe subset:

Allowed:
- color
- background-color
- font-size, weight, style
- border, border-radius
- padding, margin
- text-align
- basic width / height

Blocked:
- display:none
- absolute / fixed positioning
- flexbox / grid
- opacity
- overlap-based phishing

🧱 ARCHITECTURE
============================================================

Sentinel/
  core/
    page_loader.py        Requests + HTML cleanup + POST handling
    html_parser.py        Custom HTML → DOM tree
    security.py           Domain safety filters, blocklists
    utils.py              Helpers (ad removal, sanitizers)

  ui/
    browser_widget.py     DOM → PyQt widgets
    browser_tab.py        Tab container
    main_window.py        Title bar, URL bar, navigation, tabs

  assets/                 Icons, logo, screenshots

  README.md               This file

🚀 RUNNING THE BROWSER
============================================================

Requirements:
- Python 3.8+
- PyQt5
- requests
- beautifulsoup4

Install:
  pip install PyQt5 requests beautifulsoup4

Run:
  python main.py

🔧 UPCOMING FEATURES
============================================================

Short-term:
- File downloads
- Better SVG rendering
- Support for more input types

Long-term:
- div layout support
- span inline formatting
- Simple CSS box model

🧪 TESTING CHECKLIST
============================================================

Security:
- Homograph detection
- Suspicious domain detection
- Cross-domain POST blocking
- Blocklist filtering
- Sanitized hyperlink navigation
- Ad-domain blocking

Rendering:
- Wikipedia
- DuckDuckGo Lite
- Image-heavy sites
- Form-heavy sites
- Malformed HTML
- Large HTML pages

❤️ WHY SENTINEL EXISTS
============================================================

Modern browsers are huge and opaque.
Sentinel is the opposite:

Minimal, secure, predictable, JavaScript-free.

Ideal for research, education, and cybersecurity experiments.

<!-- ============================================================
👤 AUTHOR
============================================================

Uncanny Pronk


============================================================
📜 LICENSE
============================================================

MIT / GPL / or any license you choose. -->
