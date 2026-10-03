#!/usr/bin/env python3
"""Build the dependency-free single-file version of Auditable Group Draw."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"

html = (ROOT / "index.html").read_text(encoding="utf-8")
css = (ROOT / "style.css").read_text(encoding="utf-8").rstrip("\n")
js = (ROOT / "app.js").read_text(encoding="utf-8").rstrip("\n")


def csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


style_hash = csp_hash(css)
script_hash = csp_hash(js)
html = html.replace("script-src 'self'", f"script-src 'sha256-{script_hash}'")
html = html.replace("style-src 'self'", f"style-src 'sha256-{style_hash}'")
html = html.replace('  <link rel="stylesheet" href="style.css" />', f"  <style>{css}</style>")
html = html.replace('  <script src="app.js"></script>', f"  <script>{js}</script>")

DIST.mkdir(exist_ok=True)
out = DIST / "auditable-group-draw.html"
out.write_text(html, encoding="utf-8")
print(out)
