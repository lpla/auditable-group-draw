#!/usr/bin/env python3
"""Build the dependency-free single-file version of Auditable Group Draw."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"

html = (ROOT / "index.html").read_text(encoding="utf-8")
css = (ROOT / "style.css").read_text(encoding="utf-8").rstrip("\n")
js = (ROOT / "app.js").read_text(encoding="utf-8").rstrip("\n")

html = html.replace(
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'self\'; style-src \'self\';',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'unsafe-inline\';',
)
html = html.replace('  <link rel="stylesheet" href="style.css" />', f"  <style>\n{css}\n  </style>")
html = html.replace('  <script src="app.js"></script>', f"  <script>\n{js}\n  </script>")

DIST.mkdir(exist_ok=True)
out = DIST / "auditable-group-draw.html"
out.write_text(html, encoding="utf-8")
print(out)
