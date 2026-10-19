import argparse
import json
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser


class ResourceExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []
        self.styles = []
        self.images = []
        self.frames = []
        self.has_inline_script = False
        self.has_inline_style = False
        self.has_event_handlers = False
        self._inline_script_chunks = []
        self._in_script = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        event_attrs = {
            "onclick", "onload", "onmouseover", "onerror",
            "onsubmit", "onfocus", "onblur", "onkeyup", "onchange",
        }
        if event_attrs & set(attrs_dict):
            self.has_event_handlers = True

        if tag == "script":
            src = attrs_dict.get("src")
            if src:
                self.scripts.append(src)
            else:
                self.has_inline_script = True
                self._in_script = True
        elif tag == "link":
            rel = attrs_dict.get("rel", "")
            href = attrs_dict.get("href", "")
            if rel in ("stylesheet", "preload") and href:
                self.styles.append(href)
        elif tag == "style":
            self.has_inline_style = True
        elif tag in ("img", "image"):
            src = attrs_dict.get("src", "")
            if src:
                self.images.append(src)
        elif tag in ("iframe", "frame", "embed", "object"):
            src = attrs_dict.get("src") or attrs_dict.get("data", "")
            if src:
                self.frames.append(src)

    def handle_data(self, data):
        if self._in_script:
            self._inline_script_chunks.append(data)

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    @property
    def inline_script_content(self):
        return "".join(self._inline_script_chunks)

    @property
    def has_eval(self):
        return "eval(" in self.inline_script_content


def _origin(url: str) -> str:
    if url.startswith("//"):
        url = "https:" + url
    if url.startswith("http://") or url.startswith("https://"):
        parts = url.split("/")
        return "/".join(parts[:3])
    return "'self'"


def generate_csp(parser: ResourceExtractor) -> str:
    directives = {}

    script_src = {"'self'"}
    for s in parser.scripts:
        o = _origin(s)
        if o != "'self'":
            script_src.add(o)
    if parser.has_inline_script or parser.has_event_handlers:
        script_src.add("'unsafe-inline'")
    if parser.has_eval:
        script_src.add("'unsafe-eval'")
    directives["script-src"] = sorted(script_src)

    style_src = {"'self'"}
    for s in parser.styles:
        o = _origin(s)
        if o != "'self'":
            style_src.add(o)
    if parser.has_inline_style:
        style_src.add("'unsafe-inline'")
    directives["style-src"] = sorted(style_src)

    img_src = {"'self'", "data:"}
    for s in parser.images:
        o = _origin(s)
        if o != "'self'":
            img_src.add(o)
    directives["img-src"] = sorted(img_src)

    if parser.frames:
        frame_src = {"'self'"}
        for s in parser.frames:
            o = _origin(s)
            if o != "'self'":
                frame_src.add(o)
        directives["frame-src"] = sorted(frame_src)
    else:
        directives["frame-src"] = ["'none'"]

    directives["default-src"] = ["'self'"]

    parts = [f"{k} {' '.join(v)}" for k, v in directives.items()]
    return "; ".join(parts)


def analyze_page(url: str) -> list:
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as resp:
            ct = resp.headers.get("Content-Type", "")
            if "text/html" not in ct:
                return []
            html = resp.read().decode("utf-8", errors="replace")
            existing_csp = resp.headers.get("Content-Security-Policy")
    except Exception:
        return []

    parser = ResourceExtractor()
    parser.feed(html)

    findings = []

    if not existing_csp:
        findings.append({
            "endpoint": url,
            "vulnerability_type": "missing_csp",
            "evidence": "No Content-Security-Policy header present on this page",
            "severity": "high",
            "recommended_csp": generate_csp(parser),
        })

    if parser.has_inline_script:
        findings.append({
            "endpoint": url,
            "vulnerability_type": "inline_script_detected",
            "evidence": "Inline <script> block found — requires 'unsafe-inline' in script-src",
            "severity": "medium",
            "recommended_csp": None,
        })

    if parser.has_event_handlers:
        findings.append({
            "endpoint": url,
            "vulnerability_type": "inline_event_handler",
            "evidence": "Inline event handler attribute detected (e.g. onclick, onload)",
            "severity": "medium",
            "recommended_csp": None,
        })

    if parser.has_eval:
        findings.append({
            "endpoint": url,
            "vulnerability_type": "eval_usage_detected",
            "evidence": "eval() call found in inline script — requires 'unsafe-eval' in script-src",
            "severity": "high",
            "recommended_csp": None,
        })

    external_scripts = [
        s for s in parser.scripts
        if s.startswith("http://") or s.startswith("https://") or s.startswith("//")
    ]
    if external_scripts:
        origins = sorted({_origin(s) for s in external_scripts})
        findings.append({
            "endpoint": url,
            "vulnerability_type": "external_script_sources",
            "evidence": f"Scripts loaded from {len(external_scripts)} external source(s): {', '.join(origins)}",
            "severity": "low",
            "recommended_csp": None,
        })

    return findings


def main():
    ap = argparse.ArgumentParser(description="Content Security Policy Generator")
    ap.add_argument("--target", default="http://localhost:3000", help="Target base URL")
    args = ap.parse_args()

    target = args.target.rstrip("/")

    try:
        req = urllib.request.Request(f"{target}/pages")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            pages = data.get("pages", [])
    except Exception:
        print(json.dumps({
            "target": target,
            "findings": [],
            "summary": "Could not reach target server",
        }))
        return

    all_findings = []
    for page_path in pages:
        page_url = f"{target}{page_path}"
        print(f"Analyzing {page_url} ...", file=sys.stderr)
        page_findings = analyze_page(page_url)
        all_findings.extend(page_findings)

    high = sum(1 for f in all_findings if f["severity"] == "high")
    medium = sum(1 for f in all_findings if f["severity"] == "medium")
    low = sum(1 for f in all_findings if f["severity"] == "low")

    result = {
        "target": target,
        "findings": all_findings,
        "summary": (
            f"Analyzed {len(pages)} page(s). "
            f"Found {len(all_findings)} issue(s): "
            f"{high} high, {medium} medium, {low} low."
        ),
    }

    print(json.dumps(result, indent=2))
    print(
        f"\nSummary: {len(all_findings)} findings across {len(pages)} pages "
        f"({high} high, {medium} medium, {low} low)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
