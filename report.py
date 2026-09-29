#!/usr/bin/env python3
"""
report.py - Parse a web-enum results folder, rank findings by severity, and
render a self-contained HTML report.

Standalone usage:
    python3 report.py results/example.com          # writes report.html there
    python3 report.py results/example.com out.html  # custom output path

Also importable:
    import report
    data = report.parse_results(target_dir)   # structured dict
    path = report.generate(target_dir)        # write report.html, return path
"""
import os
import re
import sys
import html
import json
import datetime
import xml.etree.ElementTree as ET

# ---------- severity model ----------
# Order = priority. Lower index == more urgent.
SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEV_WEIGHT = {s: i for i, s in enumerate(SEV_ORDER)}

# Colours reused by both the HTML report and the GUI dashboard.
SEV_COLORS = {
    "critical": "#ff3860",
    "high":     "#ff7a18",
    "medium":   "#ffb000",
    "low":      "#9acd32",
    "info":     "#00e5ff",
    "unknown":  "#5a6b5a",
}

# Which severities count as which action bucket.
PRIORITY_BUCKET = {
    "critical": "HIGH PRIORITY",
    "high":     "HIGH PRIORITY",
    "medium":   "MEDIUM",
    "low":      "LOW / INFO",
    "info":     "LOW / INFO",
    "unknown":  "LOW / INFO",
}

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(s):
    return _ANSI.sub("", s)


def _read(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


# ---------- individual parsers ----------
def parse_nuclei_jsonl(path):
    """Parse nuclei -jsonl output: one JSON object per finding.

    Preferred over scraping the coloured text: immune to format/colour changes.
    Handles both the hyphenated (`template-id`, `matched-at`) and camelCase
    (`templateID`) key spellings nuclei has used across versions.
    """
    findings = []
    for raw in _read(path).splitlines():
        raw = raw.strip()
        if not raw.startswith("{"):
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        info = obj.get("info") or {}
        sev = str(info.get("severity") or "unknown").lower()
        if sev not in SEV_WEIGHT:
            sev = "unknown"
        name = (obj.get("template-id") or obj.get("templateID")
                or info.get("name") or "nuclei")
        detail = (obj.get("matched-at") or obj.get("matched_at")
                  or obj.get("host") or "")
        matcher = obj.get("matcher-name") or obj.get("matcher_name")
        if matcher:
            detail = f"{detail} [{matcher}]".strip()
        findings.append({
            "source": "nuclei", "severity": sev,
            "name": name, "detail": detail, "raw": raw,
        })
    return findings


def parse_nuclei(path):
    """Fallback text parser. Nuclei lines look like:
    [template-id] [http] [severity] url ...   (used only when no JSONL exists)."""
    findings = []
    for raw in _read(path).splitlines():
        line = _strip_ansi(raw).strip()
        if not line.startswith("["):
            continue
        brackets = re.findall(r"\[([^\]]+)\]", line)
        if not brackets:
            continue
        sev = "unknown"
        for b in brackets:
            if b.lower() in SEV_WEIGHT and b.lower() != "unknown":
                sev = b.lower()
                break
        name = brackets[0]
        rest = re.sub(r"^(\[[^\]]*\]\s*)+", "", line).strip()
        url = rest.split()[0] if rest else ""
        findings.append({
            "source": "nuclei", "severity": sev,
            "name": name, "detail": url, "raw": line,
        })
    return findings


# Short acronyms must match as whole words, else substrings cause false
# positives (e.g. "force" contains "rce", "muslq"/"mysql" contains "sql").
_HIGH_WORDS = re.compile(
    r"\b(xss|sql|injection|rce|remote code|traversal|lfi|rfi)\b")
_MED_WORDS = re.compile(
    r"\b(cve|osvdb|outdated|vulnerab\w*|default|backup|phpinfo|admin)\b")
_LOW_WORDS = re.compile(r"\b(header|cookie|clickjack\w*|missing)\b")


def _nikto_severity(low):
    """Nikto has no native severity field -> infer from keywords in the text."""
    if _HIGH_WORDS.search(low):
        return "high"
    if _MED_WORDS.search(low):
        return "medium"
    if _LOW_WORDS.search(low):
        return "low"
    return "info"


def parse_nikto_json(path):
    """Parse nikto -Format json output. Returns None (not []) to signal 'no
    usable JSON here, fall back to text' so an empty scan isn't mistaken for one."""
    text = _read(path)
    if not text.strip():
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    hosts = obj if isinstance(obj, list) else [obj]
    findings = []
    for h in hosts:
        if not isinstance(h, dict):
            continue
        for v in (h.get("vulnerabilities") or []):
            msg = str(v.get("msg") or "").strip()
            url = str(v.get("url") or "").strip()
            body = (msg + (" " + url if url and url not in msg else "")).strip()
            if not body:
                continue
            findings.append({
                "source": "nikto", "severity": _nikto_severity(body.lower()),
                "name": "nikto", "detail": body, "raw": body,
            })
    return findings


def parse_nikto(path):
    """Fallback text parser. Nikto findings start with '+ '."""
    findings = []
    skip = ("target ip", "target hostname", "target port", "start time",
            "end time", "server:", "host(s) tested", "requests:")
    for raw in _read(path).splitlines():
        line = raw.strip()
        if not line.startswith("+ "):
            continue
        body = line[2:].strip()
        low = body.lower()
        if any(low.startswith(s) for s in skip):
            continue
        findings.append({
            "source": "nikto", "severity": _nikto_severity(low),
            "name": "nikto", "detail": body, "raw": body,
        })
    return findings


def parse_headers(path):
    """Flag missing common security headers as low-priority findings."""
    text = _read(path).lower()
    if not text.strip():
        return []
    findings = []
    checks = [
        ("strict-transport-security", "Missing HSTS header (Strict-Transport-Security)"),
        ("content-security-policy", "Missing Content-Security-Policy header"),
        ("x-frame-options", "Missing X-Frame-Options header (clickjacking)"),
        ("x-content-type-options", "Missing X-Content-Type-Options header"),
    ]
    for token, desc in checks:
        if token not in text:
            findings.append({
                "source": "headers", "severity": "low",
                "name": "http-headers", "detail": desc, "raw": desc,
            })
    # Server header leaking version
    m = re.search(r"^server:\s*(.+)$", text, re.MULTILINE)
    if m and any(c.isdigit() for c in m.group(1)):
        findings.append({
            "source": "headers", "severity": "info",
            "name": "http-headers",
            "detail": "Server header reveals software/version: " + m.group(1).strip(),
            "raw": m.group(1).strip(),
        })
    return findings


def parse_nmap_xml(path):
    """Parse nmap -oX output. Returns None if the file is absent/unparsable so
    the caller can fall back to the text scraper."""
    if not (os.path.exists(path) and os.path.getsize(path) > 0):
        return None
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None
    ports = []
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            service = svc.get("name", "") if svc is not None else ""
            version = ""
            if svc is not None:
                version = " ".join(
                    svc.get(a) for a in ("product", "version", "extrainfo")
                    if svc.get(a)).strip()
            ports.append({
                "port": port.get("portid", ""), "proto": port.get("protocol", ""),
                "service": service, "version": version,
            })
    return ports


def parse_nmap(path):
    """Fallback text parser for nmap -oN output."""
    ports = []
    for raw in _read(path).splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", raw.strip())
        if m:
            ports.append({
                "port": m.group(1), "proto": m.group(2),
                "service": m.group(3), "version": m.group(4).strip(),
            })
    return ports


def _lines(path):
    return [l for l in (x.strip() for x in _read(path).splitlines()) if l]


# ---------- top-level parse ----------
def parse_results(target_dir):
    p = lambda f: os.path.join(target_dir, f)
    findings = []

    # Nuclei: prefer structured JSONL, fall back to scraping coloured text.
    nuclei_jsonl = p("11_nuclei.jsonl")
    if os.path.exists(nuclei_jsonl) and os.path.getsize(nuclei_jsonl) > 0:
        findings += parse_nuclei_jsonl(nuclei_jsonl)
    else:
        findings += parse_nuclei(p("11_nuclei.txt"))

    # Nikto: prefer JSON, fall back to '+ ' text lines.
    nikto = parse_nikto_json(p("10_nikto.json"))
    if nikto is None:
        nikto = parse_nikto(p("10_nikto.txt"))
    findings += nikto

    findings += parse_headers(p("05_headers.txt"))
    findings.sort(key=lambda f: SEV_WEIGHT.get(f["severity"], 99))

    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    # Nmap: prefer XML, fall back to text.
    ports = parse_nmap_xml(p("04_nmap.xml"))
    if ports is None:
        ports = parse_nmap(p("04_nmap.txt"))
    subs = _lines(p("03b_subdomains.txt"))
    live = _lines(p("03c_live_hosts.txt"))
    whatweb = _read(p("06_whatweb.txt")).strip()

    return {
        "target": os.path.basename(os.path.normpath(target_dir)),
        "dir": target_dir,
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "findings": findings,
        "counts": counts,
        "ports": ports,
        "subdomains": subs,
        "live_hosts": live,
        "whatweb": whatweb,
    }


# ---------- HTML rendering ----------
def _badge(sev):
    c = SEV_COLORS.get(sev, "#5a6b5a")
    return (f'<span class="badge" style="background:{c}22;color:{c};'
            f'border:1px solid {c}">{html.escape(sev.upper())}</span>')


def render_html(data):
    e = html.escape
    counts = data["counts"]
    high = counts["critical"] + counts["high"]
    med = counts["medium"]
    low = counts["low"] + counts["info"] + counts["unknown"]

    tiles = ""
    for sev in SEV_ORDER[:-1]:
        c = SEV_COLORS[sev]
        n = counts.get(sev, 0)
        dim = "" if n else "opacity:.35;"
        tiles += (f'<div class="tile" style="border-color:{c};{dim}">'
                  f'<div class="num" style="color:{c}">{n}</div>'
                  f'<div class="lbl">{sev.upper()}</div></div>')

    # findings rows
    rows = ""
    if data["findings"]:
        for f in data["findings"]:
            bucket = PRIORITY_BUCKET.get(f["severity"], "LOW / INFO")
            rows += (
                "<tr>"
                f"<td>{_badge(f['severity'])}</td>"
                f"<td class='bucket'>{e(bucket)}</td>"
                f"<td class='src'>{e(f['source'])}</td>"
                f"<td class='name'>{e(f['name'])}</td>"
                f"<td class='detail'>{e(f['detail'])}</td>"
                "</tr>")
    else:
        rows = ("<tr><td colspan='5' class='empty'>No findings parsed "
                "(nuclei/nikto/headers produced nothing to flag).</td></tr>")

    # ports
    port_rows = "".join(
        f"<tr><td>{e(p['port'])}/{e(p['proto'])}</td><td>{e(p['service'])}</td>"
        f"<td>{e(p['version'])}</td></tr>" for p in data["ports"])
    if not port_rows:
        port_rows = "<tr><td colspan='3' class='empty'>No open ports parsed.</td></tr>"

    subs = data["subdomains"]
    live = data["live_hosts"]
    subs_html = "".join(f"<li>{e(s)}</li>" for s in subs[:200]) or "<li class='empty'>none</li>"
    live_html = "".join(f"<li>{e(s)}</li>" for s in live[:200]) or "<li class='empty'>none</li>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon report — {e(data['target'])}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:#0a0e0a; color:#c8f7c0;
         font-family:"DejaVu Sans Mono",ui-monospace,monospace; font-size:14px; }}
  .wrap {{ max-width:1100px; margin:0 auto; padding:24px 16px 64px; }}
  h1 {{ color:#39ff14; font-size:22px; margin:0 0 4px; }}
  h2 {{ color:#39ff14; font-size:16px; margin:32px 0 10px;
        border-bottom:1px solid #1f8a12; padding-bottom:6px; }}
  .meta {{ color:#5a6b5a; margin-bottom:20px; }}
  .prio {{ display:flex; gap:12px; flex-wrap:wrap; margin:16px 0; }}
  .pcard {{ flex:1; min-width:180px; border-radius:8px; padding:14px 16px;
            background:#0f160f; border-left:5px solid; }}
  .pcard .pn {{ font-size:30px; font-weight:bold; }}
  .pcard .pt {{ color:#8aa; font-size:12px; letter-spacing:1px; }}
  .tiles {{ display:flex; gap:10px; flex-wrap:wrap; }}
  .tile {{ background:#0f160f; border:1px solid; border-radius:8px;
           padding:10px 14px; min-width:92px; text-align:center; }}
  .tile .num {{ font-size:24px; font-weight:bold; }}
  .tile .lbl {{ font-size:11px; color:#8aa; letter-spacing:1px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:8px; font-size:13px; }}
  th,td {{ text-align:left; padding:7px 9px; border-bottom:1px solid #14210f;
           vertical-align:top; }}
  th {{ color:#39ff14; border-bottom:1px solid #1f8a12; }}
  tr:hover td {{ background:#0f160f; }}
  .badge {{ font-size:11px; font-weight:bold; padding:2px 8px; border-radius:10px;
            letter-spacing:1px; }}
  .bucket {{ color:#8aa; font-size:11px; white-space:nowrap; }}
  .src {{ color:#00e5ff; }}
  .name {{ color:#9acd32; word-break:break-word; }}
  .detail {{ color:#c8f7c0; word-break:break-word; }}
  .empty {{ color:#5a6b5a; font-style:italic; }}
  .cols {{ display:flex; gap:24px; flex-wrap:wrap; }}
  .col {{ flex:1; min-width:260px; }}
  ul {{ list-style:none; padding:0; margin:0; max-height:320px; overflow:auto;
        background:#0f160f; border:1px solid #14210f; border-radius:6px; }}
  li {{ padding:4px 10px; border-bottom:1px solid #101a10; }}
  .foot {{ margin-top:40px; color:#5a6b5a; font-size:12px; border-top:1px solid #1f8a12;
           padding-top:12px; }}
</style></head>
<body><div class="wrap">
  <h1>▚ Web Enumeration Report</h1>
  <div class="meta">target <b style="color:#39ff14">{e(data['target'])}</b>
     &nbsp;·&nbsp; generated {e(data['generated'])}</div>

  <div class="prio">
    <div class="pcard" style="border-color:#ff3860">
      <div class="pn" style="color:#ff3860">{high}</div>
      <div class="pt">HIGH PRIORITY — act first (critical + high)</div></div>
    <div class="pcard" style="border-color:#ffb000">
      <div class="pn" style="color:#ffb000">{med}</div>
      <div class="pt">MEDIUM — review soon</div></div>
    <div class="pcard" style="border-color:#00e5ff">
      <div class="pn" style="color:#00e5ff">{low}</div>
      <div class="pt">LOW / INFO — note for later</div></div>
  </div>

  <h2>Severity breakdown</h2>
  <div class="tiles">{tiles}</div>

  <h2>Findings — ordered by priority</h2>
  <table>
    <tr><th>Severity</th><th>Priority</th><th>Source</th><th>Name</th><th>Detail</th></tr>
    {rows}
  </table>

  <h2>Open ports &amp; services</h2>
  <table>
    <tr><th>Port</th><th>Service</th><th>Version / info</th></tr>
    {port_rows}
  </table>

  <div class="cols">
    <div class="col"><h2>Subdomains ({len(subs)})</h2><ul>{subs_html}</ul></div>
    <div class="col"><h2>Live hosts ({len(live)})</h2><ul>{live_html}</ul></div>
  </div>

  <div class="foot">
    Generated by web-enum · Authorized testing only — run only against systems you
    own or are explicitly permitted to test.
  </div>
</div></body></html>"""


def generate_json(target_dir, out_path=None, data=None):
    """Write a machine-readable report.json (findings, counts, ports, assets)."""
    data = data if data is not None else parse_results(target_dir)
    out_path = out_path or os.path.join(target_dir, "report.json")
    with open(out_path, "w") as fh:
        json.dump(data, fh, indent=2)
    return out_path


def generate(target_dir, out_path=None, also_json=True):
    data = parse_results(target_dir)
    html_text = render_html(data)
    out_path = out_path or os.path.join(target_dir, "report.html")
    with open(out_path, "w") as fh:
        fh.write(html_text)
    if also_json:
        # Sibling report.json next to the HTML, for pipelines / CI.
        json_path = os.path.splitext(out_path)[0] + ".json"
        generate_json(target_dir, json_path, data=data)
    return out_path


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--json"]
    json_only = "--json" in sys.argv
    if not args:
        print("usage: python3 report.py <results/target_dir> [out.html] [--json]")
        sys.exit(1)
    tdir = args[0]
    if not os.path.isdir(tdir):
        print(f"not a directory: {tdir}")
        sys.exit(1)
    outp = args[1] if len(args) > 1 else None
    d = parse_results(tdir)
    c = d["counts"]
    if json_only:
        jpath = generate_json(tdir, outp, data=d)
        print(f"[+] JSON report: {jpath}")
    else:
        path = generate(tdir, outp)
        print(f"[+] Report: {path}")
        print(f"[+] JSON:   {os.path.splitext(path)[0] + '.json'}")
    print(f"[+] Findings -> critical:{c['critical']} high:{c['high']} "
          f"medium:{c['medium']} low:{c['low']} info:{c['info']}")
    print(f"[+] Open ports: {len(d['ports'])}  subdomains: {len(d['subdomains'])}  "
          f"live: {len(d['live_hosts'])}")
