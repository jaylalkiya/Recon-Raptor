# web-enum

Web enumeration wrapper scripts for Kali Linux. Chains common recon tools
(nmap, whatweb, curl, gobuster/feroxbuster, nikto) and saves each step's output
to a per-target results folder.

> **Authorized use only.** Run these only against systems you own or have
> explicit written permission to test. Unauthorized scanning is illegal.

## Files

| File          | What it does                                              |
|---------------|----------------------------------------------------------|
| `web-enum.sh` | Full script: reachability check (with HTTPS auto-probe), DNS/whois, subdomain enum, nmap, HTTP fingerprint, robots, dir brute, nikto, nuclei, plus a `00_summary.txt` roll-up. Per-step timeouts; skips any missing tool gracefully; **resumes** by skipping steps whose output already exists (`FORCE=1` to redo). Emits **structured output** (nmap XML, nikto JSON, nuclei JSONL) alongside the human-readable text. |
| `oneliner.sh` | Compact chain (subdomains + nuclei) for quick runs; guards each tool. |
| `web-enum-gui.py` | Hacker-themed Tkinter GUI (Scan / Dashboard / Results tabs): presets, an **options** panel (wordlist, timeouts, force re-scan), colour-coded live output, findings dashboard by severity, one-click HTML report. Wraps `web-enum.sh`. |
| `report.py` | Parses a results folder (preferring structured tool output, falling back to text), ranks findings by severity, and renders a self-contained HTML report plus a machine-readable `report.json`. Usable from the GUI or standalone. |
| `tests/` | `unittest` suite for `report.py`'s parsers (`python3 -m unittest discover -s tests`). |

## Usage

```bash
chmod +x web-enum.sh oneliner.sh

# Full run
./web-enum.sh example.com
./web-enum.sh https://10.10.10.10 results/box1

# Quick one-liner
./oneliner.sh 10.10.10.10

# GUI (desktop app)
python3 web-enum-gui.py
```

Results are written under `results/<host>/`.

## GUI

`web-enum-gui.py` is a dark, terminal-style front-end for `web-enum.sh` with two tabs:

**Scan tab**
- Enter the **target** (Enter key runs it) and, optionally, an **output dir**.
- One-click **presets** — `Quick` (http/nmap/dirb), `Recon` (dns/subs/http), `Full` (everything) — or tick individual **scan steps** (All / None buttons too).
- **Run** streams **colour-coded** output live with an elapsed **timer**; **Stop** SIGTERMs the whole process group and escalates to SIGKILL if it hangs.

**Dashboard tab** — see what matters, ranked:
- Three priority cards — **HIGH PRIORITY** (critical + high), **MEDIUM**, **LOW / INFO** — plus per-severity tiles and asset counts (open ports, subdomains, live hosts).
- A **findings table ordered by severity** (colour-coded), parsed from Nuclei, Nikto, and HTTP security-header checks.
- **📄 Generate HTML report** writes a self-contained, styled `report.html` into the target folder; **Open report** opens it in your browser.

**Results tab** — no more opening 12 files by hand:
- Pick a **target** from the dropdown; every output file is listed with a friendly name (empty files marked `∅`).
- Click any file to **read it inline**, colour-coded (findings highlighted). The `00_summary.txt` opens automatically.
- **⟳ Refresh** rescans the folder (auto-refreshes when a scan finishes); **Open folder** opens it in your file manager.

### HTML report (also standalone)

```bash
# after a scan, build a ranked HTML report (also writes report.json beside it)
python3 report.py results/example.com          # -> results/example.com/report.{html,json}
python3 report.py results/example.com out.html  # custom path (+ out.json)
python3 report.py results/example.com --json    # JSON only, no HTML
```

`report.py` prefers structured tool output when present — `04_nmap.xml`,
`10_nikto.json`, `11_nuclei.jsonl` — and falls back to parsing the plain-text
files, so reports from older result folders still work.

The report groups findings into **HIGH PRIORITY / MEDIUM / LOW-INFO** buckets so you
can see at a glance what to act on first, and lists open ports, subdomains and live hosts.

It works by setting the `RUN_STEPS` env var (comma-separated tokens
`dns,subs,nmap,http,dirb,nikto,nuclei`, or `all`) which `web-enum.sh` reads —
so the CLI honors it too:

```bash
RUN_STEPS=nmap,nuclei ./web-enum.sh target.tld
```

Requires `python3-tk` (`sudo apt install python3-tk` — usually preinstalled on Kali).

## Requirements (all standard on Kali)

- `nmap`, `whatweb`, `curl`, `nikto`
- `gobuster` or `feroxbuster` for content discovery
- `dnsutils` / `whois` for DNS lookups
- `subfinder` / `assetfinder` (passive) or `ffuf` (active DNS brute) + `httpx` for subdomain enum
- `nuclei` for template-based vuln scanning (run `nuclei -update-templates` first)
- Wordlist at `/usr/share/wordlists/dirb/common.txt` (override with `WL_DIR=...`)
- Subdomain wordlist for the ffuf fallback (override with `SUB_WL=...`)

## Customizing

```bash
# Use a different wordlist
WL_DIR=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt ./web-enum.sh target.tld

# Tune timeouts (seconds): per-request network timeout, hard cap per step,
# and nikto's own scan budget
NET_TIMEOUT=30 STEP_TIMEOUT=900 NIKTO_TIMEOUT=300 ./web-enum.sh target.tld

# Resume a partial run (skips steps whose output already exists) ...
./web-enum.sh target.tld
# ... or force a full re-scan, overwriting previous output
FORCE=1 ./web-enum.sh target.tld
```

Every run also appends a line to `results/<host>/.runs.log` (timestamp, steps,
resolved URL) so you have a simple history of what was scanned when.

Every run also writes `results/<host>/00_summary.txt` — a quick roll-up of
subdomains, live hosts, open ports and Nuclei findings.
