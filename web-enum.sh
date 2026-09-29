#!/usr/bin/env bash
#
# web-enum.sh - One-liner-friendly web enumeration wrapper for Kali Linux
#
# Purpose: Automate common recon steps against an authorized web target.
# Usage:   ./web-enum.sh <target> [output_dir]
#          ./web-enum.sh example.com
#          ./web-enum.sh https://10.10.10.10 results/box1
#
# ONLY run this against systems you own or are explicitly authorized to test.
#
set -euo pipefail

# ---------- args ----------
TARGET="${1:-}"
if [[ -z "$TARGET" || "$TARGET" == -* ]]; then
    echo "Usage: $0 <target> [output_dir]"
    echo "Example: $0 example.com"
    exit 1
fi

# Normalise: strip scheme, path, and any trailing port to get a bare host.
HOST="$(echo "$TARGET" | sed -E 's#^https?://##; s#/.*$##')"
# Host without port (for host/whois/dig which don't accept host:port).
HOST_NP="${HOST%%:*}"

# Build a URL form (default to http if no scheme provided).
if [[ "$TARGET" =~ ^https?:// ]]; then
    URL="$TARGET"
else
    URL="http://$TARGET"
fi

OUTDIR="${2:-results/$HOST_NP}"
mkdir -p "$OUTDIR"

# Common wordlists shipped with Kali (adjust if missing)
WL_DIR="${WL_DIR:-/usr/share/wordlists/dirb/common.txt}"
# Wordlist for DNS subdomain brute-forcing (used if passive tools are absent)
SUB_WL="${SUB_WL:-/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt}"

# Per-tool network timeouts (seconds). Override via env if needed.
NET_TIMEOUT="${NET_TIMEOUT:-20}"
STEP_TIMEOUT="${STEP_TIMEOUT:-600}"   # hard cap per long-running step
NIKTO_TIMEOUT="${NIKTO_TIMEOUT:-120}" # nikto's own -maxtime (seconds)

# Resume: skip a step whose output already exists and is non-empty.
# Set FORCE=1 to re-run everything regardless.
FORCE="${FORCE:-0}"

# ---------- helpers ----------
c_ok()   { echo -e "\033[1;32m[+]\033[0m $*"; }
c_info() { echo -e "\033[1;34m[*]\033[0m $*"; }
c_warn() { echo -e "\033[1;33m[!]\033[0m $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

# done_already <outfile> -> true if it exists non-empty and we're not forcing.
done_already() { [[ "$FORCE" != 1 && -s "$OUTDIR/$1" ]]; }

# Wrap a command with `timeout` if available, so no single step can hang forever.
tmo() {
    local secs="$1"; shift
    if have timeout; then
        timeout --signal=TERM --kill-after=10 "$secs" "$@"
    else
        "$@"
    fi
}

# Which steps to run. Comma-separated tokens, or "all" (default).
# Tokens: dns subs nmap http dirb nikto nuclei
RUN_STEPS="${RUN_STEPS:-all}"
want() {
    # want <token> -> true if that step should run
    [[ "$RUN_STEPS" == "all" ]] && return 0
    [[ ",$RUN_STEPS," == *",$1,"* ]] && return 0
    return 1
}

# If the user gave no scheme, prefer HTTPS when it answers (fall back to http).
if [[ ! "$TARGET" =~ ^https?:// ]] && have curl \
   && curl -sS --max-time 5 -o /dev/null "https://$HOST" 2>/dev/null; then
    URL="https://$HOST"
fi

# Append a line to the per-target run history.
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ')  steps=$RUN_STEPS  url=$URL  force=$FORCE" \
    >> "$OUTDIR/.runs.log" 2>/dev/null || true

run() {
    # run "step name" "outfile" cmd...
    local name="$1"; local out="$2"; shift 2
    if done_already "$out"; then
        c_info "Skipping $name -- $out exists (FORCE=1 to redo)."
        return 0
    fi
    if ! have "$1"; then
        c_warn "Skipping $name -- '$1' not installed."
        return 0
    fi
    c_info "$name ..."
    if tmo "$STEP_TIMEOUT" "$@" >"$OUTDIR/$out" 2>&1; then
        c_ok "$name -> $OUTDIR/$out"
    else
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            c_warn "$name TIMED OUT after ${STEP_TIMEOUT}s (partial output in $OUTDIR/$out)"
        else
            c_warn "$name finished with non-zero exit ($rc) (see $OUTDIR/$out)"
        fi
    fi
}

# ---------- banner ----------
echo "=================================================="
echo "  Web Enumeration :: target = $HOST"
echo "  URL   = $URL"
echo "  Out   = $OUTDIR"
echo "  Date  = $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "=================================================="

# ---------- 0. Reachability pre-check ----------
# Quick check so we don't waste minutes on a dead host. Non-fatal: some hosts
# block ping/HTTP but still expose services, so we only warn.
HOST_UP=1
if have curl && curl -sSI --max-time "$NET_TIMEOUT" "$URL" >/dev/null 2>&1; then
    c_ok "Host responds over HTTP."
elif have ping && ping -c1 -W2 "$HOST_NP" >/dev/null 2>&1; then
    c_ok "Host responds to ICMP ping."
else
    HOST_UP=0
    c_warn "Host did not respond to HTTP or ping -- continuing anyway (results may be empty)."
fi

# ---------- 1. DNS / host info ----------
if want dns; then
run "DNS lookup (host)"        "01_host.txt"        host "$HOST_NP"
run "WHOIS"                    "02_whois.txt"       whois "$HOST_NP"
# ANY queries are refused by most modern resolvers (RFC 8482); query the
# useful record types explicitly instead.
if done_already "03_dig.txt"; then
    c_info "Skipping dig -- 03_dig.txt exists (FORCE=1 to redo)."
elif have dig; then
    c_info "dig (A/AAAA/MX/NS/TXT/CNAME) ..."
    {
        for rr in A AAAA MX NS TXT CNAME SOA; do
            echo "; ---- $rr ----"
            dig +noall +answer "$HOST_NP" "$rr"
        done
    } > "$OUTDIR/03_dig.txt" 2>&1 || true
    c_ok "dig -> $OUTDIR/03_dig.txt"
else
    c_warn "Skipping dig -- 'dig' not installed (dnsutils)."
fi
fi

# ---------- 1b. Subdomain enumeration ----------
# Passive first (subfinder / assetfinder), then optional active DNS brute (ffuf).
if want subs && done_already "03b_subdomains.txt"; then
    c_info "Skipping subdomain enum -- 03b_subdomains.txt exists (FORCE=1 to redo)."
elif want subs; then
SUBS_FILE="$OUTDIR/03b_subdomains.txt"
: > "$SUBS_FILE"
if have subfinder; then
    c_info "Subfinder (passive) ..."
    tmo "$STEP_TIMEOUT" subfinder -d "$HOST_NP" -silent 2>/dev/null >> "$SUBS_FILE" || true
    c_ok "subfinder done"
fi
if have assetfinder; then
    c_info "Assetfinder (passive) ..."
    tmo "$STEP_TIMEOUT" assetfinder --subs-only "$HOST_NP" 2>/dev/null >> "$SUBS_FILE" || true
    c_ok "assetfinder done"
fi
if ! have subfinder && ! have assetfinder && have ffuf; then
    if [[ -f "$SUB_WL" ]]; then
        c_info "ffuf DNS brute (active) ..."
        tmo "$STEP_TIMEOUT" ffuf -u "http://FUZZ.$HOST_NP" -w "$SUB_WL" \
            -mc 200,204,301,302,307,401,403 \
            -s 2>/dev/null | sed "s/$/.$HOST_NP/" >> "$SUBS_FILE" || true
        c_ok "ffuf done"
    else
        c_warn "Subdomain wordlist not found: $SUB_WL"
    fi
fi
if [[ -s "$SUBS_FILE" ]]; then
    sort -u "$SUBS_FILE" -o "$SUBS_FILE"
    c_ok "Subdomains ($(wc -l < "$SUBS_FILE")) -> $SUBS_FILE"
    # Probe which discovered hosts are live over HTTP(S)
    if have httpx; then
        c_info "Probing live hosts with httpx ..."
        tmo "$STEP_TIMEOUT" httpx -l "$SUBS_FILE" -silent \
            -o "$OUTDIR/03c_live_hosts.txt" 2>/dev/null || true
        c_ok "live hosts -> $OUTDIR/03c_live_hosts.txt"
    fi
else
    c_warn "No subdomain enumeration tool (subfinder/assetfinder/ffuf) found or no results."
fi
fi  # want subs

# ---------- 2. Port / service scan ----------
# Fast top-ports TCP scan with service+version detection.
if want nmap; then
run "Nmap service scan"        "04_nmap.txt" \
    nmap -sV -sC -T4 --top-ports 1000 -oN /dev/stdout -oX "$OUTDIR/04_nmap.xml" "$HOST_NP"
fi

# ---------- 3. HTTP fingerprinting ----------
if want http; then
run "HTTP headers (curl)"      "05_headers.txt"     curl -sSIL --max-time "$NET_TIMEOUT" "$URL"
run "WhatWeb fingerprint"      "06_whatweb.txt"     whatweb -a 3 "$URL"

# robots.txt / sitemap.xml
c_info "Fetching robots.txt / sitemap.xml ..."
curl -sSL --max-time 15 "$URL/robots.txt"  > "$OUTDIR/07_robots.txt"  2>/dev/null || true
curl -sSL --max-time 15 "$URL/sitemap.xml" > "$OUTDIR/08_sitemap.xml" 2>/dev/null || true
c_ok "robots/sitemap saved"
fi

# ---------- 4. Directory / content discovery ----------
if want dirb; then
if have gobuster; then
    run "Gobuster dir brute" "09_gobuster.txt" \
        gobuster dir -u "$URL" -w "$WL_DIR" -q -t 40 -o /dev/stdout
elif have feroxbuster; then
    run "Feroxbuster" "09_ferox.txt" \
        feroxbuster -u "$URL" -w "$WL_DIR" -q
else
    c_warn "No dir-brute tool (gobuster/feroxbuster) found -- skipping content discovery."
fi
fi  # want dirb

# ---------- 5. Vuln scan (nikto) ----------
if want nikto; then
# Human-readable output goes to 10_nikto.txt (stdout); a structured copy goes to
# 10_nikto.json (-Format json) which report.py prefers when present.
run "Nikto scan" "10_nikto.txt" \
    nikto -h "$URL" -maxtime "${NIKTO_TIMEOUT}s" \
    -o "$OUTDIR/10_nikto.json" -Format json
fi

# ---------- 6. Nuclei template scan ----------
if want nuclei; then
if have nuclei; then
    # Scan the main URL plus any live hosts discovered during subdomain enum.
    NUCLEI_TARGETS="$OUTDIR/11_nuclei_targets.txt"
    { echo "$URL"; [[ -f "$OUTDIR/03c_live_hosts.txt" ]] && cat "$OUTDIR/03c_live_hosts.txt"; } \
        | sort -u > "$NUCLEI_TARGETS"
    # -jsonl writes machine-readable findings to 11_nuclei.jsonl (report.py prefers
    # it); the human-readable/stats stream is still captured to 11_nuclei.txt.
    run "Nuclei scan" "11_nuclei.txt" \
        nuclei -l "$NUCLEI_TARGETS" -severity low,medium,high,critical -stats \
        -jsonl -o "$OUTDIR/11_nuclei.jsonl"
else
    c_warn "Skipping Nuclei -- 'nuclei' not installed (install: nuclei; update: nuclei -update-templates)."
fi
fi  # want nuclei

# ---------- 7. Summary report ----------
# Small human-readable roll-up so you don't have to open every file.
SUMMARY="$OUTDIR/00_summary.txt"
{
    echo "=================================================="
    echo " Web Enumeration Summary"
    echo " Target : $HOST   ($URL)"
    echo " Date   : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo " Host up: $([[ $HOST_UP -eq 1 ]] && echo yes || echo 'unknown/no')"
    echo "=================================================="
    [[ -s "$OUTDIR/03b_subdomains.txt" ]] && \
        echo "Subdomains found : $(wc -l < "$OUTDIR/03b_subdomains.txt")"
    [[ -s "$OUTDIR/03c_live_hosts.txt" ]] && \
        echo "Live hosts       : $(wc -l < "$OUTDIR/03c_live_hosts.txt")"
    if [[ -s "$OUTDIR/04_nmap.txt" ]]; then
        echo "Open ports       :"
        grep -E '^[0-9]+/tcp\s+open' "$OUTDIR/04_nmap.txt" 2>/dev/null | sed 's/^/  /' || true
    fi
    if [[ -s "$OUTDIR/11_nuclei.jsonl" ]]; then
        echo "Nuclei findings  : $(grep -c '^{' "$OUTDIR/11_nuclei.jsonl" 2>/dev/null || echo 0)"
    elif [[ -s "$OUTDIR/11_nuclei.txt" ]]; then
        echo "Nuclei findings  : $(grep -c '\[' "$OUTDIR/11_nuclei.txt" 2>/dev/null || echo 0)"
    fi
    echo "--------------------------------------------------"
    echo "Output files:"
    ls -1 "$OUTDIR" | sed 's/^/  /'
} > "$SUMMARY" 2>&1 || true

# ---------- done ----------
echo "=================================================="
c_ok "Enumeration complete. Results in: $OUTDIR"
c_ok "Summary: $SUMMARY"
cat "$SUMMARY"
echo "=================================================="
