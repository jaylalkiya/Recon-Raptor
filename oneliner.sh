#!/usr/bin/env bash
# One-liner web enum. Usage: ./oneliner.sh <host>   (authorized targets only)
set -uo pipefail
T="${1:?usage: oneliner.sh <host>}"; O="results/${T%%:*}"; mkdir -p "$O"
have() { command -v "$1" >/dev/null 2>&1; }
WL="${WL_DIR:-/usr/share/wordlists/dirb/common.txt}"

have subfinder && have httpx && subfinder -d "$T" -silent 2>/dev/null | tee "$O/subs.txt" | httpx -silent 2>/dev/null | tee "$O/live.txt"
have whatweb  && whatweb -a3 "http://$T" | tee "$O/whatweb.txt"
have curl     && curl -sSIL --max-time 20 "http://$T" | tee "$O/headers.txt"
have nmap     && nmap -sV -sC -T4 --top-ports 1000 "$T" -oN "$O/nmap.txt"
have gobuster && [[ -f "$WL" ]] && gobuster dir -u "http://$T" -w "$WL" -q -t40 -o "$O/gobuster.txt"
have nikto    && nikto -h "http://$T" -maxtime 120s | tee "$O/nikto.txt"
have nuclei   && { echo "http://$T"; cat "$O/live.txt" 2>/dev/null; } | sort -u | nuclei -severity low,medium,high,critical -o "$O/nuclei.txt"
echo "[+] done -> $O"
