#!/usr/bin/env python3
"""
web-enum-gui.py - Hacker-themed Tkinter front-end for web-enum.sh

Two tabs:
  [ Scan ]     enter a target, pick steps/presets, watch live colour output
  [ Results ]  browse every output file per target and read it inline

Authorized targets only. Run only against systems you own or may test.

Usage:  python3 web-enum-gui.py
Needs:  python3-tk  (sudo apt install python3-tk -- usually preinstalled on Kali)
"""
import os
import queue
import signal
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

try:
    import report  # local report.py -- parser + HTML report engine
except Exception:  # pragma: no cover
    report = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(SCRIPT_DIR, "web-enum.sh")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
MAX_VIEW_BYTES = 2_000_000  # don't load huge files fully into the viewer

# ---------- hacker theme palette ----------
BG      = "#0a0e0a"   # near-black
PANEL   = "#0f160f"   # slightly lighter panel
FG      = "#39ff14"   # neon green
FG_DIM  = "#1f8a12"   # dim green
ACCENT  = "#00e5ff"   # cyan accent
WARN    = "#ffb000"   # amber
ERR     = "#ff3860"   # red
INFO    = "#00e5ff"   # cyan
GREY    = "#5a6b5a"
FONT    = ("DejaVu Sans Mono", 10)
FONT_B  = ("DejaVu Sans Mono", 11, "bold")

BANNER = r"""
 __      __      _      _____
 \ \    / /     | |    | ____|_ __  _   _ _ __ ___
  \ \/\/ /  ___ | |__  |  _| | '_ \| | | | '_ ` _ \
   \_/\_/  / -_)| '_ \ | |___| | | | |_| | | | | | |
          \___||_.__/ |_____|_| |_|\__,_|_| |_| |_|
        [ authorized recon only // stay legal ]
"""

# Steps -> the RUN_STEPS env token the script understands (see web-enum.sh).
STEPS = [
    ("DNS / WHOIS", "dns"),
    ("Subdomain enum", "subs"),
    ("Nmap service scan", "nmap"),
    ("HTTP fingerprint", "http"),
    ("Directory brute", "dirb"),
    ("Nikto", "nikto"),
    ("Nuclei", "nuclei"),
]

# One-click presets -> which tokens they enable.
PRESETS = {
    "Quick":  ["http", "nmap", "dirb"],
    "Recon":  ["dns", "subs", "http"],
    "Full":   [t for _, t in STEPS],
}

# Friendly labels for the output files.
FILE_LABELS = {
    "00_summary.txt": "★ summary",
    "01_host.txt": "host lookup",
    "02_whois.txt": "whois",
    "03_dig.txt": "dig records",
    "03b_subdomains.txt": "subdomains",
    "03c_live_hosts.txt": "live hosts",
    "04_nmap.txt": "nmap",
    "04_nmap.xml": "nmap (xml)",
    "05_headers.txt": "http headers",
    "06_whatweb.txt": "whatweb",
    "07_robots.txt": "robots.txt",
    "08_sitemap.xml": "sitemap.xml",
    "09_gobuster.txt": "gobuster",
    "09_ferox.txt": "feroxbuster",
    "10_nikto.txt": "nikto",
    "10_nikto.json": "nikto (json)",
    "11_nuclei.txt": "nuclei",
    "11_nuclei.jsonl": "nuclei (jsonl)",
    "11_nuclei_targets.txt": "nuclei targets",
    "report.html": "◆ html report",
    "report.json": "◆ json report",
    ".runs.log": "run history",
}


class EnumGUI:
    def __init__(self, root):
        self.root = root
        self.proc = None
        self.reader = None
        self.q = queue.Queue()
        self.start_time = None
        self.cur_target_dir = None
        self.file_index = []  # parallel to listbox rows: absolute paths

        root.title("Web Enum // recon console")
        root.geometry("960x760")
        root.minsize(800, 600)
        root.configure(bg=BG)

        self._init_style()

        # --- banner ---
        tk.Label(root, text=BANNER, font=("DejaVu Sans Mono", 9),
                 fg=FG, bg=BG, justify="left", anchor="w").pack(fill="x", padx=10, pady=(6, 0))

        # --- tabs ---
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=6)
        self.scan_tab = tk.Frame(self.nb, bg=BG)
        self.res_tab = tk.Frame(self.nb, bg=BG)
        self.dash_tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(self.scan_tab, text="  Scan  ")
        self.nb.add(self.dash_tab, text="  Dashboard  ")
        self.nb.add(self.res_tab, text="  Results  ")
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab)

        self._build_scan_tab()
        self._build_dashboard_tab()
        self._build_results_tab()

        # --- status bar ---
        self.status = tk.Label(root, text="● idle", anchor="w", font=FONT,
                               fg=FG_DIM, bg=PANEL, relief="flat", padx=8)
        self.status.pack(fill="x", side="bottom")

        root.after(100, self.drain)
        root.after(500, self._tick)
        root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- style ----------
    def _init_style(self):
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure("Hack.TButton", background=PANEL, foreground=FG,
                     bordercolor=FG_DIM, focuscolor=BG, font=FONT, padding=6)
        st.map("Hack.TButton",
               background=[("active", FG_DIM)], foreground=[("active", "#000")])
        st.configure("Run.TButton", background=FG_DIM, foreground="#000",
                     font=FONT_B, padding=8)
        st.map("Run.TButton", background=[("active", FG)])
        st.configure("Stop.TButton", background="#4a1020", foreground=ERR,
                     font=FONT_B, padding=8)
        st.map("Stop.TButton", background=[("active", ERR)], foreground=[("active", "#000")])
        # notebook
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=PANEL, foreground=FG_DIM,
                     font=FONT_B, padding=(14, 6))
        st.map("TNotebook.Tab", background=[("selected", FG_DIM)],
               foreground=[("selected", "#000")])
        st.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                     foreground=FG, arrowcolor=FG)
        # findings treeview
        st.configure("Hack.Treeview", background="#050805", fieldbackground="#050805",
                     foreground=FG, rowheight=24, font=FONT, borderwidth=0)
        st.configure("Hack.Treeview.Heading", background=PANEL, foreground=FG,
                     font=FONT_B, relief="flat")
        st.map("Hack.Treeview", background=[("selected", FG_DIM)],
               foreground=[("selected", "#000")])

    # ================= SCAN TAB =================
    def _build_scan_tab(self):
        root = self.scan_tab
        pad = {"padx": 10, "pady": 5}

        top = tk.Frame(root, bg=BG)
        top.pack(fill="x", **pad)
        tk.Label(top, text="target>", font=FONT_B, fg=ACCENT, bg=BG).pack(side="left")
        self.target = tk.Entry(top, font=FONT, bg=PANEL, fg=FG, insertbackground=FG,
                               relief="flat", highlightthickness=1,
                               highlightbackground=FG_DIM, highlightcolor=FG)
        self.target.pack(side="left", fill="x", expand=True, padx=8, ipady=4)
        self.target.insert(0, "example.com")
        self.target.bind("<Return>", lambda e: self.start())

        tk.Label(top, text="out>", font=FONT_B, fg=ACCENT, bg=BG).pack(side="left")
        self.outdir = tk.Entry(top, width=18, font=FONT, bg=PANEL, fg=FG,
                               insertbackground=FG, relief="flat", highlightthickness=1,
                               highlightbackground=FG_DIM, highlightcolor=FG)
        self.outdir.pack(side="left", padx=8, ipady=4)

        pre = tk.Frame(root, bg=BG)
        pre.pack(fill="x", **pad)
        tk.Label(pre, text="presets:", font=FONT, fg=GREY, bg=BG).pack(side="left")
        for name in PRESETS:
            ttk.Button(pre, text=name, style="Hack.TButton",
                       command=lambda n=name: self.apply_preset(n)).pack(side="left", padx=4)
        ttk.Button(pre, text="All", style="Hack.TButton",
                   command=lambda: self.toggle(True)).pack(side="left", padx=(16, 4))
        ttk.Button(pre, text="None", style="Hack.TButton",
                   command=lambda: self.toggle(False)).pack(side="left", padx=4)

        box = tk.LabelFrame(root, text=" scan steps ", font=FONT, fg=FG, bg=BG,
                            bd=1, relief="groove", labelanchor="nw")
        box.pack(fill="x", **pad)
        self.vars = {}
        for i, (label, token) in enumerate(STEPS):
            v = tk.BooleanVar(value=True)
            self.vars[token] = v
            tk.Checkbutton(box, text=label, variable=v, font=FONT, fg=FG, bg=BG,
                           selectcolor=PANEL, activebackground=BG, activeforeground=ACCENT,
                           highlightthickness=0, anchor="w").grid(
                row=i // 4, column=i % 4, sticky="w", padx=10, pady=4)

        # --- advanced options (map to env vars web-enum.sh reads) ---
        opt = tk.LabelFrame(root, text=" options ", font=FONT, fg=FG, bg=BG,
                            bd=1, relief="groove", labelanchor="nw")
        opt.pack(fill="x", **pad)

        def _mk_entry(parent, label, default, width):
            tk.Label(parent, text=label, font=FONT, fg=GREY, bg=BG).pack(side="left")
            e = tk.Entry(parent, width=width, font=FONT, bg=PANEL, fg=FG,
                         insertbackground=FG, relief="flat", highlightthickness=1,
                         highlightbackground=FG_DIM, highlightcolor=FG)
            e.insert(0, default)
            e.pack(side="left", padx=(4, 14), ipady=2)
            return e

        row1 = tk.Frame(opt, bg=BG)
        row1.pack(fill="x", padx=8, pady=4)
        self.wl_entry = _mk_entry(row1, "wordlist:",
                                  "/usr/share/wordlists/dirb/common.txt", 40)
        row2 = tk.Frame(opt, bg=BG)
        row2.pack(fill="x", padx=8, pady=(0, 4))
        self.net_to = _mk_entry(row2, "net timeout(s):", "20", 6)
        self.step_to = _mk_entry(row2, "step timeout(s):", "600", 7)
        self.force_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="force re-scan (ignore cached results)",
                       variable=self.force_var, font=FONT, fg=FG, bg=BG,
                       selectcolor=PANEL, activebackground=BG,
                       activeforeground=ACCENT, highlightthickness=0).pack(
            side="left", padx=6)

        btns = tk.Frame(root, bg=BG)
        btns.pack(fill="x", **pad)
        self.run_btn = ttk.Button(btns, text="▶  RUN", style="Run.TButton", command=self.start)
        self.run_btn.pack(side="left")
        self.stop_btn = ttk.Button(btns, text="■  STOP", style="Stop.TButton",
                                   command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        ttk.Button(btns, text="Clear", style="Hack.TButton",
                   command=self.clear).pack(side="left", padx=8)
        ttk.Button(btns, text="View results ▶", style="Hack.TButton",
                   command=self._goto_results).pack(side="right")

        self.out = scrolledtext.ScrolledText(
            root, wrap="word", bg="#050805", fg=FG, insertbackground=FG,
            font=FONT, relief="flat", highlightthickness=1,
            highlightbackground=FG_DIM, padx=8, pady=6)
        self.out.pack(fill="both", expand=True, **pad)
        self._config_tags(self.out)
        self.log("[*] Ready. Enter a target and hit RUN (or press Enter).\n", "info")
        self.log("[!] Authorized targets only.\n\n", "warn")

    # ================= RESULTS TAB =================
    def _build_results_tab(self):
        root = self.res_tab
        pad = {"padx": 10, "pady": 5}

        bar = tk.Frame(root, bg=BG)
        bar.pack(fill="x", **pad)
        tk.Label(bar, text="target>", font=FONT_B, fg=ACCENT, bg=BG).pack(side="left")
        self.res_target = ttk.Combobox(bar, state="readonly", font=FONT, width=40)
        self.res_target.pack(side="left", padx=8)
        self.res_target.bind("<<ComboboxSelected>>", lambda e: self._load_file_list())
        ttk.Button(bar, text="⟳ Refresh", style="Hack.TButton",
                   command=self._refresh_targets).pack(side="left", padx=4)
        ttk.Button(bar, text="Open folder", style="Hack.TButton",
                   command=self.open_results).pack(side="right")

        body = tk.Frame(root, bg=BG)
        body.pack(fill="both", expand=True, **pad)

        # left: file list
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="y")
        tk.Label(left, text="files", font=FONT, fg=GREY, bg=BG, anchor="w").pack(fill="x")
        self.file_list = tk.Listbox(left, width=26, font=FONT, bg=PANEL, fg=FG,
                                    selectbackground=FG_DIM, selectforeground="#000",
                                    highlightthickness=1, highlightbackground=FG_DIM,
                                    relief="flat", activestyle="none")
        self.file_list.pack(fill="y", expand=True, pady=(2, 0))
        self.file_list.bind("<<ListboxSelect>>", lambda e: self._show_selected_file())

        # right: content viewer
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))
        self.res_title = tk.Label(right, text="select a file", font=FONT_B,
                                  fg=ACCENT, bg=BG, anchor="w")
        self.res_title.pack(fill="x")
        self.viewer = scrolledtext.ScrolledText(
            right, wrap="none", bg="#050805", fg=FG, insertbackground=FG,
            font=FONT, relief="flat", highlightthickness=1,
            highlightbackground=FG_DIM, padx=8, pady=6)
        self.viewer.pack(fill="both", expand=True, pady=(2, 0))
        self._config_tags(self.viewer)

        self._refresh_targets()

    # ================= DASHBOARD TAB =================
    def _build_dashboard_tab(self):
        root = self.dash_tab
        pad = {"padx": 10, "pady": 5}

        bar = tk.Frame(root, bg=BG)
        bar.pack(fill="x", **pad)
        tk.Label(bar, text="target>", font=FONT_B, fg=ACCENT, bg=BG).pack(side="left")
        self.dash_target = ttk.Combobox(bar, state="readonly", font=FONT, width=38)
        self.dash_target.pack(side="left", padx=8)
        self.dash_target.bind("<<ComboboxSelected>>", lambda e: self._load_dashboard())
        ttk.Button(bar, text="⟳ Refresh", style="Hack.TButton",
                   command=self._refresh_dashboard).pack(side="left", padx=4)
        ttk.Button(bar, text="📄 Generate HTML report", style="Run.TButton",
                   command=self._gen_report).pack(side="right")
        ttk.Button(bar, text="Open report", style="Hack.TButton",
                   command=self._open_report).pack(side="right", padx=6)

        # priority summary cards
        self.prio = tk.Frame(root, bg=BG)
        self.prio.pack(fill="x", **pad)
        self.prio_cards = {}
        for key, label, color in (("high", "HIGH PRIORITY", ERR),
                                   ("medium", "MEDIUM", WARN),
                                   ("low", "LOW / INFO", INFO)):
            card = tk.Frame(self.prio, bg=PANEL, highlightthickness=1,
                            highlightbackground=color)
            card.pack(side="left", expand=True, fill="x", padx=4)
            num = tk.Label(card, text="0", font=("DejaVu Sans Mono", 26, "bold"),
                           fg=color, bg=PANEL)
            num.pack(anchor="w", padx=12, pady=(8, 0))
            tk.Label(card, text=label, font=FONT, fg=GREY, bg=PANEL).pack(
                anchor="w", padx=12, pady=(0, 8))
            self.prio_cards[key] = num

        # severity tiles
        tiles = tk.Frame(root, bg=BG)
        tiles.pack(fill="x", **pad)
        self.sev_tiles = {}
        order = ["critical", "high", "medium", "low", "info"]
        colors = ({} if report is None else report.SEV_COLORS)
        for sev in order:
            c = colors.get(sev, FG)
            t = tk.Frame(tiles, bg=PANEL, highlightthickness=1, highlightbackground=c)
            t.pack(side="left", padx=4)
            n = tk.Label(t, text="0", font=FONT_B, fg=c, bg=PANEL, width=6)
            n.pack(padx=8, pady=(6, 0))
            tk.Label(t, text=sev.upper(), font=("DejaVu Sans Mono", 8),
                     fg=GREY, bg=PANEL).pack(padx=8, pady=(0, 6))
            self.sev_tiles[sev] = n

        # asset counts line
        self.assets_lbl = tk.Label(root, text="", font=FONT, fg=FG_DIM, bg=BG, anchor="w")
        self.assets_lbl.pack(fill="x", padx=12)

        # findings table
        tk.Label(root, text="findings — ordered by priority (highest first)",
                 font=FONT, fg=GREY, bg=BG, anchor="w").pack(fill="x", padx=12, pady=(6, 0))
        cols = ("sev", "priority", "source", "name", "detail")
        self.tree = ttk.Treeview(root, columns=cols, show="headings",
                                 style="Hack.Treeview")
        for c, w, hd in (("sev", 80, "Severity"), ("priority", 110, "Priority"),
                         ("source", 80, "Source"), ("name", 160, "Name"),
                         ("detail", 520, "Detail")):
            self.tree.heading(c, text=hd)
            self.tree.column(c, width=w, anchor="w")
        # colour rows by severity
        if report is not None:
            for sev, col in report.SEV_COLORS.items():
                self.tree.tag_configure(sev, foreground=col)
        vsb = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(2, 8))

        if report is None:
            self.assets_lbl.config(
                text="report.py not found — dashboard/report disabled.", fg=ERR)

    def _dash_targets(self):
        if not os.path.isdir(RESULTS_DIR):
            return []
        return sorted(d for d in os.listdir(RESULTS_DIR)
                      if os.path.isdir(os.path.join(RESULTS_DIR, d)))

    def _refresh_dashboard(self):
        targets = self._dash_targets()
        self.dash_target["values"] = targets
        if targets:
            if self.dash_target.get() not in targets:
                self.dash_target.set(targets[-1])
            self._load_dashboard()
        else:
            self.dash_target.set("")
            self._clear_dashboard()

    def _clear_dashboard(self):
        for k in self.prio_cards:
            self.prio_cards[k].config(text="0")
        for s in self.sev_tiles:
            self.sev_tiles[s].config(text="0")
        self.assets_lbl.config(text="No results yet — run a scan first.")
        self.tree.delete(*self.tree.get_children())

    def _load_dashboard(self):
        if report is None:
            return
        name = self.dash_target.get()
        if not name:
            return
        tdir = os.path.join(RESULTS_DIR, name)
        try:
            data = report.parse_results(tdir)
        except Exception as e:
            self.assets_lbl.config(text=f"parse error: {e}", fg=ERR)
            return
        c = data["counts"]
        self.prio_cards["high"].config(text=str(c["critical"] + c["high"]))
        self.prio_cards["medium"].config(text=str(c["medium"]))
        self.prio_cards["low"].config(text=str(c["low"] + c["info"] + c["unknown"]))
        for s in self.sev_tiles:
            self.sev_tiles[s].config(text=str(c.get(s, 0)))
        self.assets_lbl.config(
            text=(f"open ports: {len(data['ports'])}   "
                  f"subdomains: {len(data['subdomains'])}   "
                  f"live hosts: {len(data['live_hosts'])}"), fg=FG_DIM)
        self.tree.delete(*self.tree.get_children())
        bucket = report.PRIORITY_BUCKET
        for f in data["findings"]:
            self.tree.insert("", "end", tags=(f["severity"],), values=(
                f["severity"].upper(),
                bucket.get(f["severity"], "LOW / INFO"),
                f["source"], f["name"],
                f["detail"][:200]))
        if not data["findings"]:
            self.tree.insert("", "end", values=("", "", "", "", "No findings parsed."))

    def _gen_report(self):
        if report is None:
            messagebox.showerror("Unavailable", "report.py not found.")
            return
        name = self.dash_target.get()
        if not name:
            messagebox.showinfo("No target", "No scan results to report on yet.")
            return
        tdir = os.path.join(RESULTS_DIR, name)
        try:
            path = report.generate(tdir)
        except Exception as e:
            messagebox.showerror("Report failed", str(e))
            return
        self.status.config(text=f"● report written: {path}")
        if messagebox.askyesno("Report generated",
                               f"Saved:\n{path}\n\nOpen it in your browser now?"):
            self._open_report()

    def _open_report(self):
        name = self.dash_target.get()
        if not name:
            return
        path = os.path.join(RESULTS_DIR, name, "report.html")
        if not os.path.isfile(path):
            if messagebox.askyesno("No report yet", "Generate it now?"):
                self._gen_report()
            return
        try:
            subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    # ---------- results helpers ----------
    def _refresh_targets(self):
        targets = []
        if os.path.isdir(RESULTS_DIR):
            targets = sorted(
                d for d in os.listdir(RESULTS_DIR)
                if os.path.isdir(os.path.join(RESULTS_DIR, d)))
        self.res_target["values"] = targets
        if targets:
            cur = self.res_target.get()
            if cur not in targets:
                self.res_target.set(targets[-1])
            self._load_file_list()
        else:
            self.res_target.set("")
            self.file_list.delete(0, "end")
            self._view_text("No results yet. Run a scan first.", plain=True)

    def _load_file_list(self):
        name = self.res_target.get()
        if not name:
            return
        self.cur_target_dir = os.path.join(RESULTS_DIR, name)
        self.file_list.delete(0, "end")
        self.file_index = []
        try:
            files = sorted(os.listdir(self.cur_target_dir))
        except OSError:
            files = []
        for f in files:
            path = os.path.join(self.cur_target_dir, f)
            if not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            label = FILE_LABELS.get(f, f)
            marker = "·" if size else "∅"  # empty file marker
            self.file_list.insert("end", f"{marker} {label}")
            self.file_index.append(path)
        self.res_title.config(
            text=f"{name}  ({len(self.file_index)} files){self._last_run(self.cur_target_dir)}")
        # auto-open the summary if present
        for i, p in enumerate(self.file_index):
            if os.path.basename(p) == "00_summary.txt":
                self.file_list.selection_set(i)
                self._show_selected_file()
                break

    def _last_run(self, tdir):
        """Return a '  · last run <ts> (N runs)' suffix from .runs.log, or ''."""
        log = os.path.join(tdir, ".runs.log")
        try:
            with open(log) as fh:
                lines = [l for l in fh.read().splitlines() if l.strip()]
        except OSError:
            return ""
        if not lines:
            return ""
        ts = lines[-1].split()[0]
        return f"   · last run {ts}  ({len(lines)} runs)"

    def _show_selected_file(self):
        sel = self.file_list.curselection()
        if not sel:
            return
        path = self.file_index[sel[0]]
        self.res_title.config(text=os.path.relpath(path, SCRIPT_DIR))
        try:
            size = os.path.getsize(path)
            with open(path, "r", errors="replace") as fh:
                data = fh.read(MAX_VIEW_BYTES)
            if size > MAX_VIEW_BYTES:
                data += f"\n\n[... truncated, file is {size} bytes ...]\n"
            if not data.strip():
                data = "(empty file)"
                self._view_text(data, plain=True)
            else:
                self._view_text(data)
        except Exception as e:
            self._view_text(f"[error reading file: {e}]", plain=True)

    def _view_text(self, text, plain=False):
        self.viewer.delete("1.0", "end")
        if plain:
            self.viewer.insert("end", text, "dim")
        else:
            for line in text.splitlines(keepends=True):
                self.viewer.insert("end", line, self._tag_for(line))
        self.viewer.see("1.0")

    def _goto_results(self):
        self._refresh_targets()
        self.nb.select(self.res_tab)

    def _on_tab(self, _evt):
        sel = self.nb.select()
        if sel == str(self.res_tab):
            self._refresh_targets()
        elif sel == str(self.dash_tab):
            self._refresh_dashboard()

    # ---------- shared tag / colour helpers ----------
    def _config_tags(self, widget):
        widget.tag_config("ok", foreground=FG)
        widget.tag_config("info", foreground=INFO)
        widget.tag_config("warn", foreground=WARN)
        widget.tag_config("err", foreground=ERR)
        widget.tag_config("cmd", foreground=ACCENT, font=FONT_B)
        widget.tag_config("dim", foreground=GREY)

    def _tag_for(self, line):
        s = line.lstrip()
        if s.startswith("[+]"):
            return "ok"
        if s.startswith("[*]"):
            return "info"
        if s.startswith("[!]"):
            return "warn"
        low = s.lower()
        if "timed out" in low or "non-zero" in low or low.startswith("error"):
            return "err"
        if "critical" in low or "[high]" in low:
            return "err"
        if "medium" in low:
            return "warn"
        if line.startswith("$ ") or line.startswith("="):
            return "cmd"
        return "ok"

    # ---------- scan tab actions ----------
    def apply_preset(self, name):
        wanted = set(PRESETS[name])
        for token, v in self.vars.items():
            v.set(token in wanted)
        self.status.config(text=f"● preset: {name}")

    def toggle(self, val):
        for v in self.vars.values():
            v.set(val)

    def clear(self):
        self.out.delete("1.0", "end")

    def log(self, text, tag=None):
        self.out.insert("end", text, tag or self._tag_for(text))
        self.out.see("end")

    # ---------- run / stop ----------
    def start(self):
        if self.proc:
            return
        target = self.target.get().strip()
        if not target or target.startswith("-"):
            messagebox.showwarning("Invalid target", "Enter a valid target host/URL.")
            return
        steps = [t for t, v in self.vars.items() if v.get()]
        if not steps:
            messagebox.showwarning("No steps", "Select at least one scan step.")
            return
        if not os.path.exists(SCRIPT):
            messagebox.showerror("Missing script", f"Cannot find:\n{SCRIPT}")
            return

        cmd = ["bash", SCRIPT, target]
        outdir = self.outdir.get().strip()
        if outdir:
            cmd.append(outdir)

        env = dict(os.environ)
        env["RUN_STEPS"] = ",".join(steps)

        # Advanced options -> env vars web-enum.sh honours. Only set non-empty
        # entries so the script's own defaults still apply when a field is blank.
        wl = self.wl_entry.get().strip()
        if wl:
            env["WL_DIR"] = wl
        net = self.net_to.get().strip()
        if net.isdigit():
            env["NET_TIMEOUT"] = net
        step = self.step_to.get().strip()
        if step.isdigit():
            env["STEP_TIMEOUT"] = step
        env["FORCE"] = "1" if self.force_var.get() else "0"

        self.nb.select(self.scan_tab)
        self.clear()
        self.log(f"$ RUN_STEPS={env['RUN_STEPS']} FORCE={env['FORCE']} "
                 f"{' '.join(cmd)}\n\n", "cmd")
        self.status.config(text=f"● running :: {target}")
        self.run_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.start_time = time.time()

        try:
            self.proc = subprocess.Popen(
                cmd, cwd=SCRIPT_DIR, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, start_new_session=True)
        except Exception as e:
            messagebox.showerror("Launch failed", str(e))
            self.reset_buttons()
            self.proc = None
            return

        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.proc.stdout:
            self.q.put(line)
        self.q.put(None)

    def drain(self):
        try:
            while True:
                item = self.q.get_nowait()
                if item is None:
                    rc = self.proc.wait() if self.proc else -1
                    tag = "ok" if rc == 0 else "err"
                    self.log(f"\n[process exited: {rc}]\n", tag)
                    elapsed = int(time.time() - self.start_time) if self.start_time else 0
                    self.status.config(text=f"● done (exit {rc}) in {elapsed}s -- see Results tab")
                    self.proc = None
                    self.reset_buttons()
                    self._refresh_targets()    # new files ready to browse
                    self._refresh_dashboard()  # new findings ready to view
                else:
                    self.log(item)
        except queue.Empty:
            pass
        self.root.after(100, self.drain)

    def _tick(self):
        if self.proc and self.start_time:
            elapsed = int(time.time() - self.start_time)
            self.status.config(text=f"● running :: {elapsed}s elapsed")
        self.root.after(1000, self._tick)

    def stop(self):
        if not self.proc:
            return
        self.log("\n[!] stopping ...\n", "warn")
        pgid = None
        try:
            pgid = os.getpgid(self.proc.pid)
            os.killpg(pgid, signal.SIGTERM)
        except Exception as e:
            self.log(f"[stop error: {e}]\n", "err")
            return
        self.status.config(text="● stopping ...")
        self.root.after(4000, lambda: self._force_kill(pgid))

    def _force_kill(self, pgid):
        if self.proc and pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL)
                self.log("[!] force-killed (SIGKILL)\n", "err")
            except Exception:
                pass

    def open_results(self):
        path = self.cur_target_dir or RESULTS_DIR
        if not os.path.isdir(path):
            messagebox.showinfo("No results yet", f"Not found:\n{path}")
            return
        try:
            subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def reset_buttons(self):
        self.run_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.start_time = None

    def on_close(self):
        if self.proc:
            if not messagebox.askyesno("Quit", "A scan is running. Stop it and quit?"):
                return
            self.stop()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    EnumGUI(root)
    root.mainloop()
