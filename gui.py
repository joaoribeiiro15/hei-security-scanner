#!/usr/bin/env python3
"""
HEI Security Scanner — GUI
Double-click launch_gui.bat (Windows) or run: python gui.py
Requires: pip install customtkinter
"""

import glob
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import tkinter as tk
import tkinter.ttk as ttk
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

PROJECT_ROOT = Path(__file__).resolve().parent
SOURCE_DIR   = PROJECT_ROOT / "src" / "source"
RESULTS_DIR  = PROJECT_ROOT / "src" / "results"

ctk.set_appearance_mode("System")
# Custom theme: identical to CTk's built-in "blue" theme in dark mode, but
# with the light-mode half of each color pair swapped for one with better
# contrast (default "blue" light mode uses near-equal grays for card vs.
# page background and for disabled-button text vs. its own fill).
_THEME_FILE = PROJECT_ROOT / "assets" / "hei_theme.json"
ctk.set_default_color_theme(str(_THEME_FILE) if _THEME_FILE.exists() else "blue")

# Per-scanner accent colours
_SCANNER_COLORS = {
    "HTTPS / TLS":      "#1a7abf",
    "Security Headers": "#d97706",
    "DNSSEC":           "#7c3aed",
}
_GREEN  = "#2fa572"
_DKGRN  = "#1e8a5e"
_RED    = "#c0392b"
_DKRED  = "#922b21"
_PURP   = "#7c3aed"
_DKPURP = "#5b21b6"

# Matches CTkFrame's themed fg_color exactly. A "transparent" CTkFrame placed
# directly inside a CTkScrollableFrame bakes in a plain (non-tuple) inherited
# background at construction time instead of a live light/dark pair, so it
# never repaints on a later appearance-mode toggle (customtkinter quirk) —
# frames nested inside an already-opaque card aren't affected, only ones
# sitting directly on the scrollable area. Giving those a real tuple here
# sidesteps the bug entirely.
_CARD_BG = ("#ffffff", "gray17")

# Execution and display order (Security Headers → DNSSEC → HTTPS/TLS)
_SCANNER_ORDER = ["Security Headers", "DNSSEC", "HTTPS / TLS"]

_LOG_TO_DISPLAY = {
    "headers": "Security Headers",
    "dnssec":  "DNSSEC",
    "https":   "HTTPS / TLS",
}

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# LLM backend defaults
_LLM_BACKENDS = {
    "LMStudio": {
        "default_host": "127.0.0.1",
        "default_port": "1234",
        "needs_key":    False,
        "needs_url":    False,
    },
    "Ollama": {
        "default_host": "localhost",
        "default_port": "11434",
        "needs_key":    False,
        "needs_url":    False,
    },
    "OpenAI": {
        "default_host": "api.openai.com",
        "default_port": "443",
        "needs_key":    True,
        "needs_url":    False,
    },
    "Custom": {
        "default_host": "localhost",
        "default_port": "8080",
        "needs_key":    False,
        "needs_url":    True,
    },
}

# CSV auto-detect patterns: (subdir, glob_patterns_in_priority_order)
_CSV_PATTERNS = {
    "https":   ("https",   ["*https_consolidate_result*.csv", "*https*scanner*.csv", "*.csv"]),
    "headers": ("headers", ["*sh_final_result*.csv", "*headers*.csv", "*.csv"]),
    "dnssec":  ("dnssec",  ["*dnssec_consolidated_result*.csv", "*dnssec*scanner*.csv", "*.csv"]),
}


class ScannerGUI:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title("HEI Security Scanner")
        self.root.resizable(True, True)
        self.root.minsize(720, 600)
        self.root.geometry("820x920")

        self._proc: subprocess.Popen | None = None
        self._log_queue: queue.Queue = queue.Queue()
        self._running = False
        self._csv_vars: dict[Path, tk.BooleanVar] = {}

        # Per-scanner progress state: display_name -> dict
        self._sp: dict[str, dict] = {}
        self._spinner_idx = 0
        self._spinner_running = False
        # Tracks which scanner ([https/headers/dnssec]) is currently active
        # so per-URL log lines (no bracket prefix) can be attributed correctly.
        self._active_log_name: str | None = None

        # LLM subprocess
        self._llm_proc: subprocess.Popen | None = None
        self._llm_running = False

        self._build_ui()
        self._refresh_csv_list()
        self._poll_queue()

    # ------------------------------------------------------------------ #
    # UI construction                                                       #
    # ------------------------------------------------------------------ #

    def _build_ui(self):
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        is_dark = ctk.get_appearance_mode() == "Dark"
        sash_color = "#3a3a4a" if is_dark else "#c8c8c8"

        self._paned = tk.PanedWindow(
            self.root,
            orient="vertical",
            sashwidth=7,
            sashpad=0,
            sashrelief="flat",
            showhandle=False,
            background=sash_color,
        )
        self._paned.grid(row=0, column=0, sticky="nsew")

        self._upper = ctk.CTkFrame(self._paned, fg_color="transparent", corner_radius=0)
        self._upper.grid_columnconfigure(0, weight=1)
        self._upper.grid_rowconfigure(1, weight=1)

        self._lower = ctk.CTkFrame(self._paned, fg_color="transparent", corner_radius=0)
        self._lower.grid_columnconfigure(0, weight=1)
        self._lower.grid_rowconfigure(0, weight=1)

        self._paned.add(self._upper, stretch="never", minsize=120)
        self._paned.add(self._lower, stretch="always", minsize=120)

        # Header stays outside the tab view
        self._build_header()

        # Tab view: Scanners + LLM Analysis
        self._tabs = ctk.CTkTabview(self._upper, corner_radius=8)
        self._tabs.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))

        scanner_tab = self._tabs.add("⚙  Scanners")
        llm_tab     = self._tabs.add("🤖  LLM Analysis")

        scanner_tab.grid_columnconfigure(0, weight=1)
        scanner_tab.grid_rowconfigure(0, weight=1)
        llm_tab.grid_columnconfigure(0, weight=1)
        llm_tab.grid_rowconfigure(0, weight=1)

        self._scanner_scroll = ctk.CTkScrollableFrame(scanner_tab, fg_color="transparent", corner_radius=0)
        self._scanner_scroll.grid(row=0, column=0, sticky="nsew")
        self._scanner_scroll.grid_columnconfigure(0, weight=1)

        self._llm_scroll = ctk.CTkScrollableFrame(llm_tab, fg_color="transparent", corner_radius=0)
        self._llm_scroll.grid(row=0, column=0, sticky="nsew")
        self._llm_scroll.grid_columnconfigure(0, weight=1)

        self._build_csv_card(self._scanner_scroll)
        self._build_scanners_card(self._scanner_scroll)
        self._build_options_card(self._scanner_scroll)
        self._build_actions(self._scanner_scroll)
        self._build_progress_card(self._scanner_scroll)

        self._build_llm_tab(self._llm_scroll)

        self._build_log_card()
        self._build_sash_handle()

        self.root.after(200, self._bind_scrollwheels)
        self.root.after(150, self._set_initial_sash)

    def _set_initial_sash(self):
        total_h = self.root.winfo_height()
        sash_y = int(total_h * 0.62) if total_h > 100 else 570
        self._paned.sash_place(0, 0, sash_y)
        self.root.after(60, self._reposition_grip)

    def _build_header(self):
        header = ctk.CTkFrame(self._upper, corner_radius=0, fg_color=("#1a5fa8", "#1a3a5c"))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header,
            text="HEI Security Scanner",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="white",
        ).grid(row=0, column=0, padx=18, pady=(14, 2), sticky="w")

        ctk.CTkLabel(
            header,
            text="Security Assessment for European Higher Education Institutions",
            font=ctk.CTkFont(size=11),
            text_color="#a8c8f0",
        ).grid(row=1, column=0, padx=18, pady=(0, 14), sticky="w")

        self._mode_btn = ctk.CTkButton(
            header,
            text="☀ Light" if ctk.get_appearance_mode() == "Dark" else "☾ Dark",
            width=90, height=28,
            fg_color="transparent",
            border_width=1,
            border_color="#4a8abf",
            text_color="white",
            hover_color="#1e5080",
            command=self._toggle_appearance,
        )
        self._mode_btn.grid(row=0, column=2, padx=14, pady=14, sticky="e")

    def _build_csv_card(self, parent):
        csv_card = ctk.CTkFrame(parent, corner_radius=10)
        csv_card.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="ew")
        csv_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            csv_card, text="Input CSV Files", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        ctk.CTkLabel(
            csv_card,
            text="Files found in src/source/ — tick the ones to scan",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).grid(row=1, column=0, padx=14, pady=(0, 6), sticky="w")

        self.csv_scroll = ctk.CTkScrollableFrame(csv_card, height=110, corner_radius=6)
        self.csv_scroll.grid(row=2, column=0, padx=14, pady=(0, 8), sticky="ew")
        self.csv_scroll.grid_columnconfigure(0, weight=1)

        csv_btns = ctk.CTkFrame(csv_card, fg_color="transparent")
        csv_btns.grid(row=3, column=0, padx=10, pady=(0, 12), sticky="w")

        ctk.CTkButton(csv_btns, text="+ Add File…", width=110, command=self._add_csv).pack(side="left", padx=4)
        ctk.CTkButton(csv_btns, text="Remove Selected", width=130,
                      fg_color=_RED, hover_color=_DKRED, command=self._remove_csv).pack(side="left", padx=4)
        ctk.CTkButton(csv_btns, text="⟳ Refresh", width=90, command=self._refresh_csv_list).pack(side="left", padx=4)
        ctk.CTkButton(csv_btns, text="Select All", width=90, command=self._select_all_csv).pack(side="left", padx=4)
        ctk.CTkButton(csv_btns, text="Clear", width=70,
                      fg_color=("gray75", "gray30"), hover_color=("gray65", "gray40"),
                      text_color=("gray10", "gray90"),
                      command=self._clear_csv_selection).pack(side="left", padx=4)

    def _build_scanners_card(self, parent):
        scan_card = ctk.CTkFrame(parent, corner_radius=10)
        scan_card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")

        ctk.CTkLabel(
            scan_card, text="Scanners", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, columnspan=4, padx=14, pady=(10, 8), sticky="w")

        self.https_var   = tk.BooleanVar(value=True)
        self.headers_var = tk.BooleanVar(value=True)
        self.dnssec_var  = tk.BooleanVar(value=True)

        scanners = [
            ("Security Headers", self.headers_var),
            ("DNSSEC",           self.dnssec_var),
            ("HTTPS / TLS",      self.https_var),
        ]
        checks_row = ctk.CTkFrame(scan_card, fg_color="transparent")
        checks_row.grid(row=1, column=0, padx=10, pady=(0, 4), sticky="w")
        for label, var in scanners:
            color = _SCANNER_COLORS[label]
            ctk.CTkCheckBox(
                checks_row, text=label, variable=var,
                checkmark_color="white",
                fg_color=color, hover_color=color,
                font=ctk.CTkFont(size=12),
            ).pack(side="left", padx=10)

        scanner_btns = ctk.CTkFrame(scan_card, fg_color="transparent")
        scanner_btns.grid(row=2, column=0, padx=10, pady=(4, 12), sticky="w")
        ctk.CTkButton(scanner_btns, text="Select All", width=100,
                      command=self._select_all_scanners).pack(side="left", padx=4)
        ctk.CTkButton(scanner_btns, text="Clear All", width=100,
                      fg_color=("gray75", "gray30"), hover_color=("gray65", "gray40"),
                      text_color=("gray10", "gray90"),
                      command=self._clear_all_scanners).pack(side="left", padx=4)

    def _build_options_card(self, parent):
        opt_card = ctk.CTkFrame(parent, corner_radius=10)
        opt_card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")

        ctk.CTkLabel(
            opt_card, text="Options", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, padx=14, pady=(10, 6), sticky="w")

        opts_row = ctk.CTkFrame(opt_card, fg_color="transparent")
        opts_row.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="w")

        self.analyze_only_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts_row, text="Analyze Only  (skip scanning, regenerate reports)",
            variable=self.analyze_only_var, font=ctk.CTkFont(size=12),
        ).pack(side="left", padx=6)

        ctk.CTkLabel(opts_row, text="Log Level:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(22, 6))
        self.log_level_var = tk.StringVar(value="INFO")
        ctk.CTkComboBox(
            opts_row,
            values=["DEBUG", "INFO", "WARNING", "ERROR"],
            variable=self.log_level_var,
            width=110,
            state="readonly",
        ).pack(side="left")

    def _build_actions(self, parent):
        action_frame = ctk.CTkFrame(parent, fg_color=_CARD_BG)
        action_frame.grid(row=3, column=0, padx=14, pady=(4, 0), sticky="ew")
        action_frame.grid_columnconfigure(2, weight=1)

        self.run_btn = ctk.CTkButton(
            action_frame,
            text="▶   Run Scan",
            width=150, height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=_GREEN, hover_color=_DKGRN,
            command=self._toggle_run,
        )
        self.run_btn.grid(row=0, column=0, padx=(4, 8))

        ctk.CTkButton(
            action_frame,
            text="Open Output Folder",
            width=160, height=40,
            font=ctk.CTkFont(size=13),
            command=self._open_output,
        ).grid(row=0, column=1, padx=4)

        right = ctk.CTkFrame(action_frame, fg_color="transparent")
        right.grid(row=0, column=2, padx=(16, 4), sticky="ew")
        right.grid_columnconfigure(0, weight=1)

        self.status_var = tk.StringVar(value="Ready.")
        ctk.CTkLabel(
            right, textvariable=self.status_var,
            font=ctk.CTkFont(size=11), text_color="gray", anchor="w",
        ).grid(row=0, column=0, sticky="ew")

        self.progress = ctk.CTkProgressBar(right, mode="indeterminate", height=6)
        self.progress.grid(row=1, column=0, pady=(4, 0), sticky="ew")
        self.progress.grid_remove()

    def _build_progress_card(self, parent):
        self._progress_card = ctk.CTkFrame(parent, corner_radius=10)
        self._progress_card.grid(row=4, column=0, padx=14, pady=(8, 2), sticky="ew")
        self._progress_card.grid_columnconfigure(0, weight=1)
        self._progress_card.grid_remove()

        ctk.CTkLabel(
            self._progress_card, text="Scan Progress",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, padx=14, pady=(10, 6), sticky="w")

        self._progress_rows_frame = ctk.CTkFrame(self._progress_card, fg_color="transparent")
        self._progress_rows_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        self._progress_rows_frame.grid_columnconfigure(2, weight=1)

    # ------------------------------------------------------------------ #
    # LLM Analysis tab                                                      #
    # ------------------------------------------------------------------ #

    def _build_llm_tab(self, parent):
        # ── Connection card ──────────────────────────────────────────────
        conn_card = ctk.CTkFrame(parent, corner_radius=10)
        conn_card.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="ew")
        conn_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            conn_card, text="LLM Connection", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, columnspan=4, padx=14, pady=(10, 8), sticky="w")

        # Backend
        ctk.CTkLabel(conn_card, text="Backend:", font=ctk.CTkFont(size=12)).grid(
            row=1, column=0, padx=(14, 6), pady=4, sticky="w")
        self._llm_backend_var = tk.StringVar(value="LMStudio")
        self._llm_backend_combo = ctk.CTkComboBox(
            conn_card,
            values=list(_LLM_BACKENDS.keys()),
            variable=self._llm_backend_var,
            width=140,
            state="readonly",
            command=self._on_backend_change,
        )
        self._llm_backend_combo.grid(row=1, column=1, padx=4, pady=4, sticky="w")

        # Host
        self._llm_host_label = ctk.CTkLabel(conn_card, text="Host:", font=ctk.CTkFont(size=12))
        self._llm_host_label.grid(row=1, column=2, padx=(20, 6), pady=4, sticky="w")
        self._llm_host_var = tk.StringVar(value="127.0.0.1")
        self._llm_host_entry = ctk.CTkEntry(conn_card, textvariable=self._llm_host_var, width=160)
        self._llm_host_entry.grid(row=1, column=3, padx=4, pady=4, sticky="w")

        # Port
        self._llm_port_label = ctk.CTkLabel(conn_card, text="Port:", font=ctk.CTkFont(size=12))
        self._llm_port_label.grid(row=1, column=4, padx=(14, 6), pady=4, sticky="w")
        self._llm_port_var = tk.StringVar(value="1234")
        self._llm_port_entry = ctk.CTkEntry(conn_card, textvariable=self._llm_port_var, width=70)
        self._llm_port_entry.grid(row=1, column=5, padx=(4, 14), pady=4, sticky="w")

        # API Key (shown for OpenAI/Custom)
        self._llm_key_label = ctk.CTkLabel(conn_card, text="API Key:", font=ctk.CTkFont(size=12))
        self._llm_key_label.grid(row=2, column=0, padx=(14, 6), pady=4, sticky="w")
        self._llm_key_var = tk.StringVar()
        self._llm_key_entry = ctk.CTkEntry(conn_card, textvariable=self._llm_key_var,
                                            width=260, show="•")
        self._llm_key_entry.grid(row=2, column=1, columnspan=3, padx=4, pady=4, sticky="w")

        # Custom URL (shown for Custom only)
        self._llm_url_label = ctk.CTkLabel(conn_card, text="Custom URL:", font=ctk.CTkFont(size=12))
        self._llm_url_label.grid(row=3, column=0, padx=(14, 6), pady=4, sticky="w")
        self._llm_url_var = tk.StringVar(value="http://localhost:8080/v1/chat/completions")
        self._llm_url_entry = ctk.CTkEntry(conn_card, textvariable=self._llm_url_var, width=340)
        self._llm_url_entry.grid(row=3, column=1, columnspan=5, padx=(4, 14), pady=4, sticky="ew")

        # Model
        ctk.CTkLabel(conn_card, text="Model:", font=ctk.CTkFont(size=12)).grid(
            row=4, column=0, padx=(14, 6), pady=(4, 12), sticky="w")
        self._llm_model_var = tk.StringVar(value="")
        self._llm_model_entry = ctk.CTkEntry(
            conn_card, textvariable=self._llm_model_var,
            width=220, placeholder_text="auto (uses first available model)")
        self._llm_model_entry.grid(row=4, column=1, columnspan=2, padx=4, pady=(4, 12), sticky="w")

        ctk.CTkButton(
            conn_card, text="List Models", width=110,
            fg_color=("gray75", "gray30"), hover_color=("gray65", "gray40"),
            text_color=("gray10", "gray90"),
            command=self._list_llm_models,
        ).grid(row=4, column=3, padx=(4, 14), pady=(4, 12), sticky="w")

        # Set initial visibility
        self._on_backend_change("LMStudio")

        # ── CSV Inputs card ───────────────────────────────────────────────
        csv_card = ctk.CTkFrame(parent, corner_radius=10)
        csv_card.grid(row=1, column=0, padx=14, pady=6, sticky="ew")
        csv_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            csv_card, text="Scanner Result CSV Files", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, columnspan=4, padx=14, pady=(10, 8), sticky="w")

        # ── All-countries toggle ─────────────────────────────────────────
        # Default mode: analyse every country under src/source/ + the
        # per-country scanner CSVs in one run, instead of the CSV fields
        # below (which only ever covered a single, manually-picked country).
        self._llm_all_countries_var = tk.BooleanVar(value=True)
        self._llm_all_countries_chk = ctk.CTkCheckBox(
            csv_card, text="🌍 Analyze all countries (recommended)",
            variable=self._llm_all_countries_var,
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_all_countries_toggle,
        )
        self._llm_all_countries_chk.grid(
            row=1, column=0, columnspan=2, padx=(14, 6), pady=(0, 4), sticky="w")

        ctk.CTkLabel(csv_card, text="Countries filter:", font=ctk.CTkFont(size=12)).grid(
            row=1, column=2, padx=(4, 6), pady=(0, 4), sticky="e")
        self._llm_countries_var = tk.StringVar(value="")
        self._llm_countries_entry = ctk.CTkEntry(
            csv_card, textvariable=self._llm_countries_var, width=110,
            placeholder_text="all")
        self._llm_countries_entry.grid(row=1, column=3, padx=(4, 14), pady=(0, 4), sticky="w")

        self._llm_csv_vars: dict[str, tk.StringVar] = {}
        self._llm_csv_widgets: list[ctk.CTkBaseClass] = []
        csv_fields = [
            ("https",   "HTTPS / TLS CSV:",   "HTTPS scan result"),
            ("headers", "Headers CSV:",        "Security headers scan result"),
            ("dnssec",  "DNSSEC CSV:",         "DNSSEC scan result"),
        ]
        for i, (key, label, hint) in enumerate(csv_fields):
            lbl = ctk.CTkLabel(csv_card, text=label, font=ctk.CTkFont(size=12))
            lbl.grid(row=i + 2, column=0, padx=(14, 6), pady=4, sticky="w")
            var = tk.StringVar()
            self._llm_csv_vars[key] = var
            entry = ctk.CTkEntry(csv_card, textvariable=var, placeholder_text=hint)
            entry.grid(row=i + 2, column=1, padx=4, pady=4, sticky="ew")
            browse_btn = ctk.CTkButton(
                csv_card, text="Browse", width=72,
                fg_color=("gray75", "gray30"), hover_color=("gray65", "gray40"),
                text_color=("gray10", "gray90"),
                command=lambda k=key: self._browse_llm_csv(k),
            )
            browse_btn.grid(row=i + 2, column=2, padx=4, pady=4)
            auto_btn = ctk.CTkButton(
                csv_card, text="Auto", width=60,
                fg_color=("gray70", "gray25"), hover_color=("gray60", "gray35"),
                text_color=("gray10", "gray90"),
                command=lambda k=key: self._auto_detect_csv(k),
            )
            auto_btn.grid(row=i + 2, column=3, padx=(4, 14), pady=4)
            self._llm_csv_widgets += [lbl, entry, browse_btn, auto_btn]

        # Auto-detect all on build
        for key in ("https", "headers", "dnssec"):
            self._auto_detect_csv(key)

        # Reflect the default "All countries" state (disables the manual CSV fields)
        self._on_all_countries_toggle()

        # ── Options card ──────────────────────────────────────────────────
        llm_opt_card = ctk.CTkFrame(parent, corner_radius=10)
        llm_opt_card.grid(row=2, column=0, padx=14, pady=6, sticky="ew")

        ctk.CTkLabel(
            llm_opt_card, text="Analysis Options", font=ctk.CTkFont(size=13, weight="bold")
        ).grid(row=0, column=0, columnspan=6, padx=14, pady=(10, 6), sticky="w")

        opts_row = ctk.CTkFrame(llm_opt_card, fg_color="transparent")
        opts_row.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="w")

        ctk.CTkLabel(opts_row, text="Limit:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(6, 4))
        self._llm_limit_var = tk.StringVar(value="")
        ctk.CTkEntry(opts_row, textvariable=self._llm_limit_var, width=70,
                     placeholder_text="all").pack(side="left", padx=4)

        ctk.CTkLabel(opts_row, text="institutions", font=ctk.CTkFont(size=12),
                     text_color="gray").pack(side="left", padx=(2, 20))

        ctk.CTkLabel(opts_row, text="Delay:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 4))
        self._llm_delay_var = tk.StringVar(value="1.0")
        ctk.CTkEntry(opts_row, textvariable=self._llm_delay_var, width=60).pack(side="left", padx=4)
        ctk.CTkLabel(opts_row, text="s between calls", font=ctk.CTkFont(size=12),
                     text_color="gray").pack(side="left", padx=(2, 20))

        ctk.CTkLabel(opts_row, text="Timeout:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 4))
        self._llm_timeout_var = tk.StringVar(value="600")
        ctk.CTkEntry(opts_row, textvariable=self._llm_timeout_var, width=70).pack(side="left", padx=4)
        ctk.CTkLabel(opts_row, text="s", font=ctk.CTkFont(size=12),
                     text_color="gray").pack(side="left", padx=(2, 20))

        ctk.CTkLabel(opts_row, text="Max Tokens:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 4))
        self._llm_max_tokens_var = tk.StringVar(value="4096")
        ctk.CTkEntry(opts_row, textvariable=self._llm_max_tokens_var, width=80,
                     placeholder_text="auto").pack(side="left", padx=4)
        ctk.CTkLabel(opts_row, text="tokens", font=ctk.CTkFont(size=12),
                     text_color="gray").pack(side="left", padx=(2, 20))

        ctk.CTkLabel(opts_row, text="Retries:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 4))
        self._llm_retries_var = tk.StringVar(value="3")
        ctk.CTkEntry(opts_row, textvariable=self._llm_retries_var, width=50).pack(side="left", padx=4)

        # ── Run row ───────────────────────────────────────────────────────
        run_row = ctk.CTkFrame(parent, fg_color=_CARD_BG)
        run_row.grid(row=3, column=0, padx=14, pady=(4, 8), sticky="ew")
        run_row.grid_columnconfigure(1, weight=1)

        self._llm_run_btn = ctk.CTkButton(
            run_row,
            text="▶   Run LLM Analysis",
            width=190, height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=_PURP, hover_color=_DKPURP,
            command=self._toggle_llm_run,
        )
        self._llm_run_btn.grid(row=0, column=0, padx=(4, 12))

        ctk.CTkButton(
            run_row, text="Open LLM Output", width=150, height=40,
            font=ctk.CTkFont(size=13),
            command=self._open_llm_output,
        ).grid(row=0, column=1, padx=4, sticky="w")

        self._llm_status_var = tk.StringVar(value="Ready.")
        ctk.CTkLabel(
            run_row, textvariable=self._llm_status_var,
            font=ctk.CTkFont(size=11), text_color="gray", anchor="e",
        ).grid(row=0, column=2, padx=(4, 4), sticky="e")

    def _on_all_countries_toggle(self):
        all_countries = self._llm_all_countries_var.get()
        state = "disabled" if all_countries else "normal"
        for w in self._llm_csv_widgets:
            w.configure(state=state)
        self._llm_countries_entry.configure(state=("normal" if all_countries else "disabled"))

    def _on_backend_change(self, value=None):
        backend = self._llm_backend_var.get()
        cfg = _LLM_BACKENDS.get(backend, _LLM_BACKENDS["LMStudio"])

        self._llm_host_var.set(cfg["default_host"])
        self._llm_port_var.set(cfg["default_port"])

        show_host = backend != "OpenAI"
        show_key  = cfg["needs_key"] or backend == "Custom"
        show_url  = backend == "Custom"

        if show_host:
            self._llm_host_label.grid()
            self._llm_host_entry.grid()
            self._llm_port_label.grid()
            self._llm_port_entry.grid()
        else:
            self._llm_host_label.grid_remove()
            self._llm_host_entry.grid_remove()
            self._llm_port_label.grid_remove()
            self._llm_port_entry.grid_remove()

        if show_key:
            self._llm_key_label.grid()
            self._llm_key_entry.grid()
        else:
            self._llm_key_label.grid_remove()
            self._llm_key_entry.grid_remove()

        if show_url:
            self._llm_url_label.grid()
            self._llm_url_entry.grid()
        else:
            self._llm_url_label.grid_remove()
            self._llm_url_entry.grid_remove()

    def _auto_detect_csv(self, key: str):
        subdir, patterns = _CSV_PATTERNS[key]
        search_dir = RESULTS_DIR / subdir
        if not search_dir.exists():
            return
        for pattern in patterns:
            matches = sorted(search_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
            if matches:
                self._llm_csv_vars[key].set(str(matches[0]))
                return

    def _browse_llm_csv(self, key: str):
        path = filedialog.askopenfilename(
            title=f"Select {key.upper()} CSV",
            initialdir=str(RESULTS_DIR / _CSV_PATTERNS[key][0]) if RESULTS_DIR.exists() else str(PROJECT_ROOT),
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self._llm_csv_vars[key].set(path)

    def _build_llm_args(self) -> list[str]:
        backend = self._llm_backend_var.get().lower()
        args = [
            sys.executable, str(PROJECT_ROOT / "llm_risk_analysis.py"),
            "--backend", backend,
        ]
        if backend == "lmstudio":
            args += ["--lmstudio-host", self._llm_host_var.get(),
                     "--lmstudio-port", self._llm_port_var.get()]
        elif backend == "ollama":
            host = self._llm_host_var.get()
            port = self._llm_port_var.get()
            args += ["--api-url", f"http://{host}:{port}/api/chat"]
        elif backend == "openai":
            key = self._llm_key_var.get().strip()
            if key:
                args += ["--api-key", key]
        elif backend == "custom":
            url = self._llm_url_var.get().strip()
            if url:
                args += ["--api-url", url]
            key = self._llm_key_var.get().strip()
            if key:
                args += ["--api-key", key]

        model = self._llm_model_var.get().strip()
        if model:
            args += ["--model", model]

        if self._llm_all_countries_var.get():
            args += ["--all-countries"]
            countries = self._llm_countries_var.get().strip()
            if countries:
                args += ["--countries", countries]
        else:
            for key, flag in [("https", "--https-csv"), ("headers", "--headers-csv"), ("dnssec", "--dnssec-csv")]:
                val = self._llm_csv_vars[key].get().strip()
                if val:
                    args += [flag, val]

        limit = self._llm_limit_var.get().strip()
        if limit and limit.isdigit():
            args += ["--limit", limit]

        delay = self._llm_delay_var.get().strip()
        if delay:
            args += ["--delay", delay]

        timeout = self._llm_timeout_var.get().strip()
        if timeout:
            args += ["--timeout", timeout]

        max_tokens = self._llm_max_tokens_var.get().strip()
        if max_tokens and max_tokens.isdigit():
            args += ["--max-tokens", max_tokens]

        retries = self._llm_retries_var.get().strip()
        if retries and retries.isdigit():
            args += ["--retries", retries]

        return args

    def _list_llm_models(self):
        backend = self._llm_backend_var.get().lower()
        args = [sys.executable, str(PROJECT_ROOT / "llm_risk_analysis.py"),
                "--backend", backend, "--list-models"]
        if backend == "lmstudio":
            args += ["--lmstudio-host", self._llm_host_var.get(),
                     "--lmstudio-port", self._llm_port_var.get()]
        self._log(f"[LLM] Listing models for backend: {backend}...\n", tag="gui")
        threading.Thread(target=self._run_list_models, args=(args,), daemon=True).start()

    def _run_list_models(self, args: list[str]):
        try:
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=30, cwd=str(PROJECT_ROOT)
            )
            output = result.stdout + result.stderr
            self._log_queue.put(f"[LLM] Models:\n{output}\n")
        except Exception as exc:
            self._log_queue.put(f"[LLM] Could not list models: {exc}\n__WARN__")

    def _toggle_llm_run(self):
        if self._llm_running:
            self._stop_llm()
        else:
            self._start_llm()

    def _start_llm(self):
        args = self._build_llm_args()
        self._llm_running = True
        self._llm_run_btn.configure(text="⏹   Stop LLM", fg_color=_RED, hover_color=_DKRED)
        self._llm_status_var.set("Running LLM analysis…")
        self._log(f"[LLM] Command: {' '.join(args)}\n", tag="gui")
        threading.Thread(target=self._run_llm_subprocess, args=(args,), daemon=True).start()

    def _stop_llm(self):
        if self._llm_proc and self._llm_proc.poll() is None:
            self._llm_proc.terminate()
            self._log("[LLM] Analysis terminated by user.\n", tag="WARNING")
        self._set_llm_idle()

    def _run_llm_subprocess(self, args: list[str]):
        try:
            self._llm_proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(PROJECT_ROOT),
            )
            for line in self._llm_proc.stdout:
                self._log_queue.put(line)
            self._llm_proc.wait()
            rc = self._llm_proc.returncode
            if rc == 0:
                self._log_queue.put("[LLM] Analysis finished successfully.\n__DONE__")
            else:
                self._log_queue.put(f"[LLM] Process exited with code {rc}.\n__WARN__")
        except Exception as exc:
            self._log_queue.put(f"[LLM] Error: {exc}\n__ERROR__")
        finally:
            self._log_queue.put("__LLM_IDLE__")

    def _set_llm_idle(self):
        self._llm_running = False
        self._llm_run_btn.configure(text="▶   Run LLM Analysis", fg_color=_PURP, hover_color=_DKPURP)
        self._llm_status_var.set("Ready.")

    def _open_llm_output(self):
        target = RESULTS_DIR / "llm_analysis"
        if not target.exists():
            target = RESULTS_DIR
        if not target.exists():
            messagebox.showinfo("Output folder", f"Not found yet:\n{target}")
            return
        if sys.platform == "win32":
            os.startfile(str(target))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)])

    def _build_log_card(self):
        log_card = ctk.CTkFrame(self._lower, corner_radius=10)
        log_card.grid(row=0, column=0, padx=14, pady=(6, 14), sticky="nsew")
        log_card.grid_rowconfigure(1, weight=1)
        log_card.grid_columnconfigure(0, weight=1)

        log_header = ctk.CTkFrame(log_card, fg_color="transparent")
        log_header.grid(row=0, column=0, padx=12, pady=(8, 4), sticky="ew")
        ctk.CTkLabel(
            log_header, text="Log Output", font=ctk.CTkFont(size=13, weight="bold")
        ).pack(side="left")
        ctk.CTkButton(
            log_header, text="Clear", width=70, height=26,
            fg_color=("gray75", "gray30"), hover_color=("gray65", "gray40"),
            text_color=("gray10", "gray90"),
            command=self._clear_log,
        ).pack(side="right")

        # Always a dark terminal, regardless of the app's light/dark
        # appearance mode: it's a real tkinter.Text widget (not CTk), so it
        # won't auto-restyle when the mode is toggled later — pinning it to
        # one deliberate palette avoids it going stale/mismatched, and reads
        # like a proper console either way.
        log_bg = "#1e1e2e"
        log_fg = "#cdd6f4"

        self.log_text = tk.Text(
            log_card,
            state="disabled",
            wrap="word",
            font=("Consolas", 10),
            background=log_bg,
            foreground=log_fg,
            insertbackground=log_fg,
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=8,
        )
        self.log_text.grid(row=1, column=0, padx=6, pady=(0, 6), sticky="nsew")
        self.log_text.tag_configure("WARNING", foreground="#f9a825")
        self.log_text.tag_configure("ERROR",   foreground="#f44336")
        self.log_text.tag_configure("done",    foreground="#4caf50")
        self.log_text.tag_configure("gui",     foreground="#42a5f5")

        log_sb = ctk.CTkScrollbar(log_card, command=self.log_text.yview)
        log_sb.grid(row=1, column=1, padx=(0, 6), pady=(0, 6), sticky="ns")
        self.log_text.configure(yscrollcommand=log_sb.set)
        self.log_text.bind("<Control-a>", self._select_all_log)

        # Tk's built-in Entry class binding for <Control-a> moves the cursor
        # to the start of the line (an Emacs-style shortcut) instead of
        # selecting all text, and CTkEntry — whose visible widget is a real
        # tkinter.Entry under the hood — inherits that default and doesn't
        # override it. bind_class replaces that class-level default outright
        # (rather than bind_all, which sits at a lower priority and would
        # fire *after* it, too late to change the behaviour), so this fixes
        # every CTkEntry in the app (host, port, key, url, model, countries,
        # CSV paths, limit/delay/timeout/etc.) in one place.
        self.root.bind_class("Entry", "<Control-a>", self._select_all_entry)

    # ------------------------------------------------------------------ #
    # Progress panel                                                        #
    # ------------------------------------------------------------------ #

    def _init_progress_panel(self, selected_display_names: list[str]):
        for w in self._progress_rows_frame.winfo_children():
            w.destroy()
        self._sp.clear()

        for i, name in enumerate(selected_display_names):
            color = _SCANNER_COLORS[name]
            base_row = i * 2

            spinner_lbl = ctk.CTkLabel(
                self._progress_rows_frame, text="○",
                font=ctk.CTkFont(size=14), text_color="gray", width=24,
            )
            spinner_lbl.grid(row=base_row, column=0, padx=(4, 6), pady=(4, 0), sticky="w")

            ctk.CTkLabel(
                self._progress_rows_frame, text=name,
                font=ctk.CTkFont(size=12), width=140, anchor="w",
            ).grid(row=base_row, column=1, padx=(0, 8), pady=(4, 0), sticky="w")

            bar = ctk.CTkProgressBar(
                self._progress_rows_frame,
                mode="determinate",
                progress_color=color,
                height=10,
            )
            bar.set(0)
            bar.grid(row=base_row, column=2, padx=(0, 8), pady=(4, 0), sticky="ew")

            pct_lbl = ctk.CTkLabel(
                self._progress_rows_frame, text="  0%",
                font=ctk.CTkFont(size=11, weight="bold"), width=38, anchor="e",
            )
            pct_lbl.grid(row=base_row, column=3, padx=(0, 4), pady=(4, 0), sticky="e")

            status_lbl = ctk.CTkLabel(
                self._progress_rows_frame, text="Waiting…",
                font=ctk.CTkFont(size=10), text_color="gray", anchor="w",
            )
            status_lbl.grid(
                row=base_row + 1, column=1, columnspan=3,
                padx=(0, 4), pady=(0, 6), sticky="w",
            )

            self._sp[name] = {
                "spinner":      spinner_lbl,
                "bar":          bar,
                "pct_lbl":      pct_lbl,
                "status_lbl":   status_lbl,
                "pct":          0.0,
                "file_count":   0,
                "color":        color,
                "total":        0,
                "seen_urls":    set(),
                "current_file": "",
            }

        self._progress_card.grid()
        self.root.after(50, lambda: self._fix_scroll(self._scanner_scroll))

    def _update_scanner_progress(self, display_name: str, pct: float, status: str):
        if display_name not in self._sp:
            return
        state = self._sp[display_name]
        state["pct"] = pct
        state["bar"].set(pct)
        state["pct_lbl"].configure(text=f"{int(pct * 100):3d}%")
        state["status_lbl"].configure(text=status)
        if pct >= 1.0:
            state["spinner"].configure(text="✓", text_color="#4caf50")
            state["bar"].configure(progress_color="#4caf50")

    def _animate_spinner(self):
        if not self._spinner_running:
            return
        self._spinner_idx = (self._spinner_idx + 1) % len(_SPINNER_FRAMES)
        frame = _SPINNER_FRAMES[self._spinner_idx]
        for state in self._sp.values():
            pct = state["pct"]
            if 0.0 < pct < 1.0:
                state["spinner"].configure(text=frame, text_color=state["color"])
        self.root.after(80, self._animate_spinner)

    # ------------------------------------------------------------------ #
    # Log-line progress parsing                                             #
    # ------------------------------------------------------------------ #

    def _parse_progress(self, line: str):
        bracket_match = re.search(r'\[(headers|dnssec|https)\]', line)
        running_match = re.search(
            r'(?:Running|Analyzing) (headers|dnssec|https)\.\.\.', line, re.IGNORECASE
        )

        # Determine scanner from explicit bracket/running prefix and remember it.
        # Per-URL log lines have no prefix, so they inherit _active_log_name.
        if bracket_match:
            self._active_log_name = bracket_match.group(1)
            log_name = bracket_match.group(1)
        elif running_match:
            self._active_log_name = running_match.group(1)
            log_name = running_match.group(1)
        else:
            log_name = self._active_log_name

        if not log_name or log_name not in _LOG_TO_DISPLAY:
            return
        display_name = _LOG_TO_DISPLAY[log_name]
        if display_name not in self._sp:
            return

        state = self._sp[display_name]
        ln = line.lower()

        # Parse total institutions count emitted once before the per-file loop.
        total_match = re.search(r'\[(?:https|headers|dnssec)\] Total: (\d+)', line)
        if total_match:
            state["total"] = int(total_match.group(1))
            return

        # Per-URL/domain log lines — update granular progress via seen-URL set.
        url_match   = re.search(r'Scanning (?:URL|HTTP|HTTPS):\s*(\S+)', line)
        domain_match = re.search(r'Scanning domain:\s*(\S+)', line)
        if url_match and state["total"] > 0:
            state["seen_urls"].add(url_match.group(1))
            self._update_url_progress(display_name, state)
            return
        if domain_match and state["total"] > 0:
            state["seen_urls"].add(domain_match.group(1))
            self._update_url_progress(display_name, state)
            return

        # Coarse stage milestones (bracket-prefixed lines only).
        if running_match:
            self._update_scanner_progress(display_name, 0.02, "Starting…")
        elif "scanning file" in ln and bracket_match:
            file_match = re.search(r'Scanning file:\s*(\S+)', line, re.IGNORECASE)
            if file_match:
                state["current_file"] = Path(file_match.group(1)).name
            state["file_count"] += 1
            if state["total"] == 0:
                pct = min(0.55, 0.02 + state["file_count"] * 0.10)
                self._update_scanner_progress(display_name, pct, f"Scanning file {state['file_count']}…")
            else:
                # Keep current progress (seen_urls may already have prior-file entries),
                # just refresh the status label with the new filename.
                self._update_url_progress(display_name, state)
        elif "generating reports" in ln or "running analysis" in ln:
            self._update_scanner_progress(display_name, 0.85, "Generating reports…")
        elif "outputs collected" in ln:
            self._update_scanner_progress(display_name, 0.92, "Collecting outputs…")
        elif "latest/ updated" in ln:
            self._update_scanner_progress(display_name, 0.96, "Updating latest/…")
        elif "complete." in ln:
            self._update_scanner_progress(display_name, 1.0, "Complete ✓")

    def _update_url_progress(self, display_name: str, state: dict):
        """Recalculate and push progress after a new URL/domain is added to seen_urls."""
        count = len(state["seen_urls"])
        total = state["total"]
        pct   = 0.05 + 0.75 * min(1.0, count / total)
        fname = state["current_file"]
        status = f"{count}/{total}{(' — ' + fname) if fname else ''}"
        self._update_scanner_progress(display_name, pct, status)

    # ------------------------------------------------------------------ #
    # Appearance                                                            #
    # ------------------------------------------------------------------ #

    def _toggle_appearance(self):
        mode = "Light" if ctk.get_appearance_mode() == "Dark" else "Dark"
        ctk.set_appearance_mode(mode)
        self._mode_btn.configure(text="☀ Light" if mode == "Dark" else "☾ Dark")

        # self._paned and self._sash_grip are raw tkinter widgets (not CTk),
        # so they don't auto-restyle on mode switch like the rest of the UI —
        # without this they'd keep whatever color they had at build time,
        # leaving a stray dark strip once the app turns light.
        is_dark = mode == "Dark"
        sash_color = "#3a3a4a" if is_dark else "#c8c8c8"
        grip_fg = "#888899" if is_dark else "#707080"
        self._paned.configure(background=sash_color)
        self._sash_grip.configure(bg=sash_color, fg=grip_fg)

    # ------------------------------------------------------------------ #
    # CSV list management                                                   #
    # ------------------------------------------------------------------ #

    def _refresh_csv_list(self):
        previously_checked = {p for p, v in self._csv_vars.items() if v.get()}

        for w in self.csv_scroll.winfo_children():
            w.destroy()
        self._csv_vars.clear()

        SOURCE_DIR.mkdir(parents=True, exist_ok=True)
        paths = sorted(SOURCE_DIR.glob("*.csv"))

        if not paths:
            ctk.CTkLabel(
                self.csv_scroll,
                text="No CSV files found in src/source/ — use Add File…",
                text_color="gray",
                font=ctk.CTkFont(size=11),
            ).pack(pady=10)
            self.root.after(50, lambda: self._fix_scroll(self._scanner_scroll))
            return

        for p in paths:
            checked = p in previously_checked if previously_checked else True
            var = tk.BooleanVar(value=checked)
            ctk.CTkCheckBox(
                self.csv_scroll,
                text=p.name,
                variable=var,
                font=ctk.CTkFont(family="Consolas", size=12),
            ).pack(anchor="w", padx=6, pady=3)
            self._csv_vars[p] = var

        self.root.after(50, lambda: self._fix_scroll(self._scanner_scroll))

    def _add_csv(self):
        paths = filedialog.askopenfilenames(
            title="Select CSV file(s) to add",
            initialdir=str(SOURCE_DIR) if SOURCE_DIR.exists() else str(PROJECT_ROOT),
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not paths:
            return
        SOURCE_DIR.mkdir(parents=True, exist_ok=True)
        added = []
        for path in paths:
            src = Path(path)
            dest = SOURCE_DIR / src.name
            if dest.resolve() != src.resolve():
                shutil.copy2(src, dest)
                added.append(src.name)
        self._refresh_csv_list()
        if added:
            self._log(f"[GUI] Added to src/source/: {', '.join(added)}\n", tag="gui")

    def _remove_csv(self):
        to_remove = [p for p, v in self._csv_vars.items() if v.get()]
        if not to_remove:
            messagebox.showinfo("Remove", "Tick the files you want to remove first.")
            return
        names = "\n".join(p.name for p in to_remove)
        if not messagebox.askyesno("Confirm Remove", f"Delete from src/source/?\n\n{names}"):
            return
        for p in to_remove:
            if p.exists():
                p.unlink()
                self._log(f"[GUI] Removed {p.name}\n", tag="WARNING")
        self._refresh_csv_list()

    def _select_all_csv(self):
        for var in self._csv_vars.values():
            var.set(True)

    def _clear_csv_selection(self):
        for var in self._csv_vars.values():
            var.set(False)

    # ------------------------------------------------------------------ #
    # Scanner helpers                                                       #
    # ------------------------------------------------------------------ #

    def _select_all_scanners(self):
        for v in (self.https_var, self.headers_var, self.dnssec_var):
            v.set(True)

    def _clear_all_scanners(self):
        for v in (self.https_var, self.headers_var, self.dnssec_var):
            v.set(False)

    # ------------------------------------------------------------------ #
    # Scan lifecycle                                                        #
    # ------------------------------------------------------------------ #

    def _toggle_run(self):
        if self._running:
            self._stop_scan()
        else:
            self._start_scan()

    def _open_output(self):
        target = RESULTS_DIR if RESULTS_DIR.exists() else PROJECT_ROOT / "src"
        if not target.exists():
            messagebox.showinfo("Output folder", f"Not found yet:\n{target}")
            return
        if sys.platform == "win32":
            os.startfile(str(target))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)])

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _start_scan(self):
        selected = {p for p, v in self._csv_vars.items() if v.get()}
        if not selected:
            messagebox.showwarning("No CSV selected", "Tick at least one CSV file.")
            return

        scanner_flags = []
        if self.headers_var.get(): scanner_flags.append("--headers")
        if self.dnssec_var.get():  scanner_flags.append("--dnssec")
        if self.https_var.get():   scanner_flags.append("--https")
        if not scanner_flags:
            messagebox.showwarning("No scanner", "Select at least one scanner.")
            return

        _var_map = {
            "Security Headers": self.headers_var,
            "DNSSEC":           self.dnssec_var,
            "HTTPS / TLS":      self.https_var,
        }
        selected_display = [name for name in _SCANNER_ORDER if _var_map[name].get()]

        to_hide = [p for p in self._csv_vars if p not in selected]

        args = [sys.executable, "main.py"] + scanner_flags
        if self.analyze_only_var.get():
            args.append("--analyze-only")
        args += ["--log-level", self.log_level_var.get()]

        names = ", ".join(p.name for p in sorted(selected))
        self._running = True
        self.run_btn.configure(text="⏹   Stop", fg_color=_RED, hover_color=_DKRED)
        self.status_var.set(f"Scanning: {names}")
        self.progress.grid()
        self.progress.start()

        self._log(f"[GUI] Files : {names}\n", tag="gui")
        self._log(f"[GUI] Cmd   : {' '.join(args)}\n", tag="gui")

        self._active_log_name = None
        self._init_progress_panel(selected_display)
        self._spinner_running = True
        self._animate_spinner()

        threading.Thread(
            target=self._run_subprocess, args=(args, to_hide), daemon=True
        ).start()

    def _stop_scan(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            self._log("[GUI] Scan terminated by user.\n", tag="WARNING")
        self._set_idle()

    def _run_subprocess(self, args: list[str], to_hide: list[Path]):
        hidden: list[tuple[Path, Path]] = []
        try:
            for p in to_hide:
                bak = p.with_suffix(".csv.bak")
                p.rename(bak)
                hidden.append((bak, p))

            self._proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=str(PROJECT_ROOT),
            )
            for line in self._proc.stdout:
                self._log_queue.put(line)
            self._proc.wait()
            rc = self._proc.returncode
            if rc == 0:
                self._log_queue.put("[GUI] Scan finished successfully.\n__DONE__")
            else:
                self._log_queue.put(f"[GUI] Process exited with code {rc}.\n__WARN__")
        except Exception as exc:
            self._log_queue.put(f"[GUI] Error: {exc}\n__ERROR__")
        finally:
            for bak, original in hidden:
                if bak.exists():
                    bak.rename(original)
            self._log_queue.put("__IDLE__")

    # ------------------------------------------------------------------ #
    # Log / queue helpers                                                   #
    # ------------------------------------------------------------------ #

    def _poll_queue(self):
        try:
            while True:
                msg = self._log_queue.get_nowait()
                if msg == "__IDLE__":
                    self._set_idle()
                    self._refresh_csv_list()
                elif msg == "__LLM_IDLE__":
                    self._set_llm_idle()
                elif msg.endswith("__DONE__"):
                    self._log(msg[: -len("__DONE__")], tag="done")
                elif msg.endswith("__WARN__"):
                    self._log(msg[: -len("__WARN__")], tag="WARNING")
                elif msg.endswith("__ERROR__"):
                    self._log(msg[: -len("__ERROR__")], tag="ERROR")
                else:
                    tag = None
                    u = msg.upper()
                    if " - WARNING - " in u or u.startswith("WARNING"):
                        tag = "WARNING"
                    elif " - ERROR - " in u or u.startswith("ERROR"):
                        tag = "ERROR"
                    self._log(msg, tag=tag)
                    if self._running:
                        self._parse_progress(msg)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _log(self, text: str, tag: str | None = None):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text, tag or "")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _set_idle(self):
        self._running = False
        self._spinner_running = False
        self._active_log_name = None
        self.run_btn.configure(text="▶   Run Scan", fg_color=_GREEN, hover_color=_DKGRN)
        self.status_var.set("Ready.")
        self.progress.stop()
        self.progress.grid_remove()
        self._progress_card.grid_remove()

    # ------------------------------------------------------------------ #
    # Sash grip handle                                                      #
    # ------------------------------------------------------------------ #

    def _build_sash_handle(self):
        is_dark = ctk.get_appearance_mode() == "Dark"
        sash_bg = "#3a3a4a" if is_dark else "#c8c8c8"
        grip_fg = "#888899" if is_dark else "#707080"

        self._sash_grip = tk.Label(
            self._paned,
            text="⠿ ⠿ ⠿",
            font=("Segoe UI", 8),
            bg=sash_bg,
            fg=grip_fg,
            cursor="sb_v_double_arrow",
            padx=6,
            pady=0,
            relief="flat",
            bd=0,
        )
        self._sash_grip.bind("<ButtonPress-1>", self._grip_press)
        self._sash_grip.bind("<B1-Motion>", self._grip_motion)

        self._paned.bind("<Configure>", lambda e: self.root.after(10, self._reposition_grip))
        self._paned.bind("<B1-Motion>", lambda e: self._reposition_grip())
        self._paned.bind("<ButtonRelease-1>", lambda e: self._reposition_grip())

    def _reposition_grip(self):
        try:
            _, y = self._paned.sash_coord(0)
            sash_h = int(self._paned.cget("sashwidth"))
            mid_y = y + sash_h // 2
            self._sash_grip.place(in_=self._paned, relx=0.5, y=mid_y, anchor="center")
            self._sash_grip.lift()
        except Exception:
            pass

    def _grip_press(self, event):
        self._grip_drag_y = event.y_root

    def _grip_motion(self, event):
        try:
            dy = event.y_root - self._grip_drag_y
            self._grip_drag_y = event.y_root
            _, y = self._paned.sash_coord(0)
            self._paned.sash_place(0, 0, y + dy)
            self._reposition_grip()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Mouse-wheel scroll fix for Windows                                    #
    # ------------------------------------------------------------------ #

    def _fix_scroll(self, sf: ctk.CTkScrollableFrame):
        """Bind scroll events on every descendant of sf so it always scrolls sf.
        Windows/macOS use <MouseWheel>; Linux X11 uses <Button-4>/<Button-5>."""
        canvas = sf._parent_canvas

        def _scroll_win(event):
            # CTkScrollableFrame sets yscrollincrement to a tiny 1px (Windows)
            # or 8px (macOS) — see customtkinter's _set_scroll_increments —
            # so "units" here are pixels, not lines. Dividing the wheel delta
            # by 120 (the old assumption, correct for a ~line-sized unit)
            # therefore moved the content only ~1px per notch on Windows,
            # making the scroll feel almost frozen. Match customtkinter's own
            # internal handler ratio per platform instead (delta/6 on
            # Windows, delta as-is on macOS) so it scrolls at the same speed
            # CTk's built-in — but too narrowly targeted to actually fire —
            # handler would have.
            if sys.platform.startswith("win"):
                canvas.yview_scroll(int(-1 * (event.delta / 6)), "units")
            elif sys.platform == "darwin":
                canvas.yview_scroll(int(-1 * event.delta), "units")
            else:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            return "break"

        def _scroll_up(event):
            canvas.yview_scroll(-1, "units")
            return "break"

        def _scroll_dn(event):
            canvas.yview_scroll(1, "units")
            return "break"

        def _bind_tree(widget):
            widget.bind("<MouseWheel>", _scroll_win, add="+")
            widget.bind("<Button-4>",   _scroll_up,  add="+")
            widget.bind("<Button-5>",   _scroll_dn,  add="+")
            for child in widget.winfo_children():
                _bind_tree(child)

        _bind_tree(sf)

    def _bind_scrollwheels(self):
        self._fix_scroll(self._scanner_scroll)
        self._fix_scroll(self._llm_scroll)

    # ------------------------------------------------------------------ #
    # Log helpers                                                           #
    # ------------------------------------------------------------------ #

    def _select_all_log(self, event=None):
        self.log_text.tag_add("sel", "1.0", "end")
        return "break"

    def _select_all_entry(self, event):
        """Generic <Control-a> handler for the internal tkinter.Entry inside
        every CTkEntry widget (see comment where this is bound)."""
        widget = event.widget
        if isinstance(widget, tk.Entry):
            widget.select_range(0, "end")
            widget.icursor("end")
            return "break"


def main():
    root = ctk.CTk()
    ScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
