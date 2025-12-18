"""
Crypto Tracker + Email Alerts (Standalone)

Features (modeled after don-books.com/Crypto-Tracker):
- Live CAD prices via CoinGecko
- Alerts: coin + condition (>= or <=) + target CAD
- Optional 24h low/high for "potential" + profit estimate on "Assume $"
- Email notifications (SMTP) when alerts trigger
- Saves alerts/config locally (JSON)

Install:
  python -m pip install requests

Run:
  python crypto_tracker.py
"""

from __future__ import annotations

import json
import os
import time
import threading
import ssl
import smtplib
from email.message import EmailMessage
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

import requests
import tkinter as tk
from tkinter import ttk, messagebox

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(APP_DIR, "crypto_tracker_data.json")

COINGECKO_SIMPLE_PRICE = "https://api.coingecko.com/api/v3/simple/price"


# ---- Coin list (Yahoo-like symbols shown on your page) ----
DEFAULT_YAHOO_SYMBOLS = [
    "BTC-USD","ETH-USD","USDT-USD","BNB-USD","XRP-USD","SOL-USD","USDC-USD","ADA-USD","DOGE-USD","TRX-USD",
    "DOT-USD","LTC-USD","AVAX-USD","LINK-USD","XLM-USD","XMR-USD","ATOM-USD","ETC-USD","UNI-USD","ALGO-USD",
    "MATIC-USD","APT-USD","ARB-USD","ICP-USD","FIL-USD","HBAR-USD","VET-USD","NEAR-USD","GRT-USD","FTM-USD",
    "IMX-USD","RNDR-USD","AAVE-USD","SAND-USD","AXS-USD","FLOW-USD","EOS-USD","TFUEL-USD","CHZ-USD","MANA-USD"
]

# Map Yahoo-ish symbols to CoinGecko IDs (best-effort; you can adjust if you want)
YAHOO_TO_COINGECKO = {
    "BTC-USD":"bitcoin",
    "ETH-USD":"ethereum",
    "USDT-USD":"tether",
    "BNB-USD":"binancecoin",
    "XRP-USD":"ripple",
    "SOL-USD":"solana",
    "USDC-USD":"usd-coin",
    "ADA-USD":"cardano",
    "DOGE-USD":"dogecoin",
    "TRX-USD":"tron",
    "DOT-USD":"polkadot",
    "LTC-USD":"litecoin",
    "AVAX-USD":"avalanche-2",
    "LINK-USD":"chainlink",
    "XLM-USD":"stellar",
    "XMR-USD":"monero",
    "ATOM-USD":"cosmos",
    "ETC-USD":"ethereum-classic",
    "UNI-USD":"uniswap",
    "ALGO-USD":"algorand",
    "MATIC-USD":"polygon-ecosystem-token",  # CoinGecko renamed; this is the newer ID
    "APT-USD":"aptos",
    "ARB-USD":"arbitrum",
    "ICP-USD":"internet-computer",
    "FIL-USD":"filecoin",
    "HBAR-USD":"hedera-hashgraph",
    "VET-USD":"vechain",
    "NEAR-USD":"near",
    "GRT-USD":"the-graph",
    "FTM-USD":"fantom",
    "IMX-USD":"immutable-x",
    "RNDR-USD":"render-token",
    "AAVE-USD":"aave",
    "SAND-USD":"the-sandbox",
    "AXS-USD":"axie-infinity",
    "FLOW-USD":"flow",
    "EOS-USD":"eos",
    "TFUEL-USD":"theta-fuel",
    "CHZ-USD":"chiliz",
    "MANA-USD":"decentraland",
}


@dataclass
class Alert:
    symbol: str                 # Yahoo-like symbol shown in UI
    condition: str              # ">=" or "<="
    target_cad: float
    low_24h_cad: Optional[float] = None
    high_24h_cad: Optional[float] = None
    last_price_cad: Optional[float] = None
    triggered: bool = False
    last_trigger_ts: Optional[float] = None


@dataclass
class EmailConfig:
    enabled: bool = False
    to_email: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""   # NOTE: stored locally; use an app password if possible
    from_email: str = ""  # if blank, smtp_user is used


@dataclass
class AppState:
    assume_amount: float = 100.0
    refresh_seconds: int = 60
    alerts: List[Alert] = None
    email: EmailConfig = None


def safe_float(s: str) -> Optional[float]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def load_state() -> AppState:
    if not os.path.exists(DATA_FILE):
        return AppState(assume_amount=100.0, refresh_seconds=60, alerts=[], email=EmailConfig())
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        email_raw = raw.get("email", {}) or {}
        alerts_raw = raw.get("alerts", []) or []
        email = EmailConfig(**{
            "enabled": bool(email_raw.get("enabled", False)),
            "to_email": str(email_raw.get("to_email","")),
            "smtp_host": str(email_raw.get("smtp_host","")),
            "smtp_port": int(email_raw.get("smtp_port",587)),
            "smtp_user": str(email_raw.get("smtp_user","")),
            "smtp_pass": str(email_raw.get("smtp_pass","")),
            "from_email": str(email_raw.get("from_email","")),
        })
        alerts = []
        for a in alerts_raw:
            alerts.append(Alert(
                symbol=a["symbol"],
                condition=a["condition"],
                target_cad=float(a["target_cad"]),
                low_24h_cad=a.get("low_24h_cad", None),
                high_24h_cad=a.get("high_24h_cad", None),
                last_price_cad=a.get("last_price_cad", None),
                triggered=bool(a.get("triggered", False)),
                last_trigger_ts=a.get("last_trigger_ts", None),
            ))
        return AppState(
            assume_amount=float(raw.get("assume_amount", 100.0)),
            refresh_seconds=int(raw.get("refresh_seconds", 60)),
            alerts=alerts,
            email=email
        )
    except Exception:
        # If the JSON is corrupted, start fresh rather than crashing
        return AppState(assume_amount=100.0, refresh_seconds=60, alerts=[], email=EmailConfig())


def save_state(state: AppState) -> None:
    payload = {
        "assume_amount": state.assume_amount,
        "refresh_seconds": state.refresh_seconds,
        "email": asdict(state.email),
        "alerts": [asdict(a) for a in (state.alerts or [])],
    }
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def coingecko_fetch(ids: List[str]) -> Dict[str, Dict[str, float]]:
    if not ids:
        return {}
    params = {
        "ids": ",".join(ids),
        "vs_currencies": "cad",
        "include_24hr_low": "true",
        "include_24hr_high": "true",
        "include_24hr_change": "true",
    }
    r = requests.get(COINGECKO_SIMPLE_PRICE, params=params, timeout=20)
    r.raise_for_status()
    return r.json()


def compute_potential(low: Optional[float], high: Optional[float], assume_amount: float) -> Tuple[str, str]:
    """
    Returns (potential_percent_str, profit_est_str)
    """
    if low is None or high is None or low <= 0:
        return ("—", "—")
    swing_pct = (high - low) / low * 100.0
    profit = assume_amount * ((high / low) - 1.0)
    return (f"{swing_pct:.2f}%", f"${profit:.2f}")


def send_email(cfg: EmailConfig, subject: str, body: str) -> None:
    if not cfg.enabled:
        return
    if not (cfg.to_email and cfg.smtp_host and cfg.smtp_user and cfg.smtp_pass):
        raise RuntimeError("Email config incomplete (to/smtp host/user/pass).")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.from_email.strip() or cfg.smtp_user.strip()
    msg["To"] = cfg.to_email.strip()
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(cfg.smtp_host.strip(), int(cfg.smtp_port), timeout=25) as server:
        server.ehlo()
        # Try STARTTLS
        try:
            server.starttls(context=context)
            server.ehlo()
        except Exception:
            # Some servers may not support it; continue (or you can enforce TLS if you want)
            pass
        server.login(cfg.smtp_user.strip(), cfg.smtp_pass)
        server.send_message(msg)


class CryptoTrackerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Crypto Tracker + Email Alerts (CAD)")
        self.state = load_state()

        self._stop = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        self._build_ui()
        self._load_into_ui()
        self._start_worker()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_ui(self):
        self.root.geometry("1100x650")

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Assume $", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.assume_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.assume_var, width=10).pack(side="left", padx=(6, 14))

        ttk.Label(top, text="Refresh (sec)", font=("Segoe UI", 10, "bold")).pack(side="left")
        self.refresh_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.refresh_var, width=8).pack(side="left", padx=(6, 14))

        ttk.Button(top, text="Refresh now", command=self.refresh_now).pack(side="left", padx=(0, 10))
        ttk.Button(top, text="Save alerts", command=self.save_all).pack(side="left", padx=(0, 10))
        ttk.Button(top, text="Send test email", command=self.send_test_email).pack(side="left")

        mid = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        mid.pack(fill="x")

        # Add alert form
        form = ttk.LabelFrame(mid, text="Price alerts", padding=10)
        form.pack(side="left", fill="x", expand=True, padx=(0, 10))

        ttk.Label(form, text="Coin (Yahoo symbol)").grid(row=0, column=0, sticky="w")
        ttk.Label(form, text="Condition").grid(row=0, column=1, sticky="w")
        ttk.Label(form, text="Target (CAD)").grid(row=0, column=2, sticky="w")
        ttk.Label(form, text="24h low (CAD) [optional]").grid(row=0, column=3, sticky="w")
        ttk.Label(form, text="24h high (CAD) [optional]").grid(row=0, column=4, sticky="w")

        self.coin_var = tk.StringVar()
        self.cond_var = tk.StringVar(value=">=")
        self.target_var = tk.StringVar()
        self.low_var = tk.StringVar()
        self.high_var = tk.StringVar()

        self.coin_cb = ttk.Combobox(form, textvariable=self.coin_var, values=DEFAULT_YAHOO_SYMBOLS, width=14, state="readonly")
        self.coin_cb.grid(row=1, column=0, padx=(0, 8), pady=6, sticky="w")
        self.coin_cb.set(DEFAULT_YAHOO_SYMBOLS[0])

        ttk.Combobox(form, textvariable=self.cond_var, values=[">=", "<="], width=6, state="readonly") \
            .grid(row=1, column=1, padx=(0, 8), pady=6, sticky="w")

        ttk.Entry(form, textvariable=self.target_var, width=12).grid(row=1, column=2, padx=(0, 8), pady=6, sticky="w")
        ttk.Entry(form, textvariable=self.low_var, width=14).grid(row=1, column=3, padx=(0, 8), pady=6, sticky="w")
        ttk.Entry(form, textvariable=self.high_var, width=14).grid(row=1, column=4, padx=(0, 8), pady=6, sticky="w")

        ttk.Button(form, text="Add alert", command=self.add_alert).grid(row=1, column=5, padx=(6, 0), pady=6, sticky="w")

        # Email settings
        email_box = ttk.LabelFrame(mid, text="Email to send alerts (SMTP)", padding=10)
        email_box.pack(side="right", fill="x")

        self.email_enabled = tk.BooleanVar(value=False)
        ttk.Checkbutton(email_box, text="Enable email alerts", variable=self.email_enabled).grid(row=0, column=0, columnspan=2, sticky="w")

        ttk.Label(email_box, text="To").grid(row=1, column=0, sticky="e", padx=(0, 6))
        ttk.Label(email_box, text="SMTP host").grid(row=2, column=0, sticky="e", padx=(0, 6))
        ttk.Label(email_box, text="SMTP port").grid(row=3, column=0, sticky="e", padx=(0, 6))
        ttk.Label(email_box, text="SMTP user").grid(row=4, column=0, sticky="e", padx=(0, 6))
        ttk.Label(email_box, text="SMTP pass").grid(row=5, column=0, sticky="e", padx=(0, 6))
        ttk.Label(email_box, text="From (optional)").grid(row=6, column=0, sticky="e", padx=(0, 6))

        self.to_var = tk.StringVar()
        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar()
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.from_var = tk.StringVar()

        ttk.Entry(email_box, textvariable=self.to_var, width=34).grid(row=1, column=1, pady=2, sticky="w")
        ttk.Entry(email_box, textvariable=self.host_var, width=34).grid(row=2, column=1, pady=2, sticky="w")
        ttk.Entry(email_box, textvariable=self.port_var, width=10).grid(row=3, column=1, pady=2, sticky="w")
        ttk.Entry(email_box, textvariable=self.user_var, width=34).grid(row=4, column=1, pady=2, sticky="w")
        ttk.Entry(email_box, textvariable=self.pass_var, width=34, show="•").grid(row=5, column=1, pady=2, sticky="w")
        ttk.Entry(email_box, textvariable=self.from_var, width=34).grid(row=6, column=1, pady=2, sticky="w")

        # Alerts table
        table_box = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        table_box.pack(fill="both", expand=True)

        cols = ("Symbol", "Condition", "Target(CAD)", "Last(CAD)", "24h Low", "24h High", "Potential", "Profit est", "Triggered")
        self.tree = ttk.Treeview(table_box, columns=cols, show="headings", height=14)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=120 if c not in ("Symbol","Condition","Triggered") else 90, anchor="center")
        self.tree.column("Symbol", width=110, anchor="w")
        self.tree.column("Triggered", width=90, anchor="center")

        self.tree.pack(side="left", fill="both", expand=True)

        sb = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")

        # bottom buttons/status
        bottom = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")

        ttk.Button(bottom, text="Remove selected", command=self.remove_selected).pack(side="left")
        ttk.Button(bottom, text="Reset triggered on selected", command=self.reset_selected).pack(side="left", padx=(10, 0))

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="right")

    def _load_into_ui(self):
        self.assume_var.set(str(self.state.assume_amount))
        self.refresh_var.set(str(self.state.refresh_seconds))

        self.email_enabled.set(bool(self.state.email.enabled))
        self.to_var.set(self.state.email.to_email)
        self.host_var.set(self.state.email.smtp_host)
        self.port_var.set(str(self.state.email.smtp_port))
        self.user_var.set(self.state.email.smtp_user)
        self.pass_var.set(self.state.email.smtp_pass)
        self.from_var.set(self.state.email.from_email)

        self._render_table()

    def _sync_from_ui(self):
        assume = safe_float(self.assume_var.get())
        if assume is not None and assume >= 0:
            self.state.assume_amount = assume

        rsec = safe_float(self.refresh_var.get())
        if rsec is not None and rsec >= 10:
            self.state.refresh_seconds = int(rsec)

        self.state.email.enabled = bool(self.email_enabled.get())
        self.state.email.to_email = self.to_var.get().strip()
        self.state.email.smtp_host = self.host_var.get().strip()
        self.state.email.smtp_port = int(safe_float(self.port_var.get()) or 587)
        self.state.email.smtp_user = self.user_var.get().strip()
        self.state.email.smtp_pass = self.pass_var.get()
        self.state.email.from_email = self.from_var.get().strip()

    def save_all(self):
        self._sync_from_ui()
        save_state(self.state)
        self.status_var.set("Saved.")

    def _render_table(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        assume = self.state.assume_amount
        for idx, a in enumerate(self.state.alerts):
            pot_pct, profit = compute_potential(a.low_24h_cad, a.high_24h_cad, assume)
            self.tree.insert(
                "", "end", iid=str(idx),
                values=(
                    a.symbol,
                    a.condition,
                    f"{a.target_cad:.4f}",
                    f"{a.last_price_cad:.4f}" if a.last_price_cad is not None else "—",
                    f"{a.low_24h_cad:.4f}" if a.low_24h_cad is not None else "—",
                    f"{a.high_24h_cad:.4f}" if a.high_24h_cad is not None else "—",
                    pot_pct,
                    profit,
                    "YES" if a.triggered else "NO",
                )
            )

    def add_alert(self):
        symbol = self.coin_var.get().strip()
        cond = self.cond_var.get().strip()
        target = safe_float(self.target_var.get())
        low = safe_float(self.low_var.get())
        high = safe_float(self.high_var.get())

        if symbol not in DEFAULT_YAHOO_SYMBOLS:
            messagebox.showerror("Error", "Please choose a coin from the dropdown.")
            return
        if cond not in (">=", "<="):
            messagebox.showerror("Error", "Condition must be >= or <=.")
            return
        if target is None:
            messagebox.showerror("Error", "Target price (CAD) is required.")
            return

        a = Alert(symbol=symbol, condition=cond, target_cad=float(target), low_24h_cad=low, high_24h_cad=high)
        self.state.alerts.append(a)

        self.target_var.set("")
        self.low_var.set("")
        self.high_var.set("")

        self._render_table()
        self.save_all()

    def remove_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        idxs = sorted([int(i) for i in sel], reverse=True)
        for i in idxs:
            if 0 <= i < len(self.state.alerts):
                self.state.alerts.pop(i)
        self._render_table()
        self.save_all()

    def reset_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        for s in sel:
            i = int(s)
            if 0 <= i < len(self.state.alerts):
                self.state.alerts[i].triggered = False
                self.state.alerts[i].last_trigger_ts = None
        self._render_table()
        self.save_all()

    def refresh_now(self):
        # force a fetch in UI thread using worker logic
        threading.Thread(target=self._fetch_update_check, daemon=True).start()

    def send_test_email(self):
        self._sync_from_ui()
        try:
            send_email(self.state.email, "Crypto Tracker test email", "This is a test email from your Crypto Tracker app.")
            messagebox.showinfo("Email", "Test email sent (if SMTP settings are correct).")
        except Exception as e:
            messagebox.showerror("Email error", str(e))

    def _start_worker(self):
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()

    def _worker_loop(self):
        while not self._stop.is_set():
            try:
                self._fetch_update_check()
            except Exception as e:
                self._set_status(f"Error: {e}")
            # sleep in small steps so close is responsive
            total = max(10, int(self.state.refresh_seconds))
            for _ in range(total):
                if self._stop.is_set():
                    break
                time.sleep(1)

    def _set_status(self, text: str):
        def _():
            self.status_var.set(text)
        self.root.after(0, _)

    def _fetch_update_check(self):
        self._sync_from_ui()

        ids = []
        sym_to_id = {}
        for a in self.state.alerts:
            cg_id = YAHOO_TO_COINGECKO.get(a.symbol)
            if cg_id:
                ids.append(cg_id)
                sym_to_id[a.symbol] = cg_id

        if not ids:
            self._set_status("No alerts set. Ready.")
            return

        data = coingecko_fetch(sorted(set(ids)))

        now_ts = time.time()
        triggered_msgs = []

        for a in self.state.alerts:
            cg_id = sym_to_id.get(a.symbol)
            if not cg_id:
                continue

            row = data.get(cg_id, {})
            price = row.get("cad")
            low24 = row.get("cad_24h_low")
            high24 = row.get("cad_24h_high")

            if isinstance(price, (int, float)):
                a.last_price_cad = float(price)

            # If user didn't enter low/high, auto-fill from CoinGecko so potential works
            if a.low_24h_cad is None and isinstance(low24, (int, float)):
                a.low_24h_cad = float(low24)
            if a.high_24h_cad is None and isinstance(high24, (int, float)):
                a.high_24h_cad = float(high24)

            # Alert check
            if a.triggered or a.last_price_cad is None:
                continue

            hit = False
            if a.condition == ">=" and a.last_price_cad >= a.target_cad:
                hit = True
            elif a.condition == "<=" and a.last_price_cad <= a.target_cad:
                hit = True

            if hit:
                a.triggered = True
                a.last_trigger_ts = now_ts
                triggered_msgs.append(
                    f"{a.symbol} {a.condition} {a.target_cad:.4f} CAD\n"
                    f"Current: {a.last_price_cad:.4f} CAD"
                )

        # Save + update UI
        save_state(self.state)
        self.root.after(0, self._render_table)

        # Email any triggers
        if triggered_msgs and self.state.email.enabled:
            subject = f"Crypto Alert Triggered ({len(triggered_msgs)})"
            body = "The following alerts triggered:\n\n" + "\n\n---\n\n".join(triggered_msgs)
            try:
                send_email(self.state.email, subject, body)
                self._set_status(f"Triggered {len(triggered_msgs)} alert(s) — email sent.")
            except Exception as e:
                self._set_status(f"Triggered {len(triggered_msgs)} alert(s) — email failed: {e}")
        elif triggered_msgs:
            self._set_status(f"Triggered {len(triggered_msgs)} alert(s). (Email disabled)")
        else:
            self._set_status("Updated prices. Ready.")

    def on_close(self):
        self._stop.set()
        try:
            self.save_all()
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        # nicer default on Windows
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    CryptoTrackerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
