#!/usr/bin/env python3
"""
Keylogger Detector – detector.py

A lightweight, cross-platform detector for potential keylogger activity.
- Scans running processes (psutil)
- Signature matching (from signatures.json or built-in fallback)
- Simple heuristics (name patterns, hidden-ish processes, suspicious cmdline)
- Optional termination of flagged processes
- Structured logging to ./logs/YYYY-MM-DD_HHMMSS.log

Usage:
  python detector.py                # scan once, print results
  python detector.py --interval 5   # scan every 5 seconds
  python detector.py --terminate    # attempt to terminate flagged processes
  python detector.py --logdir logs  # custom log directory
  python detector.py --once         # single scan (default behavior)

Requirements:
  pip install psutil
  (optional) pip install colorama   # nicer colored terminal output

Safety:
  By default, NO processes are terminated. Use --terminate to enable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    print("[!] psutil is required. Install with: pip install psutil")
    sys.exit(1)

# Optional color support
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_OK = Fore.GREEN + "[+]" + Style.RESET_ALL
    COLOR_WARN = Fore.YELLOW + "[!]" + Style.RESET_ALL
    COLOR_BAD = Fore.RED + "[!]" + Style.RESET_ALL
    COLOR_INFO = Fore.CYAN + "[i]" + Style.RESET_ALL
except Exception:
    COLOR_OK = "[+]"
    COLOR_WARN = "[!]"
    COLOR_BAD = "[!]"
    COLOR_INFO = "[i]"

# -------- Built-in fallback signatures (conservative) --------
# These are intentionally generic/common names seen in commodity keyloggers.
# Your repository's signatures.json can expand/override these.
FALLBACK_SIGNATURES = {
    "process_names": [
        "keylogger", "keylog", "klg", "kl", "hookkey", "winlog", "winhook",
        "logkeys", "pykeylogger", "spyrix", "refog", "ardamax", "ghostpress",
        "kidlogger", "keyscrambler", "keycapture", "keysniffer"
    ],
    # simple substrings to search in command lines
    "cmdline_markers": [
        "--hook", "--keyboard", "--keylog", "keybd_event", "SetWindowsHookEx",
        "GetAsyncKeyState", "XRecordEnableContext", "XGrabKey", "evdev"
    ],
    # absolute or basename paths (use with care; these are only weak hints)
    "paths": []
}

# ------------------------ Logging Setup ------------------------
def setup_logger(logdir: Path) -> Path:
    logdir.mkdir(parents=True, exist_ok=True)
    log_path = logdir / f"{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.log"
    logging.basicConfig(
        filename=str(log_path),
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    # Also log to console (info+)
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger().addHandler(console)
    return log_path

# ------------------------ Signatures ------------------------
def load_signatures(sig_path: Optional[Path]) -> Dict[str, List[str]]:
    if sig_path and sig_path.exists():
        try:
            with sig_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            # Normalize keys
            return {
                "process_names": [s.lower() for s in data.get("process_names", [])],
                "cmdline_markers": [s for s in data.get("cmdline_markers", [])],
                "paths": [s for s in data.get("paths", [])],
            }
        except Exception as e:
            logging.warning(f"{COLOR_WARN} Failed to parse {sig_path}: {e}. Using fallback signatures.")
    # fallback
    return FALLBACK_SIGNATURES

# ------------------------ Heuristics ------------------------
def heuristic_score(proc: psutil.Process) -> Tuple[int, List[str]]:
    """
    Return (score, reasons). Higher score = more suspicious.
    Heuristics are intentionally conservative.
    """
    score = 0
    reasons: List[str] = []

    # Process name hints
    name = ""
    try:
        name = (proc.name() or "").lower()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        name = ""
    if any(k in name for k in ["keylog", "hook", "keyboard"]):
        score += 2
        reasons.append(f"name='{name}' contains keylogging keyword")

    # Hidden-ish / background-ish indicators
    try:
        cmdline = " ".join(proc.cmdline()).lower()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        cmdline = ""
    if cmdline and any(x in cmdline for x in ["--hook", "--keyboard", "setwindowshookex", "getasynckeystate"]):
        score += 2
        reasons.append("cmdline contains keyboard hook markers")

    # Long-lived background process with no terminal (very rough)
    try:
        create_time = proc.create_time()
        cpu_times = proc.cpu_times()
        # If process is very long-lived but almost no user CPU -> could be a background listener
        if (time.time() - create_time) > 6 * 3600 and (cpu_times.user + cpu_times.system) < 5.0:
            score += 1
            reasons.append("long-lived background process with low CPU time")
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass

    # Suspicious open files (Linux often reads from /dev/input/* for key capture)
    try:
        if sys.platform.startswith("linux"):
            for of in proc.open_files():
                if "/dev/input" in of.path:
                    score += 2
                    reasons.append("accessing /dev/input (possible keystroke capture)")
                    break
    except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
        pass

    return score, reasons

# ------------------------ Signature Matching ------------------------
def match_signatures(
    proc: psutil.Process, sigs: Dict[str, List[str]]
) -> Tuple[bool, List[str]]:
    hits: List[str] = []
    try:
        name = (proc.name() or "").lower()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        name = ""
    if name:
        for pat in sigs["process_names"]:
            if pat in name:
                hits.append(f"process_name~='{pat}'")

    cmdline = ""
    try:
        cmdline = " ".join(proc.cmdline())
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        cmdline = ""
    if cmdline:
        for marker in sigs["cmdline_markers"]:
            if marker.lower() in cmdline.lower():
                hits.append(f"cmdline contains '{marker}'")

    try:
        exe = proc.exe() or ""
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        exe = ""
    if exe:
        for p in sigs["paths"]:
            if p and p.lower() in exe.lower():
                hits.append(f"path contains '{p}'")

    return (len(hits) > 0), hits

# ------------------------ Utilities ------------------------
def safe_proc_info(proc: psutil.Process) -> Dict[str, str]:
    info = {"pid": str(proc.pid)}
    try:
        info["name"] = proc.name()
    except Exception:
        info["name"] = "N/A"
    try:
        info["exe"] = proc.exe()
    except Exception:
        info["exe"] = "N/A"
    try:
        info["username"] = proc.username()
    except Exception:
        info["username"] = "N/A"
    try:
        info["cmdline"] = " ".join(proc.cmdline())
    except Exception:
        info["cmdline"] = "N/A"
    return info

def terminate_process(proc: psutil.Process, timeout: float = 3.0) -> bool:
    try:
        proc.terminate()
        proc.wait(timeout=timeout)
        return True
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return True
    except psutil.TimeoutExpired:
        try:
            proc.kill()
            proc.wait(timeout=timeout)
            return True
        except Exception:
            return False
    except psutil.AccessDenied:
        return False

# ------------------------ Scanner ------------------------
def scan_once(
    signatures: Dict[str, List[str]],
    terminate: bool,
    logger: logging.Logger,
) -> Tuple[int, int]:
    suspicious_count = 0
    terminated_count = 0

    for proc in psutil.process_iter(attrs=[], ad_value=None):
        try:
            matched, sig_hits = match_signatures(proc, signatures)
            h_score, h_reasons = heuristic_score(proc)
            if matched or h_score >= 2:
                suspicious_count += 1
                info = safe_proc_info(proc)
                logger.info(
                    f"{COLOR_BAD} Suspicious process detected:\n"
                    f"    Name: {info['name']}\n"
                    f"    PID: {info['pid']}\n"
                    f"    EXE: {info['exe']}\n"
                    f"    User: {info['username']}\n"
                    f"    Cmd: {info['cmdline']}\n"
                    f"    Indicators: {', '.join(sig_hits + h_reasons) if (sig_hits or h_reasons) else 'N/A'}"
                )
                if terminate:
                    ok = terminate_process(proc)
                    if ok:
                        terminated_count += 1
                        logger.info(f"    Action: Terminated")
                    else:
                        logger.info(f"    Action: Termination failed (insufficient permissions or protected process)")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            logger.info(f"{COLOR_WARN} Error scanning PID {getattr(proc, 'pid', '?')}: {e}")

    return suspicious_count, terminated_count

# ------------------------ Main ------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Detect potential keylogger activity via process scanning and signatures."
    )
    p.add_argument("--signatures", type=str, default="signatures.json",
                   help="Path to signatures.json (optional; fallback is built-in)")
    p.add_argument("--logdir", type=str, default="logs",
                   help="Directory for output logs")
    p.add_argument("--interval", type=float, default=0.0,
                   help="Scan interval in seconds. 0 = scan once and exit.")
    p.add_argument("--terminate", action="store_true",
                   help="Attempt to terminate suspicious processes (USE WITH CAUTION).")
    p.add_argument("--once", action="store_true",
                   help="Force a single scan and exit (same as --interval 0).")
    return p.parse_args()

def main():
    args = parse_args()
    log_path = setup_logger(Path(args.logdir))
    logger = logging.getLogger(__name__)

    # Header
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info("════════════════════════════════════════════════════════════")
    logger.info("KEYLOGGER DETECTOR – REAL-TIME SCANNER")
    logger.info("════════════════════════════════════════════════════════════")
    logger.info(f"Time: {ts}")
    logger.info(f"{COLOR_INFO} Log file: {log_path}")
    logger.info(f"{COLOR_INFO} Termination: {'ENABLED' if args.terminate else 'DISABLED'}")
    logger.info("")

    sig_path = Path(args.signatures) if args.signatures else None
    signatures = load_signatures(sig_path)

    # Determine loop behavior
    interval = 0.0 if args.once else float(args.interval)
    if interval < 0:
        interval = 0.0

    try:
        while True:
            start_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            logger.info("------------------------------------------------------------")
            logger.info(f"{COLOR_INFO} Scan started at {start_ts}")
            suspicious, terminated = scan_once(signatures, args.terminate, logger)
            logger.info(f"{COLOR_OK} Scan complete. Suspicious: {suspicious} | Terminated: {terminated}")
            if interval <= 0.0:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info(f"{COLOR_WARN} Stopped by user (CTRL+C).")

    logger.info("Done.")

if __name__ == "__main__":
    main()
