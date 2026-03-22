# -*- coding: cp1252 -*-
import os
import subprocess
from collections import defaultdict
import win32evtlog
import datetime
import requests
import time
import logging
from logging.handlers import TimedRotatingFileHandler

# ------------------- Konfiguration -------------------
MAX_ATTEMPTS = 5
TIME_WINDOW_MINUTES = 5
CHECK_INTERVAL_SECONDS = 30

LOG_DIR = r"C:\logs\rdp-detection"

# Secrets über Umgebungsvariablen
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Whitelist
WHITELIST_IPS = {
    "127.0.0.1",
    "::1",
}

WHITELIST_PREFIXES = [
    "10.",
    "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
]

QUARANTINE_DIR = os.path.join(LOG_DIR, "Quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ------------------- Logging -------------------
logger = logging.getLogger("RDPProtection")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    logfile = os.path.join(LOG_DIR, "rdp_protection.log")
    file_handler = TimedRotatingFileHandler(
        logfile,
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
    )
    file_handler.suffix = "%Y-%m-%d"

    console_handler = logging.StreamHandler()

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)-8s - %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

# ------------------- Hilfsfunktionen -------------------
def is_whitelisted(ip):
    if not ip:
        return True
    if ip in WHITELIST_IPS:
        return True
    return any(ip.startswith(prefix) for prefix in WHITELIST_PREFIXES)


def get_existing_blocked_ips():
    try:
        cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="cp1252")

        blocked_ips = set()
        for line in result.stdout.splitlines():
            if "Block_" in line:
                idx = line.find("Block_")
                if idx != -1:
                    blocked_ips.add(line[idx + len("Block_"):].strip())
        return blocked_ips
    except Exception as e:
        logger.error(f"Fehler beim Auslesen der Firewall-Regeln: {e}")
        return set()


def get_failed_rdp_ips_recent():
    server = "localhost"
    logtype = "Security"
    ip_count = defaultdict(int)

    try:
        hand = win32evtlog.OpenEventLog(server, logtype)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        now = datetime.datetime.now()
        cutoff_time = now - datetime.timedelta(minutes=TIME_WINDOW_MINUTES)

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break

            for event in events:
                if event.TimeGenerated < cutoff_time:
                    return dict(ip_count)

                if event.EventID != 4625:
                    continue

                if event.StringInserts and len(event.StringInserts) >= 19:
                    ip = event.StringInserts[18]
                    if ip and ip != "-":
                        ip_count[ip] += 1

        return dict(ip_count)

    except Exception as e:
        logger.error(f"Fehler beim Lesen des Security-Logs: {e}")
        return {}
    finally:
        try:
            win32evtlog.CloseEventLog(hand)
        except Exception:
            pass


def block_ip(ip):
    try:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Block_{ip}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True, encoding="cp1252")
        logger.info(f"IP gesperrt: {ip}")
        return True
    except Exception as e:
        logger.error(f"Fehler beim Sperren der IP {ip}: {e}")
        return False


def quarantine_ip(ip):
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(QUARANTINE_DIR, f"{ip}_{timestamp}.txt")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"IP {ip} gesperrt am {datetime.datetime.now().isoformat()}")

        logger.info(f"Quarantäne protokolliert für IP: {ip}")
    except Exception as e:
        logger.error(f"Fehler bei Quarantäne-Datei: {e}")


def notify_telegram(message):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return

    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": message}, timeout=10)
    except Exception as e:
        logger.error(f"Telegram-Fehler: {e}")


def check_rdp_attempts():
    failed_ips = get_failed_rdp_ips_recent()
    if not failed_ips:
        return

    blocked_ips = get_existing_blocked_ips()

    for ip, count in failed_ips.items():
        if is_whitelisted(ip):
            continue

        if count < MAX_ATTEMPTS:
            continue

        if ip in blocked_ips:
            continue

        if block_ip(ip):
            quarantine_ip(ip)
            notify_telegram(
                f"IP {ip} nach {count} Fehlversuchen "
                f"in den letzten {TIME_WINDOW_MINUTES} Minuten gesperrt"
            )


# ------------------- Main -------------------
if __name__ == "__main__":
    logger.info("RDP-Schutz gestartet")

    while True:
        check_rdp_attempts()
        time.sleep(CHECK_INTERVAL_SECONDS)
