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

# --- Konfiguration ---
MAX_ATTEMPTS = 5
LOG_DIR = r"X:\logs\rdp-detection"  # Dein Log-Ordner
TELEGRAM_TOKEN = "DEIN_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "DEIN_CHAT_ID"
TIME_WINDOW_MINUTES = 5
CHECK_INTERVAL_SECONDS = 30

# Quarantäne-Ordner im Log-Verzeichnis
QUARANTINE_DIR = os.path.join(LOG_DIR, "Quarantine")
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

# ------------------- Logging -------------------
logger = logging.getLogger("RDPSchutz")
logger.setLevel(logging.INFO)
logger.propagate = False

logfile = os.path.join(LOG_DIR, "rdp_protection.log")
handler = TimedRotatingFileHandler(
    logfile, when="midnight", interval=1, backupCount=7, encoding="utf-8"
)
handler.setLevel(logging.INFO)
handler.suffix = "%Y-%m-%d"

# --- Konsole ohne Farben ---
console = logging.StreamHandler()
console.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s - %(levelname)-8s - %(message)s",
    "%Y-%m-%d %H:%M:%S"
)

console.setFormatter(formatter)
handler.setFormatter(formatter)

logger.addHandler(handler)
logger.addHandler(console)

# ------------------- Funktionen -------------------

def is_ip_blocked(ip):
    cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return f"Block_{ip}" in result.stdout

def get_failed_rdp_ips_recent():
    server = 'localhost'
    logtype = 'Security'
    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    ip_count = defaultdict(int)
    now = datetime.datetime.now()
    cutoff_time = now - datetime.timedelta(minutes=TIME_WINDOW_MINUTES)

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break
        for e in events:
            event_time = e.TimeGenerated
            if event_time < cutoff_time:
                return ip_count
            if e.EventID == 4625:
                if e.StringInserts and len(e.StringInserts) >= 18:
                    ip = e.StringInserts[18]
                    if ip != "-":
                        ip_count[ip] += 1
    return ip_count

def block_ip(ip):
    try:
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"
        ]
        subprocess.run(cmd, check=True)
        logger.info(f"IP {ip} gesperrt")
        return True
    except subprocess.CalledProcessError:
        logger.error(f"Fehler beim Sperren der IP {ip}")
        return False

def quarantine_ip(ip):
    filepath = os.path.join(
        QUARANTINE_DIR, f"{ip}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    )
    with open(filepath, "w") as f:
        f.write(f"IP {ip} gesperrt am {datetime.datetime.now()}")
    logger.info(f"IP {ip} in Quarantäne protokolliert")

def notify_telegram(message):
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        try:
            requests.post(url, data=payload)
        except Exception as e:
            logger.error(f"Telegram-Fehler: {e}")

def check_rdp_attempts():
    failed_ips = get_failed_rdp_ips_recent()
    for ip, count in failed_ips.items():
        if count >= MAX_ATTEMPTS:
            if not is_ip_blocked(ip):
                if block_ip(ip):
                    quarantine_ip(ip)
                    notify_telegram(
                        f"IP {ip} nach {count} Fehlversuchen in den letzten {TIME_WINDOW_MINUTES} Minuten gesperrt"
                    )
            else:
                logger.info(f"IP {ip} ist bereits gesperrt")

# Dauerbetrieb
if __name__ == "__main__":
    logger.info(f"RDP-Schutz gestartet, prüft alle {CHECK_INTERVAL_SECONDS} Sekunden...")
    while True:
        check_rdp_attempts()
        for remaining in range(CHECK_INTERVAL_SECONDS, 0, -1):
            print(f"\rNächste Prüfung in {remaining} Sekunden...", end="", flush=True)
            time.sleep(1)
        print("\rStarte nächste Prüfung...               ")
