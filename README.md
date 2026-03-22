# Windows Bruteforce Blocker

## Overview
This script monitors failed RDP login attempts in the Windows Security Event Log and automatically blocks offending IP addresses using Windows Firewall.

It is intended for Windows systems where repeated failed login attempts should trigger an automated response.

---

## Features

- Detects failed RDP login attempts from the Windows Security log
- Counts repeated failures within a defined time window
- Blocks offending IPs via Windows Firewall
- Avoids duplicate firewall rules for already blocked IPs
- Logs all actions to rotating log files
- Stores simple quarantine records for blocked IPs
- Optional Telegram notifications

---

## How It Works

The script reads recent Windows Security events and looks for failed login events (`Event ID 4625`).

If an IP address exceeds the configured threshold within the defined time window, the script:

1. checks whether the IP is already blocked
2. creates a Windows Firewall block rule
3. writes a quarantine log entry
4. optionally sends a Telegram notification

---

## Requirements

- Windows
- Python 3.x
- `pywin32`
- `requests`
- Administrative privileges
- Access to the Windows Security Event Log
- Permission to create Windows Firewall rules

---

## Configuration

Main configuration values in the script:

- `MAX_ATTEMPTS`
- `TIME_WINDOW_MINUTES`
- `CHECK_INTERVAL_SECONDS`
- `LOG_DIR`
- `TELEGRAM_TOKEN`
- `TELEGRAM_CHAT_ID`

Example:

```python
MAX_ATTEMPTS = 5
TIME_WINDOW_MINUTES = 5
CHECK_INTERVAL_SECONDS = 30
