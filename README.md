# Windows Bruteforce Blocker

## Overview
This script monitors failed RDP login attempts in the Windows Security Event Log and automatically blocks offending IP addresses using Windows Firewall.

It is designed for Windows systems where repeated failed login attempts should trigger an automated response.

---

## Features

- Detects failed login attempts (Event ID 4625)
- Time-based threshold detection
- Automatic firewall blocking
- Simple IP whitelist support
- Logging with daily rotation
- Quarantine logging for blocked IPs
- Optional Telegram notifications

---

## How It Works

The script reads recent Security Event Log entries and counts failed login attempts per IP.

If an IP exceeds the configured threshold within a time window:

1. It checks if the IP is whitelisted
2. It checks if the IP is already blocked
3. It creates a firewall rule to block the IP
4. It logs the action
5. Optionally sends a Telegram notification

---

## Requirements

- Windows
- Python 3.x
- `pywin32`
- `requests`
- Administrative privileges

---

## Configuration

Key settings in the script:

```python
MAX_ATTEMPTS = 5
TIME_WINDOW_MINUTES = 5
CHECK_INTERVAL_SECONDS = 30

## Optional Telegram integration via environment variables:

set TELEGRAM_TOKEN=your_token
set TELEGRAM_CHAT_ID=your_chat_id
