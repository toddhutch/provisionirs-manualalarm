# =============================================================================
# nvr_gate.py - Provision-ISR NVR8-8200PFA Gate Control (Local Network)
# Author: Todd + Grok
# Date: December 07, 2025
# =============================================================================
#
# WHAT THIS SCRIPT DOES
# This script provides reliable, fast control of the two gate relays on the
# Provision-ISR NVR8-8200PFA via the device's native web API:
# - Channel 3 → EXIT gate  (AlarmOut3OPENEXIT) GUID: {F8AC77CF-2902-F240-91A3-D312B9338A7B}   you will need to trigger a manual alarm while logged in your NVR and use the f12 tools to see what guid it is for the channel you want to trigge
# - Channel 4 → ENTRY gate (AlarmOut4OPENENTRY) GUID: {FBEFBC1A-3E31-794F-8435-8D5CD1269C19}   you will need to trigger a manual alarm while logged in your NVR and use the f12 tools to see what guid it is for the channel you want to trigge
#
# Usage:
# python nvr_gate.py on 3          # Opens EXIT gate
# python nvr_gate.py off 3         # Closes EXIT gate
# python nvr_gate.py on 4          # Opens ENTRY gate
# python nvr_gate.py off 4         # Closes ENTRY gate
# python nvr_gate.py refresh       # Forces logout + fresh login (refreshes credentials)
#
# The script automatically falls back to a fresh login if the stored credentials fail,
# and it saves the new sessionId + token to credentials.json for instant future use.
#
# HOW IT WORKS (Windows 11 / Raspberry Pi – identical behaviour)
# 1. Credential Reuse (credentials.json)
#    - On first run (or when credentials expire), the script uses Playwright to launch a
#      headless Chromium browser, logs into http://192.168.1.??, handles the privacy dialog
#      if shown, and captures the sessionId cookie and security token from /doLogin.
#    - These are saved to credentials.json in the same folder.
#    - Subsequent runs load the saved credentials and skip the browser entirely –
#      making the command almost instant (<1 second).
#
# 2. Triggering the Alarm Output
#    - Uses the stored (or freshly obtained) sessionId and token with the requests library
#      to call /setAlarmOutStatus with the hard-coded GUIDs for the correct relay.
#
# 3. Automatic Refresh + "refresh" command
#    - If a trigger fails (session expired/invalid), the script automatically logs in again,
#      overwrites credentials.json, and retries the command.
#    - Running "python nvr_gate.py refresh" explicitly logs out the current session
#      (if any) and performs a fresh login – useful after an NVR reboot, firmware update,
#      or long inactivity.
#
# Requirements (installed once):
#   pip install playwright requests
#   playwright install chromium --with-deps   # installs browser + system dependencies
#
# This approach gives the fastest, most reliable local control without the SDK, DLLs,
# Wine, or box86.
#
# =============================================================================
# DEPLOYMENT TO RASPBERRY PI CM4 (or any Raspberry Pi)
# =============================================================================
#
# 1. Copy the script (and optional existing credentials.json) to the Pi:
#    scp nvr_gate.py pi@your-pi-ip:~/nvr_gate.py
#
# 2. Create a virtual environment (recommended):
#    mkdir ~/nvr-gate && cd ~/nvr-gate
#    python3 -m venv venv
#    source venv/bin/activate
#
# 3. Install dependencies inside the venv:
#    pip install --upgrade pip
#    pip install playwright requests
#    playwright install chromium --with-deps   # ~100 MB, runs headlessly on CM4
#
# 4. Run the script:
#    source venv/bin/activate
#    python nvr_gate.py on 3   # or off 3, on 4, off 4, refresh
#
# 5. Make it convenient (optional – add to ~/.bashrc):
#    alias gate-exit-on='~/nvr-gate/venv/bin/python ~/nvr-gate/nvr_gate.py on 3'
#    alias gate-exit-off='~/nvr-gate/venv/bin/python ~/nvr-gate/nvr_gate.py off 3'
#    alias gate-entry-on='~/nvr-gate/venv/bin/python ~/nvr-gate/nvr_gate.py on 4'
#    alias gate-entry-off='~/nvr-gate/venv/bin/python ~/nvr-gate/nvr_gate.py off 4'
#    source ~/.bashrc
#
#   Or create gate.sh nano gate.sh
#       cd /home/toddhutch/nvr-gate
#       source venv/bin/activate
#       python nvr_gate.py "$@"
#
#   chmod +x ~/nvr-gate/gate.sh
#
# 6. Home Assistant Integration (optional – shell_command in configuration.yaml):
#    shell_command:
#       autumn_cache_open_entry_gate: "ssh -i /config/.ssh/id_ed25519_gate -o StrictHostKeyChecking=no toddhutch@cm4.home '/home/toddhutch/nvr-gate/gate.sh on 4'"
#       autumn_cache_close_entry_gate: "ssh -i /config/.ssh/id_ed25519_gate -o StrictHostKeyChecking=no toddhutch@cm4.home '/home/toddhutch/nvr-gate/gate.sh off 4'"
#       autumn_cache_open_exit_gate:  "ssh -i /config/.ssh/id_ed25519_gate -o StrictHostKeyChecking=no toddhutch@cm4.home '/home/toddhutch/nvr-gate/gate.sh on 3'"
#       autumn_cache_close_exit_gate: "ssh -i /config/.ssh/id_ed25519_gate -o StrictHostKeyChecking=no toddhutch@cm4.home '/home/toddhutch/nvr-gate/gate.sh off 3'"
#       autumn_cache_refresh: "ssh -i /config/.ssh/id_ed25519_gate -o StrictHostKeyChecking=no toddhutch@cm4.home '/home/toddhutch/nvr-gate/gate.sh refresh'"
#
# The exact same script runs on both Windows 11 and Raspberry Pi CM4 – credential reuse,
# automatic fallback, and the explicit "refresh" command all work identically.
# =============================================================================
from playwright.sync_api import sync_playwright
import requests
import xml.etree.ElementTree as ET
import sys
import json
import os

# --------------------- CONFIG (LOCAL ONLY) ---------------------
BASE_URL = "http://192.168.1.??"    #put in your NVR local IP address here
USERNAME = "???????"     # put in your username here
PASSWORD = "????????"    #put in your password here
GUID_MAP = {
    3: "{F8AC77CF-2902-F240-91A3-D312B9338A7B}",  # EXIT gate you will need to trigger a manual alarm while logged in your NVR and use the f12 tools to see what guid it is for the channel you want to trigger
    4: "{FBEFBC1A-3E31-794F-8435-8D5CD1269C19}"   # ENTRY gate you will need to trigger a manual alarm while logged in your NVR and use the f12 tools to see what guid it is for the channel you want to trigger
}
CREDENTIALS_FILE = "credentials.json"
# --------------------------------------------------------------

def fresh_login():
    print("Performing fresh login...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        page.goto(BASE_URL)

        # Accept privacy dialog if it appears
        try:
            if page.locator("#privacyView").is_visible(timeout=5000):
                page.check("#privacyOk")
                page.click("#btnOK")
                page.wait_for_timeout(1000)
        except:
            pass

        captured_token = [None]
        def capture_token(response):
            if "/doLogin" in response.url and response.status == 200:
                try:
                    root = ET.fromstring(response.text())
                    token_el = root.find('.//token')
                    if token_el is not None:
                        captured_token[0] = token_el.text
                except:
                    pass

        page.on("response", capture_token)

        page.fill("#txtUserName", USERNAME)
        page.fill("#txtPassword", PASSWORD)
        page.click("#btnLogin")
        page.wait_for_url("**/#live", timeout=15000)

        cookies = context.cookies()
        session_id = next((c['value'] for c in cookies if c['name'] == 'sessionId'), None)
        browser.close()

        if not session_id or not captured_token[0]:
            print("Fresh login failed – could not obtain sessionId or token")
            return None, None

        # Save new credentials
        creds = {"session_id": session_id, "token": captured_token[0]}
        with open(CREDENTIALS_FILE, "w") as f:
            json.dump(creds, f, indent=4)

        print(f"Fresh login SUCCESS! Credentials saved to {CREDENTIALS_FILE}")
        return session_id, captured_token[0]

def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        return None, None
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            data = json.load(f)
            return data.get("session_id"), data.get("token")
    except Exception as e:
        print(f"Error loading credentials: {e}")
        return None, None

def logout(session_id, token):
    if not session_id or not token:
        print("No valid credentials to log out with.")
        return False

    print("Performing logout...")
    s = requests.Session()
    s.cookies.set("sessionId", session_id)
    xml = f'''<?xml version="1.0" encoding="utf-8" ?>
<request version="1.0" systemType="NVMS-9000" clientType="WEB">
    <token>{token}</token>
</request>'''
    r = s.post(f"{BASE_URL}/doLogout", data=xml, timeout=10)
    success = r.ok and 'success' in r.text.lower()
    print("Logout:", "SUCCESS" if success else "FAILED")

    # Remove the old credentials file after successful logout
    if success and os.path.exists(CREDENTIALS_FILE):
        os.remove(CREDENTIALS_FILE)
        print(f"Old credentials file {CREDENTIALS_FILE} removed.")
    return success

def trigger_alarm(session_id, token, user_channel, turn_on):
    if user_channel not in GUID_MAP:
        print("Error: Only channels 3 (EXIT) and 4 (ENTRY) supported")
        return False

    guid = GUID_MAP[user_channel]
    gate_name = "EXIT gate (AlarmOut3OPENEXIT)" if user_channel == 3 else "ENTRY gate (AlarmOut4OPENENTRY)"
    s = requests.Session()
    s.cookies.set("sessionId", session_id)

    switch = "true" if turn_on else "false"
    xml = f'''<?xml version="1.0" encoding="utf-8" ?>
<request version="1.0" systemType="NVMS-9000" clientType="WEB">
    <token>{token}</token>
    <content>
        <switch>{switch}</switch>
        <alarmOutIds type="list">
            <item id="{guid}"></item>
        </alarmOutIds>
    </content>
</request>'''

    r = s.post(f"{BASE_URL}/setAlarmOutStatus", data=xml, timeout=10)
    action = "OPEN" if turn_on else "CLOSE"
    success = r.ok and 'success' in r.text.lower()
    print(f"{gate_name} → {action} : {'SUCCESS' if success else 'FAILED (status {r.status_code})'}")
    return success

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python nvr_gate.py on|off 3|4   (3=EXIT gate, 4=ENTRY gate)")
        print("  python nvr_gate.py refresh     (force logout + fresh login)")
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "refresh":
        # Log out first if we have credentials, then do a fresh login
        session_id, token = load_credentials()
        logout(session_id, token)
        session_id, token = fresh_login()
        if session_id and token:
            print("Credentials successfully refreshed.")
        else:
            print("Failed to refresh credentials.")
        sys.exit(0)

    if cmd not in ["on", "off"] or len(sys.argv) != 3 or sys.argv[2] not in ["3", "4"]:
        print("Invalid arguments.")
        print("Usage:")
        print("  python nvr_gate.py on|off 3|4   (3=EXIT gate, 4=ENTRY gate)")
        print("  python nvr_gate.py refresh     (force logout + fresh login)")
        sys.exit(1)

    turn_on = (cmd == "on")
    user_channel = int(sys.argv[2])

    # Try stored credentials first
    session_id, token = load_credentials()
    if session_id and token:
        print("Using stored credentials...")
        if trigger_alarm(session_id, token, user_channel, turn_on):
            sys.exit(0)
        else:
            print("Stored credentials failed – performing fresh login...")

    # Fall back to fresh login
    session_id, token = fresh_login()
    if session_id and token:
        trigger_alarm(session_id, token, user_channel, turn_on)
    else:
        print("Unable to obtain valid credentials. Gate command failed.")
        sys.exit(1)
