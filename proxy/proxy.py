import sys
import subprocess
import importlib.util

# =========================================
# REQUIREMENTS CHECK + AUTO INSTALL
# =========================================
def ensure_requirements():
    required = [
        "mitmproxy",
    ]

    missing = []
    for pkg in required:
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)

    if missing:
        print(f"[REQ] Missing packages detected: {missing}")
        print("[REQ] Installing now...")

        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", *missing]
            )
            print("[REQ] Installation complete.")
        except Exception as e:
            print(f"[REQ ERROR] Failed to install requirements: {e}")
            print("[REQ] Please run manually:")
            print(f"    pip install {' '.join(missing)}")
            sys.exit(1)

ensure_requirements()

# =========================================
# YOUR ORIGINAL SCRIPT
# =========================================
import json
import os
from mitmproxy import http, ctx
from pathlib import Path

GUEST_FILE = "guest.json"
guest_cache = {}
last_mtime = 0

BASE_DIR = Path(__file__).parent

# -------------------------------
# Save the mitmproxy certificate
# -------------------------------
def save_mitmproxy_cert():
    try:
        home = os.path.expanduser("~/.mitmproxy")
        ca_cert = os.path.join(home, "mitmproxy-ca-cert.pem")
        output_file = BASE_DIR / "certificate.pem"

        if os.path.exists(ca_cert):
            with open(ca_cert, "rb") as src, open(output_file, "wb") as dst:
                dst.write(src.read())
            print(f"[CERT] Certificate copied to: {output_file}")
        else:
            print("[CERT] CA file not found in ~/.mitmproxy")
    except Exception as e:
        print(f"[CERT ERROR] {e}")

save_mitmproxy_cert()


def load_guest():
    global guest_cache, last_mtime

    try:
        mtime = os.path.getmtime(GUEST_FILE)
        if mtime != last_mtime:
            with open(GUEST_FILE, "r", encoding="utf-8") as f:
                guest_cache = json.load(f)
            last_mtime = mtime
            print("[+] guest.json reloaded:", guest_cache)
    except Exception as e:
        print("[!] guest.json error:", e)


class GuestProxy:

    def request(self, flow: http.HTTPFlow):
        if flow.request.method == "POST" and "/api/v2/oauth/guest/token:grant" in flow.request.path:

            load_guest()

            try:
                data = json.loads(flow.request.get_text())

                if "uid" in guest_cache:
                    data["uid"] = guest_cache["uid"]

                if "password" in guest_cache:
                    data["password"] = guest_cache["password"]

                new_body = json.dumps(data, separators=(",", ":"))
                flow.request.set_text(new_body)

                content_length = len(new_body.encode("utf-8"))
                flow.request.headers["Content-Length"] = str(content_length)

                print("[*] Request modified")
                print("    UID:", data.get("uid"))
                print("    Password:", data.get("password"))

            except Exception as e:
                print("[!] JSON parse error:", e)

    def response(self, flow: http.HTTPFlow):
        if "/api/v2/oauth/guest/token:grant" in flow.request.path:
            if flow.response and flow.response.status_code == 200:
                print("[+] Auth success -> shutting down proxy")
                #ctx.master.shutdown()


addons = [GuestProxy()]
