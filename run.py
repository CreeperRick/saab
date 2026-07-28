"""
Run the server on your local network so your Android device/emulator can
reach it.

Usage:
    python run.py

Then find your machine's LAN IP (e.g. `ipconfig` on Windows, `ifconfig` /
`ip addr` on Mac/Linux — look for something like 192.168.1.x) and point the
Android app at http://<that-ip>:8000

If you're using the Android Emulator (not a real phone), use 10.0.2.2:8000
instead — that's the special alias the emulator uses to reach your host
machine's localhost.
"""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
