"""Non-privileged VPN service placeholder; no network policy changes."""
import json
import time
print(json.dumps({'component':'vpn','status':'scaffold','network_changes':False}),flush=True)
while True:
    time.sleep(3600)
