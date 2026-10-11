#!/usr/bin/env python3
"""On WAN recovery, distinguish an existing interface from a working WG session.
Exit 0 healthy, 3 stale/unresponsive; read-only (caller preserves kill switch).
"""
import subprocess,sys,time
IFACE="wga509c86fbd2"
def run(*args,timeout=6):
 return subprocess.run(args,capture_output=True,text=True,timeout=timeout)
def health():
 link=run("ip","link","show","dev",IFACE)
 if link.returncode:return False,"interface_missing"
 handshakes=run("wg","show",IFACE,"latest-handshakes")
 if handshakes.returncode:return False,"wireguard_status_missing"
 try: latest=max(int(row.split()[-1]) for row in handshakes.stdout.splitlines() if row.split())
 except ValueError:return False,"no_handshake"
 age=time.time()-latest if latest else float("inf")
 if age<180:return True,"handshake_recent"
 # A stale timestamp alone must not prompt unnecessary tunnel disruption.
 probe=run("ping","-c","1","-W","2","-I",IFACE,"1.1.1.1",timeout=4)
 if probe.returncode==0:return True,"tunnel_probe_ok"
 return False,"stale_handshake_and_failed_probe"
if __name__=="__main__":
 ok,reason=health()
 print(reason)
 sys.exit(0 if ok else 3)
