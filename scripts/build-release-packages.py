#!/usr/bin/env python3
"""Build DEV archives from tracked source with exact commit provenance."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
def git(*args):
    return subprocess.check_output(["git", "-c", f"safe.directory={ROOT}", *args], cwd=ROOT)
def main():
    sha = git("rev-parse", "HEAD").decode().strip()
    version = (ROOT / "VERSION").read_text().strip()
    prefix = f"gateway-vpn-multi-{version}-deployment"
    out = ROOT / "releases" / "public-build"
    out.mkdir(parents=True, exist_ok=True)
    names = git("ls-files", "-z").decode().split("\0")
    source = {name: git("show", f"HEAD:{name}") for name in names
              if name and not name.startswith("releases/")}
    source["SOURCE_COMMIT"] = (sha + "\n").encode()
    tarpath = out / (prefix + ".tar.gz")
    zippath = out / (prefix + ".zip")
    with tarfile.open(tarpath, "w:gz") as tar, zipfile.ZipFile(zippath, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(source.items()):
            arcname = prefix + "/" + name
            info = tarfile.TarInfo(arcname)
            info.size = len(data)
            info.mode = 0o755 if name.endswith(".sh") else 0o644
            tar.addfile(info, io.BytesIO(data))
            zinfo = zipfile.ZipInfo(arcname)
            zinfo.external_attr = info.mode << 16
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(zinfo, data)
    with tarfile.open(tarpath) as tar, zipfile.ZipFile(zippath) as archive:
        assert tar.extractfile(prefix + "/SOURCE_COMMIT").read().decode().strip() == sha
        assert archive.testzip() is None
        assert archive.read(prefix + "/SOURCE_COMMIT").decode().strip() == sha
        for name in ("deploy/webadmin-nginx.conf", "deploy/webadmin-lan-https.conf", "start.sh"):
            assert archive.read(prefix + "/" + name) == source[name]
    manifest = {"commit": sha, "version": version, "files": {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (tarpath, zippath)}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))
if __name__ == "__main__":
    main()
