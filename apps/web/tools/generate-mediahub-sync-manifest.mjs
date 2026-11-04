// Versioned, static MediaHub Linux host installer assets shipped by the
// VPN Gateway WebAdmin. Generated during build, before Vite copies /public.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../public/mediahub-sync/v1");
const files = [
  "scripts/mediahub-gateway-port-sync.py",
  "deploy/systemd/mediahub-gateway-port-sync.service",
  "deploy/systemd/mediahub-gateway-port-sync.timer",
  "deploy/examples/mediahub-port-sync.conf.example",
  "installers/install-mediahub-gateway-port-sync-linux.sh",
];
const entries = files.map((name) => {
  const bytes = readFileSync(path.join(root, name));
  return `${createHash("sha256").update(bytes).digest("hex")}  ${name}`;
});
writeFileSync(path.join(root, "SHA256SUMS"), entries.join("\n") + "\n");
console.log("MediaHub gateway-hosted bundle manifest created:", files.length, "assets");
