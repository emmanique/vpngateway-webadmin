#!/usr/bin/env bash
# Local equivalent of .github/workflows/ci.yml; authorized QA hosts only.
# Source is an immutable git archive. No Compose, VPN or host routes are changed.
set -Eeuo pipefail
umask 077
usage() {
  echo 'Usage: sudo bash scripts/run-local-ci.sh [--job all|api|web|containers|dataplane] [--python /path/python] [--output /absolute/path]'
}
JOB=all
PYTHON="$(command -v python3)"
OUTPUT=''
while (($#)); do
  case "$1" in
    --job) JOB="$2"; shift 2;;
    --python) PYTHON="$2"; shift 2;;
    --output) OUTPUT="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) usage >&2; exit 2;;
  esac
done
case "$JOB" in api|web|containers|dataplane|all) ;; *) echo "Invalid job $JOB" >&2; exit 2;; esac
for c in git tar docker; do command -v "$c" >/dev/null || { echo "Missing $c" >&2; exit 2; }; done
SOURCE="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
SHA="$(git -C "$SOURCE" rev-parse HEAD)"
SHORT="$(printf '%s' "$SHA" | cut -c 1-12)"
if [[ -z "$OUTPUT" ]]; then OUTPUT="/var/tmp/vpngw-local-ci/$(date -u +%Y%m%dT%H%M%SZ)-$SHORT"; fi
[[ "$OUTPUT" = /* ]] || { echo "Output must be absolute" >&2; exit 2; }
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd -P)"
SUMMARY="$OUTPUT/summary.tsv"
printf 'job\tresult\texit_code\tlog\n' > "$SUMMARY"
WORK="$(mktemp -d /var/tmp/vpngw-ci-src-XXXXXXXX)"
trap 'rm -rf -- "$WORK"' EXIT
git -C "$SOURCE" archive HEAD | tar -x -C "$WORK"
printf '%s\n' "$SHA" > "$OUTPUT/commit.sha"
export CI_LOCAL_SOURCE="$WORK"
export CI_LOCAL_PYTHON="$PYTHON"
export CI_LOCAL_TAG="ci-$SHORT"
FAILED=0
run_job() {
  local name="$1" steps="$2" rc=0
  echo "RUN $name"
  (cd "$WORK" && bash -Eeuo pipefail -c "$steps") >"$OUTPUT/$name.log" 2>&1 || rc=$?
  if ((rc)); then
    FAILED=1
    echo "FAIL $name (exit $rc)"
    tail -20 "$OUTPUT/$name.log" || true
    printf '%s\tFAIL\t%s\t%s\n' "$name" "$rc" "$OUTPUT/$name.log" >> "$SUMMARY"
  else
    echo "PASS $name"
    printf '%s\tPASS\t0\t%s\n' "$name" "$OUTPUT/$name.log" >> "$SUMMARY"
  fi
}
echo "Source revision: $SHA; logs: $OUTPUT"
if [[ "$JOB" = all || "$JOB" = api ]]; then
  command -v "$PYTHON" >/dev/null || { echo "Python unavailable" >&2; exit 2; }
  run_job api '
    "$CI_LOCAL_PYTHON" -m compileall -q apps/api scripts
    "$CI_LOCAL_PYTHON" scripts/audit-static-dependencies.py --strict
    bash -n start.sh installers/install-policy-agent-linux.sh scripts/build-proton-natpmpc-isolated.sh
    bash scripts/build-proton-natpmpc-isolated.sh --build-only
    "$CI_LOCAL_PYTHON" -m unittest discover -s tests -p test_qa_install_release_contract.py -v
    "$CI_LOCAL_PYTHON" -m unittest discover -s tests -p "test_*.py" -q
    PYTHONPATH=apps/api "$CI_LOCAL_PYTHON" -m unittest discover -s apps/api/tests -p test_host_port_settings.py -v
    PYTHONPATH=apps/api "$CI_LOCAL_PYTHON" -m unittest discover -s apps/api/tests -p test_rebind_watcher.py -v
    PYTHONPATH=apps/api "$CI_LOCAL_PYTHON" -m pytest -q apps/api/tests/test_port_forward_plan.py
  '
fi
if [[ "$JOB" = all || "$JOB" = web ]]; then
  command -v npm >/dev/null || { echo "npm unavailable" >&2; exit 2; }
  run_job web '
    cd apps/web
    npm ci --fetch-retries=5 --fetch-timeout=180000 --no-audit --no-fund
    npm run build
  '
fi
if [[ "$JOB" = all || "$JOB" = containers ]]; then
  run_job container_webadmin '
    docker build -t "vpngateway/webadmin:$CI_LOCAL_TAG" -f apps/web/Dockerfile.webadmin .
    docker run --rm --network none --entrypoint nginx "vpngateway/webadmin:$CI_LOCAL_TAG" -t
    docker run --rm --network none --entrypoint python "vpngateway/webadmin:$CI_LOCAL_TAG" -c "import main, system_maintenance, host_transition_plan"
    docker run --rm --network none --entrypoint python "vpngateway/webadmin:$CI_LOCAL_TAG" -V
    # Run the full unit suite with the CI-matching Python 3.12 runtime too.
    docker run --rm --network none -v "$CI_LOCAL_SOURCE:/repo:ro" -w /repo \
      -e PYTHONPATH=/repo/apps/api --entrypoint python \
      "vpngateway/webadmin:$CI_LOCAL_TAG" -m unittest discover -s tests -p "test_*.py" -q
  '
  run_job container_vpn '
    docker build -t "vpngateway/vpn:$CI_LOCAL_TAG" -f apps/vpn/Dockerfile apps/vpn
    docker run --rm --network none --entrypoint python "vpngateway/vpn:$CI_LOCAL_TAG" -c "from pathlib import Path; compile(Path(\"/app/health.py\").read_text(), \"/app/health.py\", \"exec\")"
  '
fi
if [[ "$JOB" = all || "$JOB" = dataplane ]]; then
  [[ $EUID -eq 0 ]] || { echo "Root required for network namespaces" >&2; exit 2; }
  for c in nft ip unshare ping; do command -v "$c" >/dev/null || { echo "Missing $c" >&2; exit 2; }; done
  run_job dataplane '
    for mode in shared routed multi_lan; do unshare --net -- python3 scripts/test-topology-dataplane.py "$mode"; done
    bash scripts/test-vpn-recovery-netns.sh
    bash scripts/test-dns-central-netns.sh
    bash scripts/test-dns-cutover-rollback-netns.sh
    unshare --net -- python3 scripts/test-dns-origin-dnat-netns.py
    unshare --net -- env VPNGW_ISOLATED_NETNS=1 python3 scripts/test-port-forward-netns.py
  '
fi
cat "$SUMMARY"
echo "RESULT_REPORT=$SUMMARY"
if ((FAILED)); then echo "LOCAL_CI_FAILED" >&2; exit 1; fi
echo "LOCAL_CI_PASSED revision=$SHA (not a GitHub-hosted check)"
