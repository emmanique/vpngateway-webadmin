"""Public MediaHub bootstrap delivers an observer, never a second .env writer."""
import importlib.util
import json
import stat
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1] / "apps/web/public/mediahub-sync/v1"
SCRIPT = ROOT / "scripts/mediahub-gateway-port-sync.py"
spec = importlib.util.spec_from_file_location("mediahub_gateway_observer", SCRIPT)
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def test_observer_publishes_root_protected_port(tmp_path):
    path = tmp_path / "gateway-port-observation.json"
    with patch.object(observer, "OBSERVATION", path):
        observer.publish_observation(
            40819, policy="stremio", mac="bc:24:11:53:5f:65",
            host_ip="192.168.1.199", gateway="192.168.1.231",
            route="vpn-protwg", issued=1000., expiry=1055.)
    data = json.loads(path.read_text())
    assert data["port"] == 40819
    assert data["policy_id"] == "stremio"
    assert data["lease_expires_at"] == 1055.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_observer_refuses_symlink(tmp_path):
    real = tmp_path / "target"
    real.write_text("protected")
    shadow = tmp_path / "observer"
    shadow.symlink_to(real)
    with patch.object(observer, "OBSERVATION", shadow):
        try:
            observer.publish_observation(
                None,policy="stremio",mac="bc:24:11:53:5f:65",
                host_ip="192.168.1.199",gateway="192.168.1.231",
                route=None,issued=None,expiry=None)
        except observer.PortSyncError:
            pass
        else:
            raise AssertionError("Observer must refuse symlink")
    assert real.read_text() == "protected"


def test_no_docker_or_env_writer_in_gateway_observer():
    import inspect
    code = inspect.getsource(observer)
    assert "docker compose up" not in code
    assert "force-recreate" not in code
    assert "STREMIOSRV_BT_LISTEN_PORT" not in code
    assert "def apply_port" not in code


def test_bootstrap_targets_existing_stremio_reconciler():
    installer = (ROOT / "installers/install-mediahub-gateway-port-sync-linux.sh").read_text()
    assert 'com.docker.compose.project.working_dir' in installer
    assert '"SOURCE":"observation"' in installer
    assert '"ENABLED":"1"' in installer
    assert "stremio-webadmin-reconcile" not in installer or "timer" in installer
