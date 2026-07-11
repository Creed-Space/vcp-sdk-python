"""Install, lockfile, verify_tree, ref/namespace/scheme validation, and the
never-execute invariant for vcp.hub.

The load-bearing security property here: an installed artifact is *data*. No
code path imports, evals, or executes it, and the lockfile pins it so later
drift is caught.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from conftest import TEST_KEY_ID, build_entry_dict, make_sidecar, write_version_dir
from vcp.hub import cli
from vcp.hub import install as install_mod
from vcp.hub.errors import HubError, VerificationError
from vcp.hub.install import install, verify_tree
from vcp.hub.registry import RegistryClient, validate_ref

REF = "creed-space/anti_gaslighting"
ARTIFACT_ID = "anti_gaslighting"


@pytest.fixture
def hub(make_hub):
    return make_hub()


def _install(ref: str, hub_root: Path, target: Path):
    return install(ref, target, RegistryClient(str(hub_root)))


def test_install_writes_artifact_sig_and_entry(hub, tmp_path):
    target = tmp_path / "artifacts"

    result = _install(REF, hub, target)

    version_dir = target / "creed-space" / ARTIFACT_ID / "1.0.0"
    assert (version_dir / f"{ARTIFACT_ID}.md").is_file()
    assert (version_dir / f"{ARTIFACT_ID}.md.ed25519.sig").is_file()
    assert json.loads((version_dir / "entry.json").read_text())["id"] == ARTIFACT_ID
    assert result.version == "1.0.0"


def test_install_pins_version_hash_and_key_in_lockfile(hub, tmp_path):
    target = tmp_path / "artifacts"

    result = _install(REF, hub, target)

    lock = json.loads((target / "vcp.lock").read_text())
    assert lock["artifacts"][REF] == {
        "version": "1.0.0",
        "content_sha256": result.content_sha256,
        "key_id": TEST_KEY_ID,
        "artifact": f"{ARTIFACT_ID}.md",
        "trust_tier": "signed",
    }


def test_install_from_a_file_url_registry(hub, tmp_path):
    """The explicit file:// branch (url2pathname) resolves the same tree as a bare path."""
    target = tmp_path / "artifacts"

    result = install(REF, target, RegistryClient(f"file://{hub}"))

    assert result.version == "1.0.0"
    assert verify_tree(target) == [f"{REF}@1.0.0"]


def test_install_accepts_an_explicit_version(hub, tmp_path):
    result = _install(f"{REF}@1.0.0", hub, tmp_path / "artifacts")

    assert result.version == "1.0.0"


def test_install_of_an_unknown_version_is_refused(hub, tmp_path):
    with pytest.raises(HubError, match="not found in registry index"):
        _install(f"{REF}@9.9.9", hub, tmp_path / "artifacts")


def test_verify_tree_passes_after_install(hub, tmp_path):
    target = tmp_path / "artifacts"
    _install(REF, hub, target)

    assert verify_tree(target) == [f"{REF}@1.0.0"]


def test_verify_tree_detects_a_tampered_artifact(hub, tmp_path):
    target = tmp_path / "artifacts"
    _install(REF, hub, target)
    installed = target / "creed-space" / ARTIFACT_ID / "1.0.0" / f"{ARTIFACT_ID}.md"
    installed.write_bytes(installed.read_bytes() + b"\nsmuggled clause\n")

    with pytest.raises(VerificationError, match="drifted"):
        verify_tree(target)


def test_verify_tree_detects_a_deleted_signature(hub, tmp_path):
    target = tmp_path / "artifacts"
    _install(REF, hub, target)
    (target / "creed-space" / ARTIFACT_ID / "1.0.0" / f"{ARTIFACT_ID}.md.ed25519.sig").unlink()

    with pytest.raises(VerificationError, match="signature missing"):
        verify_tree(target)


def test_verify_tree_detects_lockfile_hash_drift(hub, tmp_path):
    target = tmp_path / "artifacts"
    _install(REF, hub, target)
    lock_path = target / "vcp.lock"
    lock = json.loads(lock_path.read_text())
    lock["artifacts"][REF]["content_sha256"] = "0" * 64
    lock_path.write_text(json.dumps(lock))

    with pytest.raises(VerificationError, match="content hash mismatch"):
        verify_tree(target)


def test_foreign_namespace_is_launch_locked():
    with pytest.raises(HubError, match="not yet open"):
        validate_ref("somebody-else/thing")


@pytest.mark.parametrize("ref", ["creed_space/x", "creedspace/x"])
def test_confusable_namespaces_are_refused(ref):
    with pytest.raises(HubError):
        validate_ref(ref)


@pytest.mark.parametrize(
    "ref",
    ["creed-space/../etc", "creed-space/UPPER", "creed-space/x@1.0", "x"],
)
def test_malformed_refs_are_refused(ref):
    with pytest.raises(HubError):
        validate_ref(ref)


def test_install_refuses_an_entry_whose_hash_disagrees_with_the_artifact(hub, tmp_path):
    """T2: the registry entry cannot re-point a signed artifact at other bytes."""
    entry_path = hub / "namespaces" / "creed-space" / ARTIFACT_ID / "1.0.0" / "entry.json"
    entry = json.loads(entry_path.read_text())
    entry["content_sha256"] = "0" * 64
    entry_path.write_text(json.dumps(entry))

    with pytest.raises(VerificationError, match="content hash mismatch"):
        _install(REF, hub, tmp_path / "artifacts")


def test_registry_refuses_a_non_allowlisted_https_host():
    with pytest.raises(HubError, match="not allowlisted"):
        RegistryClient("https://evil.example.invalid/hub")


def test_registry_refuses_a_non_https_scheme():
    with pytest.raises(HubError, match="scheme"):
        RegistryClient("http://raw.githubusercontent.com/Creed-Space/vcp-hub/main")


# --- never-execute invariant -------------------------------------------------

EXEC_CANARY_ENV = "VCP_EXEC_CANARY"
CANARY_ARTIFACT = f"import os\nos.environ['{EXEC_CANARY_ENV}'] = '1'\nopen('canary.txt', 'w').write('executed')\n"

# These are inert string literals used to grep the hub source. Nothing here calls
# eval/exec; the test asserts the production modules never gain such a call.
FORBIDDEN_TOKENS = (
    "eval(",
    "exec(",
    "__import__",
    "importlib.import_module",
    "subprocess",
    "os.system",
)

HUB_MODULES = ("install", "verify", "registry", "lint", "cli", "entry_schema", "publish")


def test_install_path_never_executes_artifact(tmp_path, monkeypatch, test_private_key, pinned_test_key):
    """An artifact that *looks* like a program is installed as inert bytes."""
    hub_root = tmp_path / "hub"
    hub_root.mkdir()
    content = CANARY_ARTIFACT.encode("utf-8")
    write_version_dir(
        hub_root,
        ARTIFACT_ID,
        "1.0.0",
        content,
        make_sidecar(content, test_private_key),
        build_entry_dict(ARTIFACT_ID, "1.0.0", content),
    )
    from vcp.hub.lint import write_index

    assert write_index(hub_root).ok

    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.delenv(EXEC_CANARY_ENV, raising=False)

    _install(REF, hub_root, tmp_path / "artifacts")

    assert list(tmp_path.rglob("canary.txt")) == []
    assert not Path("canary.txt").exists()
    assert EXEC_CANARY_ENV not in os.environ
    assert ARTIFACT_ID not in sys.modules


@pytest.mark.parametrize("module_name", HUB_MODULES)
def test_hub_modules_contain_no_execution_primitives(module_name):
    """Static guard: no path in the hub client can grow a code-execution sink."""
    source = (Path(install_mod.__file__).parent / f"{module_name}.py").read_text(encoding="utf-8")

    found = [token for token in FORBIDDEN_TOKENS if token in source]
    assert found == [], f"{module_name}.py contains execution primitives: {found}"


# --- CLI smoke ---------------------------------------------------------------


def test_cli_install_verify_and_search_succeed(hub, tmp_path, capsys):
    target = tmp_path / "artifacts"

    assert cli.main(["install", REF, "--target", str(target), "--registry", str(hub)]) == 0
    assert cli.main(["verify", "--target", str(target)]) == 0
    assert cli.main(["search", "gaslighting", "--registry", str(hub)]) == 0

    assert "installed" in capsys.readouterr().out
