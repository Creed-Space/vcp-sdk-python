"""Non-duplicative adversarial regressions for hub resource and state boundaries."""

from __future__ import annotations

import json
import multiprocessing
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from conftest import (
    artifact_text,
    build_entry_dict,
    make_detached_sidecar,
    make_sidecar,
    sign_index,
    write_version_dir,
)

from vcp.hub import cli as hub_cli
from vcp.hub import install as install_module
from vcp.hub import registry as registry_module
from vcp.hub.errors import HubError, VerificationError
from vcp.hub.install import install, verify_tree
from vcp.hub.lint import lint_hub_tree, write_index
from vcp.hub.publish import MAX_FRONTMATTER_BYTES, _frontmatter_from_bytes, build_entry, publish
from vcp.hub.registry import (
    MAX_FETCH_BYTES,
    RegistryClient,
    validate_artifact_filename,
)
from vcp.hub.verify import (
    INDEX_CONTEXT,
    MAX_SIGNATURE_SIDECAR_BYTES,
    countersign_message_context,
    parse_signature_sidecar,
    verify_artifact_bytes,
)


def _write_signed_source(root: Path, artifact_id: str, private_key, *, extra_frontmatter: str = "") -> Path:
    source = root / "source"
    source.mkdir(parents=True, exist_ok=True)
    path = source / f"{artifact_id}.md"
    text = f"---\nid: {artifact_id}\nversion: 1.0.0\ntitle: T\n{extra_frontmatter}---\nbody\n"
    content = text.encode("utf-8")
    path.write_bytes(content)
    path.with_suffix(".md.ed25519.sig").write_bytes(make_sidecar(content, private_key))
    return path


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b'{"id":"one","id":"two"}', "duplicate key"),
        (b"{\xff}", "cannot read"),
        (b"[]", "must contain a JSON object"),
    ],
)
def test_publish_base_entry_reader_rejects_ambiguous_or_malformed_json(tmp_path, content, message):
    path = tmp_path / "base-entry.json"
    path.write_bytes(content)

    with pytest.raises(HubError, match=message):
        hub_cli._read_base_entry(str(path))


def test_publish_base_entry_reader_rejects_oversized_file_before_read(tmp_path):
    path = tmp_path / "base-entry.json"
    with path.open("wb") as handle:
        handle.truncate(MAX_FETCH_BYTES + 1)

    with pytest.raises(HubError, match="size cap"):
        hub_cli._read_base_entry(str(path))


@pytest.mark.parametrize(
    "filename",
    [
        None,
        "",
        ".hidden",
        "../x",
        "dir/x",
        "dir\\x",
        "bad\nname.md",
        "name.",
        "CON",
        "nul.md",
        "COM1.txt",
        "lpt9.json",
        "x" * 256,
    ],
)
def test_artifact_filename_boundary_is_portable_and_bounded(filename):
    with pytest.raises(HubError):
        validate_artifact_filename(filename)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "location",
    [
        None,
        "",
        "file://remote.example/tmp",
        "https://raw.githubusercontent.com:444/example/hub",
        "https://user@raw.githubusercontent.com/example/hub",
        "https://raw.githubusercontent.com/example/hub?ref=main",
        "https://raw.githubusercontent.com/example/hub#fragment",
    ],
)
def test_registry_location_rejects_malformed_or_authority_ambiguous_urls(location):
    with pytest.raises(HubError):
        RegistryClient(location)  # type: ignore[arg-type]


def test_https_registry_redirects_are_disabled_to_preserve_host_allowlist():
    handler = registry_module._RejectRedirects()

    assert (
        handler.redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://attacker.invalid/redirected-index.json",
        )
        is None
    )


def test_local_registry_refuses_oversized_object_before_unbounded_read(tmp_path):
    hub = tmp_path / "hub"
    hub.mkdir()
    oversized = hub / "index.json"
    with oversized.open("wb") as handle:
        handle.truncate(MAX_FETCH_BYTES + 1)

    with pytest.raises(HubError, match="size cap"):
        RegistryClient(str(hub))._fetch("index.json")


def test_local_registry_refuses_symbolic_link_objects(tmp_path):
    hub = tmp_path / "hub"
    hub.mkdir()
    target = hub / "real.json"
    target.write_text("{}", encoding="utf-8")
    (hub / "index.json").symlink_to(target)

    with pytest.raises(HubError, match="symbolic link"):
        RegistryClient(str(hub))._fetch("index.json")


def test_signed_index_with_duplicate_keys_is_rejected(tmp_path, test_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    hub.mkdir()
    content = b'{"index_version":2,"sequence":1,"sequence":2,"artifacts":{}}'
    (hub / "index.json").write_bytes(content)
    (hub / "index.json.ed25519.sig").write_bytes(make_detached_sidecar(content, test_private_key, INDEX_CONTEXT))

    with pytest.raises(HubError, match="duplicate key"):
        RegistryClient(str(hub)).index()


def test_signed_index_rejects_boolean_sequence(tmp_path, test_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    hub.mkdir()
    content = b'{"index_version":2,"sequence":true,"artifacts":{}}'
    (hub / "index.json").write_bytes(content)
    (hub / "index.json.ed25519.sig").write_bytes(make_detached_sidecar(content, test_private_key, INDEX_CONTEXT))

    with pytest.raises(VerificationError, match="monotonic sequence"):
        RegistryClient(str(hub)).index()


@pytest.mark.parametrize(
    "artifacts",
    [
        {"bad ref": {}},
        {"creed-space/item@1.0.0": {}},
        {"creed-space/item": []},
        {"creed-space/item": {"latest": True, "versions": {}}},
        {"creed-space/item": {"latest": "1.0.0", "versions": {}}},
        {
            "creed-space/item": {
                "latest": "1.0.0",
                "versions": {
                    "2.0.0": {
                        "content_sha256": "0" * 64,
                        "trust_tier": "signed",
                    }
                },
            }
        },
        {
            "creed-space/item": {
                "latest": "not-semver",
                "versions": {"not-semver": {}},
            }
        },
        {
            "creed-space/item": {
                "latest": "1.0.0",
                "versions": {"1.0.0": []},
            }
        },
        {
            "creed-space/item": {
                "latest": "1.0.0",
                "versions": {"1.0.0": {"content_sha256": "bad", "trust_tier": "signed"}},
            }
        },
        {
            "creed-space/item": {
                "latest": "1.0.0",
                "versions": {
                    "1.0.0": {
                        "content_sha256": "0" * 64,
                        "trust_tier": "self-declared",
                    }
                },
            }
        },
        {
            "creed-space/item": {
                "latest": "1.0.0",
                "versions": {
                    "1.0.0": {
                        "content_sha256": "0" * 64,
                        "trust_tier": "signed",
                        "artifact": "../escape.md",
                    }
                },
            }
        },
    ],
)
def test_signed_index_rejects_malformed_nested_records(artifacts, tmp_path, test_private_key, pinned_test_key):
    hub = tmp_path / "hub"
    hub.mkdir()
    content = json.dumps({"index_version": 2, "sequence": 1, "artifacts": artifacts}).encode()
    (hub / "index.json").write_bytes(content)
    (hub / "index.json.ed25519.sig").write_bytes(make_detached_sidecar(content, test_private_key, INDEX_CONTEXT))

    with pytest.raises(HubError):
        RegistryClient(str(hub)).index()


@pytest.mark.parametrize(
    "sidecar, message",
    [
        (b'{"version":1,"version":1}', "duplicate key"),
        (b"{}" + b" " * MAX_SIGNATURE_SIDECAR_BYTES, "size cap"),
        (
            json.dumps(
                {
                    "version": True,
                    "algorithm": "Ed25519",
                    "key_id": "k",
                    "content_hash": "0" * 64,
                    "signature": "AA==",
                }
            ).encode(),
            "version",
        ),
        (
            json.dumps(
                {
                    "version": 1,
                    "algorithm": "Ed25519",
                    "key_id": "k",
                    "content_hash": "not-a-sha256",
                    "signature": "AA==",
                }
            ).encode(),
            "content_hash",
        ),
    ],
)
def test_signature_sidecar_rejects_ambiguous_or_resource_hostile_shapes(sidecar, message):
    with pytest.raises(VerificationError, match=message):
        parse_signature_sidecar(sidecar)


def test_signature_verifier_rejects_malformed_expected_hash(pinned_test_key, sign_artifact):
    content = b"content"
    with pytest.raises(VerificationError, match="expected sha256"):
        verify_artifact_bytes(content, sign_artifact(content), expected_sha256="short")


def test_signature_verifier_wraps_non_ascii_registered_pem_as_verification_error(
    sign_artifact,
):
    content = b"content"
    with pytest.raises(VerificationError, match="failed to load"):
        verify_artifact_bytes(content, sign_artifact(content), publisher_keys={"test-signer": "\u2603"})


@pytest.mark.parametrize("ref", [None, "", "creed-space/item@1.0.0\n", "creed-space/item", "bad/ref@1.0"])
def test_counter_signature_context_rejects_noncanonical_refs(ref):
    with pytest.raises(VerificationError):
        countersign_message_context(ref)  # type: ignore[arg-type]


def test_lint_rejects_duplicate_keys_in_unsigned_entry(make_hub):
    hub = make_hub()
    entry_path = hub / "namespaces" / "creed-space" / "anti_gaslighting" / "1.0.0" / "entry.json"
    entry = json.loads(entry_path.read_text(encoding="utf-8"))
    raw = json.dumps(entry)[:-1] + ',"name":"ambiguous"}'
    entry_path.write_text(raw, encoding="utf-8")

    report = lint_hub_tree(hub, require_signed_index=False)

    assert not report.ok
    assert any("duplicate key" in problem for problem in report.problems)


def test_lint_rejects_artifact_symlink_even_when_target_bytes_are_valid(make_hub):
    hub = make_hub()
    version = hub / "namespaces" / "creed-space" / "anti_gaslighting" / "1.0.0"
    artifact = version / "anti_gaslighting.md"
    replacement = version / "same-bytes.md"
    replacement.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(replacement.name)

    report = lint_hub_tree(hub, require_signed_index=False)

    assert not report.ok
    assert any("symbolic link" in problem for problem in report.problems)


def test_verify_tree_rejects_internal_artifact_symlink(make_hub, tmp_path):
    hub = make_hub()
    target = tmp_path / "installed"
    install("creed-space/anti_gaslighting", target, RegistryClient(str(hub)))
    version = target / "creed-space" / "anti_gaslighting" / "1.0.0"
    artifact = version / "anti_gaslighting.md"
    replacement = version / "same-bytes.md"
    replacement.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(replacement.name)

    with pytest.raises(VerificationError, match="symbolic link"):
        verify_tree(target)


def test_install_rolls_back_tree_if_atomic_lock_commit_fails(make_hub, tmp_path, monkeypatch):
    hub = make_hub()
    target = tmp_path / "installed"

    def fail_write(*_args, **_kwargs):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(install_module, "_write_lock_atomically", fail_write)

    with pytest.raises(HubError, match="cannot commit install"):
        install("creed-space/anti_gaslighting", target, RegistryClient(str(hub)))

    assert not (target / "creed-space" / "anti_gaslighting" / "1.0.0").exists()
    assert not (target / "vcp.lock").exists()


def test_install_rejects_symlink_lockfile_without_overwriting_target(make_hub, tmp_path):
    hub = make_hub()
    target = tmp_path / "installed"
    victim = tmp_path / "victim.json"
    original = b'{"do_not":"replace"}\n'
    victim.write_bytes(original)
    lock_path = tmp_path / "custom.lock"
    lock_path.symlink_to(victim)

    with pytest.raises(HubError, match="symbolic link"):
        install(
            "creed-space/anti_gaslighting",
            target,
            RegistryClient(str(hub)),
            lock_path=lock_path,
        )

    assert victim.read_bytes() == original
    assert lock_path.is_symlink()
    assert not (target / "creed-space" / "anti_gaslighting" / "1.0.0").exists()


def test_lockfile_rejects_boolean_sequence_state(make_hub, tmp_path):
    hub = make_hub()
    target = tmp_path / "installed"
    install("creed-space/anti_gaslighting", target, RegistryClient(str(hub)))
    lock_path = target / "vcp.lock"
    lock = json.loads(lock_path.read_text())
    lock["registries"][str(hub)]["index_sequence"] = True
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    with pytest.raises(HubError, match="invalid index_sequence"):
        verify_tree(target)


def test_live_verify_fetches_each_signed_trust_document_once_for_the_whole_tree(
    make_hub,
    tmp_path,
    monkeypatch,
):
    hub = make_hub(artifact_id="first_item")
    make_hub(root=hub, artifact_id="second_item")
    target = tmp_path / "installed"
    registry = RegistryClient(str(hub))
    install("creed-space/first_item", target, registry)
    install("creed-space/second_item", target, registry)

    original_index = registry.index
    calls = 0

    def counted_index():
        nonlocal calls
        calls += 1
        return original_index()

    monkeypatch.setattr(registry, "index", counted_index)

    assert verify_tree(target, registry=registry) == [
        "creed-space/first_item@1.0.0",
        "creed-space/second_item@1.0.0",
    ]
    assert calls == 1


def test_concurrent_installs_preserve_every_pin(make_hub, tmp_path, test_private_key):
    hub = make_hub()
    artifact_ids = [f"concurrent_{index}" for index in range(12)]
    for artifact_id in artifact_ids:
        content = artifact_text(artifact_id).encode()
        write_version_dir(
            hub,
            artifact_id,
            "1.0.0",
            content,
            make_sidecar(content, test_private_key),
            build_entry_dict(artifact_id, "1.0.0", content),
        )
    assert write_index(hub).ok
    sign_index(hub, test_private_key)
    barrier = threading.Barrier(len(artifact_ids))

    class SynchronizedRegistry(RegistryClient):
        def artifact(self, namespace, artifact_id, version, filename):
            data = super().artifact(namespace, artifact_id, version, filename)
            if filename.endswith(".ed25519.sig"):
                barrier.wait(timeout=10)
            return data

    target = tmp_path / "installed"
    with ThreadPoolExecutor(max_workers=len(artifact_ids)) as executor:
        results = list(
            executor.map(
                lambda artifact_id: install(f"creed-space/{artifact_id}", target, SynchronizedRegistry(str(hub))),
                artifact_ids,
            )
        )

    assert {result.ref for result in results} == {f"creed-space/{artifact_id}" for artifact_id in artifact_ids}
    lock = json.loads((target / "vcp.lock").read_text())
    assert set(lock["artifacts"]) == {f"creed-space/{artifact_id}" for artifact_id in artifact_ids}
    assert set(verify_tree(target)) == {f"creed-space/{artifact_id}@1.0.0" for artifact_id in artifact_ids}


@pytest.mark.skipif(os.name == "nt", reason="fork inheritance is used to retain the test trust root")
def test_concurrent_process_installs_preserve_every_pin(make_hub, tmp_path, test_private_key):
    hub = make_hub(artifact_id="process_one")
    make_hub(root=hub, artifact_id="process_two")
    target = tmp_path / "installed"
    context = multiprocessing.get_context("fork")
    start = context.Barrier(2)

    def worker(ref):
        start.wait(timeout=10)
        install(ref, target, RegistryClient(str(hub)))

    processes = [
        context.Process(target=worker, args=("creed-space/process_one",)),
        context.Process(target=worker, args=("creed-space/process_two",)),
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
            pytest.fail(f"concurrent install child {process.pid} hung")
        assert process.exitcode == 0

    lock = json.loads((target / "vcp.lock").read_text(encoding="utf-8"))
    assert set(lock["artifacts"]) == {
        "creed-space/process_one",
        "creed-space/process_two",
    }
    assert set(verify_tree(target)) == {
        "creed-space/process_one@1.0.0",
        "creed-space/process_two@1.0.0",
    }


def test_frontmatter_delimiter_must_be_its_own_line(tmp_path, test_private_key, pinned_test_key):
    path = _write_signed_source(
        tmp_path,
        "inline_delimiter",
        test_private_key,
        extra_frontmatter='description: "three---characters"\n',
    )

    entry = build_entry(path)

    assert entry["description"] == "three---characters"


def test_frontmatter_parser_wraps_deep_yaml_recursion_as_a_stable_hub_error():
    nested = b"[" * 2_000 + b"0" + b"]" * 2_000
    content = b"---\nvalue: " + nested + b"\n---\n"

    with pytest.raises(HubError, match="invalid YAML frontmatter"):
        _frontmatter_from_bytes(content, "deep.md")


def test_frontmatter_parser_rejects_duplicate_yaml_keys():
    content = b"---\nid: first\nid: second\nversion: 1.0.0\n---\n"

    with pytest.raises(HubError, match="duplicate YAML key"):
        _frontmatter_from_bytes(content, "duplicate.md")


def test_frontmatter_byte_cap_applies_to_multibyte_text():
    content = b"---\ndescription: " + "🧠".encode() * (MAX_FRONTMATTER_BYTES // 4 + 1) + b"\n---\n"

    with pytest.raises(HubError, match="oversized YAML frontmatter"):
        _frontmatter_from_bytes(content, "multibyte.md")


def test_publish_rejects_structured_title_without_rendering_alias_graph(
    tmp_path,
    test_private_key,
    pinned_test_key,
):
    path = _write_signed_source(
        tmp_path,
        "structured_title",
        test_private_key,
        extra_frontmatter="alias_source: &title [one, two]\ndisplay_title: *title\n",
    )

    with pytest.raises(HubError, match="title must be a string"):
        build_entry(path)


def test_publish_rechecks_source_bytes_after_entry_construction(
    tmp_path, test_private_key, pinned_test_key, monkeypatch
):
    path = _write_signed_source(tmp_path, "source_race", test_private_key)
    hub = tmp_path / "hub"
    hub.mkdir()
    from vcp.hub import publish as publish_module

    original = publish_module.build_entry

    def mutate_after_build(*args, **kwargs):
        entry = original(*args, **kwargs)
        path.write_bytes(path.read_bytes() + b"changed after verification\n")
        return entry

    monkeypatch.setattr(publish_module, "build_entry", mutate_after_build)

    with pytest.raises(VerificationError, match="content hash mismatch"):
        publish_module.publish(path, hub)
    assert not (hub / "namespaces").exists()


def test_publish_rolls_back_new_version_and_index_on_lint_failure(tmp_path, test_private_key, pinned_test_key):
    path = _write_signed_source(tmp_path, "rollback_probe", test_private_key)
    hub = tmp_path / "hub"
    invalid = hub / "namespaces" / "creed-space" / "existing" / "not-a-version"
    invalid.mkdir(parents=True)
    old_index = b"preexisting index sentinel\n"
    (hub / "index.json").write_bytes(old_index)

    with pytest.raises(VerificationError, match="failed lint"):
        publish(path, hub)

    assert not (hub / "namespaces" / "creed-space" / "rollback_probe" / "1.0.0").exists()
    assert (hub / "index.json").read_bytes() == old_index


def test_publish_invalidates_stale_index_signature_after_tree_change(make_hub, tmp_path, test_private_key):
    hub = make_hub()
    assert (hub / "index.json.ed25519.sig").is_file()
    path = _write_signed_source(tmp_path / "new", "new_artifact", test_private_key)

    publish(path, hub)

    assert not (hub / "index.json.ed25519.sig").exists()
    assert lint_hub_tree(hub, require_signed_index=False).ok


def test_publish_rolls_back_if_stale_index_signature_cannot_be_removed(
    make_hub, tmp_path, test_private_key, monkeypatch
):
    hub = make_hub()
    old_index = (hub / "index.json").read_bytes()
    index_signature = hub / "index.json.ed25519.sig"
    old_signature = index_signature.read_bytes()
    path = _write_signed_source(tmp_path / "new", "unlink_failure", test_private_key)
    version_dir = hub / "namespaces" / "creed-space" / "unlink_failure" / "1.0.0"
    original_unlink = Path.unlink

    def fail_index_signature_unlink(self, *args, **kwargs):
        if self == index_signature:
            raise OSError("simulated unlink failure")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_index_signature_unlink)

    with pytest.raises(OSError, match="simulated unlink failure"):
        publish(path, hub)

    assert not version_dir.exists()
    assert (hub / "index.json").read_bytes() == old_index
    assert index_signature.read_bytes() == old_signature


def test_published_version_metadata_is_immutable(tmp_path, test_private_key, pinned_test_key):
    path = _write_signed_source(tmp_path, "immutable_meta", test_private_key)
    hub = tmp_path / "hub"
    hub.mkdir()
    publish(path, hub)
    entry_path = hub / "namespaces" / "creed-space" / "immutable_meta" / "1.0.0" / "entry.json"
    original = entry_path.read_bytes()

    with pytest.raises(VerificationError, match="immutable metadata"):
        publish(
            path,
            hub,
            base_entry={"id": "immutable_meta", "version": "1.0.0", "name": "Changed"},
        )

    assert entry_path.read_bytes() == original
