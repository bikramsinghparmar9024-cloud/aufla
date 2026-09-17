"""Hot reload: onboarding a source must not need a restart."""

from __future__ import annotations

from pathlib import Path

from aufla.mapping import MappingRegistry

GOOD = """
source: {name}
format: csv
version: {version}
approved_by: analyst-7
rules:
  - name: only
    ocsf_class: 4001
    fields:
      src_endpoint.ip: ${index}
"""


def write(directory: Path, filename: str, *, name: str, version=1, index=1) -> Path:
    path = directory / filename
    path.write_text(
        GOOD.format(name=name, version=version, index=index), encoding="utf-8"
    )
    return path


def test_loads_a_directory(tmp_path):
    write(tmp_path, "a.yaml", name="alpha")
    write(tmp_path, "b.yml", name="beta")

    reg = MappingRegistry(tmp_path)
    report = reg.refresh()

    assert set(report.loaded) == {"alpha", "beta"}
    assert reg.sources == ("alpha", "beta")
    assert len(reg) == 2
    assert "alpha" in reg


def test_missing_directory_is_not_an_error(tmp_path):
    reg = MappingRegistry(tmp_path / "does-not-exist")
    report = reg.refresh()
    assert report.ok
    assert len(reg) == 0


def test_non_yaml_files_are_ignored(tmp_path):
    write(tmp_path, "a.yaml", name="alpha")
    (tmp_path / "notes.txt").write_text("ignore me", encoding="utf-8")
    (tmp_path / "data.json").write_text("{}", encoding="utf-8")

    reg = MappingRegistry(tmp_path)
    reg.refresh()
    assert reg.sources == ("alpha",)


def test_unchanged_files_are_not_reloaded(tmp_path):
    write(tmp_path, "a.yaml", name="alpha")
    reg = MappingRegistry(tmp_path)
    reg.refresh()

    second = reg.refresh()
    assert not second.changed


def test_an_edited_file_is_picked_up(tmp_path):
    path = write(tmp_path, "a.yaml", name="alpha", version=1)
    reg = MappingRegistry(tmp_path)
    reg.refresh()
    assert reg.get("alpha").version == 1

    # Rewrite with a new version; bump mtime explicitly so the test does not
    # depend on filesystem timestamp resolution.
    path.write_text(GOOD.format(name="alpha", version=2, index=1), encoding="utf-8")
    import os

    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

    report = reg.refresh()
    assert report.updated == ("alpha",)
    assert reg.get("alpha").version == 2


def test_a_deleted_file_removes_its_source(tmp_path):
    path = write(tmp_path, "a.yaml", name="alpha")
    reg = MappingRegistry(tmp_path)
    reg.refresh()
    assert "alpha" in reg

    path.unlink()
    report = reg.refresh()
    assert report.removed == ("alpha",)
    assert "alpha" not in reg


def test_a_broken_edit_leaves_the_previous_version_in_place(tmp_path):
    # Degrading to "no change" is correct. A source silently losing its
    # mapping mid-flight would be far worse than a stale one.
    path = write(tmp_path, "a.yaml", name="alpha", version=1)
    reg = MappingRegistry(tmp_path)
    reg.refresh()

    path.write_text("source: alpha\nformat: csv\nrules: [\n", encoding="utf-8")
    import os

    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))

    report = reg.refresh()
    assert not report.ok
    assert len(report.failed) == 1
    assert reg.get("alpha").version == 1      # still serving the good one


def test_two_files_claiming_one_source_is_reported(tmp_path):
    write(tmp_path, "a.yaml", name="alpha")
    write(tmp_path, "b.yaml", name="alpha")

    reg = MappingRegistry(tmp_path)
    report = reg.refresh()

    assert len(report.loaded) == 1
    assert len(report.failed) == 1
    assert "already defined by" in report.failed[0][1]


def test_approval_can_be_required(tmp_path):
    (tmp_path / "a.yaml").write_text(
        "source: alpha\nformat: csv\nrules:\n"
        "  - name: only\n    ocsf_class: 4001\n"
        "    fields: { src_endpoint.ip: $1 }\n",
        encoding="utf-8",
    )

    lax = MappingRegistry(tmp_path)
    assert lax.refresh().ok

    strict = MappingRegistry(tmp_path, require_approval=True)
    report = strict.refresh()
    assert not report.ok
    assert "not approved" in report.failed[0][1]
    assert len(strict) == 0


def test_hashes_are_exposed_for_the_ledger(tmp_path):
    write(tmp_path, "a.yaml", name="alpha")
    reg = MappingRegistry(tmp_path)
    reg.refresh()

    hashes = reg.hashes()
    assert set(hashes) == {"alpha"}
    assert len(hashes["alpha"]) == 64


# --- the shipped reference mappings --------------------------------------


def test_the_bundled_source_mappings_all_load():
    root = Path(__file__).resolve().parents[1] / "sources"
    reg = MappingRegistry(root)
    report = reg.refresh()

    assert report.ok, f"bundled mappings failed to load: {report.failed}"
    # A subset, not an exact set: the discovery lane writes approved mappings
    # into this same directory at runtime, which is the point -- an authored
    # mapping gets no separate location and no separate treatment.
    assert {
        "pfsense_filterlog",
        "suricata_eve",
        "squid_access",
        "windows_netconn",
        "windows_eventlog",
    } <= set(reg.sources)


def test_bundled_mappings_are_approved_and_cover_expected_classes():
    root = Path(__file__).resolve().parents[1] / "sources"
    reg = MappingRegistry(root, require_approval=True)
    assert reg.refresh().ok

    assert reg.get("pfsense_filterlog").ocsf_classes == (4001,)
    assert set(reg.get("suricata_eve").ocsf_classes) == {2004, 4001}
    assert reg.get("squid_access").ocsf_classes == (4002,)
