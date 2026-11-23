import os
import stat

import pytest

from tmpfs import safe


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def test_candidate_name_keeps_caller_supplied_suffix(tmp_path):
    first = safe.candidate_name(str(tmp_path), "export-", "9f3ac1d2e4b5")
    second = safe.candidate_name(str(tmp_path), "export-", "0a7b6c5d4e3f")
    assert isinstance(first, str)
    assert os.path.abspath(os.path.dirname(first)) == os.path.abspath(str(tmp_path))
    assert os.path.basename(first).startswith("export-")
    assert os.path.basename(first).endswith("9f3ac1d2e4b5")
    assert os.path.basename(second).endswith("0a7b6c5d4e3f")
    assert first != second


def test_create_exclusive_does_not_overwrite_existing(tmp_path):
    target = tmp_path / "export-existing.bin"
    target.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        safe.create_exclusive(str(target), 0o600)
    assert target.read_bytes() == b"original"


def test_write_atomic_does_not_fall_back_to_plain_open(tmp_path):
    target = tmp_path / "export-race.bin"
    target.write_bytes(b"original")
    with pytest.raises(FileExistsError):
        safe.write_atomic(str(target), b"attacker", 0o600)
    assert target.read_bytes() == b"original"


def test_write_atomic_publishes_with_single_atomic_rename(tmp_path, monkeypatch):
    target = tmp_path / "export-atomic.bin"
    renames = []
    real_replace = os.replace
    real_rename = os.rename

    def record_replace(src, dst, *args, **kwargs):
        renames.append((os.fspath(src), os.fspath(dst)))
        return real_replace(src, dst, *args, **kwargs)

    def record_rename(src, dst, *args, **kwargs):
        renames.append((os.fspath(src), os.fspath(dst)))
        return real_rename(src, dst, *args, **kwargs)

    monkeypatch.setattr(safe.os, "replace", record_replace)
    monkeypatch.setattr(safe.os, "rename", record_rename)
    assert safe.write_atomic(str(target), b"payload", 0o600) == str(target)
    assert target.read_bytes() == b"payload"
    assert len(renames) == 1
    source, destination = renames[0]
    assert os.path.abspath(os.path.dirname(source)) == os.path.abspath(str(tmp_path))
    assert os.path.abspath(destination) == os.path.abspath(str(target))
    assert os.listdir(tmp_path) == [target.name]


def test_create_exclusive_uses_private_creation_mode(tmp_path, monkeypatch):
    target = tmp_path / "export-mode.bin"
    modes = []
    real_open = os.open

    def record_open(path, flags, mode=0o777, *, dir_fd=None):
        modes.append(mode)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(safe.os, "open", record_open)
    descriptor = safe.create_exclusive(str(target), 0o600)
    os.close(descriptor)
    assert modes
    assert stat.S_IMODE(modes[0]) == 0o600


def test_set_permissions_rejects_modes_wider_than_owner(tmp_path):
    target = tmp_path / "export-perm.bin"
    target.write_bytes(b"x")
    with pytest.raises(ValueError):
        safe.set_permissions(str(target), 0o777)
    with pytest.raises(ValueError):
        safe.set_permissions(str(target), 0o640)
    safe.set_permissions(str(target), 0o600)


def test_cleanup_refuses_paths_outside_temp_root(tmp_path, monkeypatch):
    allowed = tmp_path / "temp-root"
    allowed.mkdir()
    victim = tmp_path / "victim.bin"
    victim.write_bytes(b"keep")
    monkeypatch.setattr(safe.tempfile, "gettempdir", lambda: str(allowed))
    assert safe.cleanup(str(victim)) is False
    assert victim.exists()
    escape = os.path.join(str(allowed), "..", "victim.bin")
    assert safe.cleanup(escape) is False
    assert victim.exists()


def test_verify_owner_compares_numeric_uid(tmp_path):
    target = tmp_path / "export-owner.bin"
    target.write_bytes(b"x")
    owner = os.stat(str(target)).st_uid
    assert safe.verify_owner(str(target), owner) is True
    assert safe.verify_owner(str(target), owner + 1) is False
    assert safe.verify_owner(str(tmp_path / "missing.bin"), owner) is False


def test_export_batch_uses_distinct_names_per_item(tmp_path):
    policy = {
        "directory": str(tmp_path),
        "prefix": "export-",
        "mode": 0o600,
        "overwrite": False,
    }
    items = [
        {"name": "alpha", "data": b"alpha-payload", "suffix": "3f9a1c"},
        {"name": "beta", "data": b"beta-payload", "suffix": "c7210e"},
    ]
    exported = safe.export_batch(items, policy)["exported"]
    assert len(exported) == 2
    assert len({os.path.normcase(os.path.abspath(path)) for path in exported}) == 2
    assert sorted(read_bytes(path) for path in exported) == [
        b"alpha-payload",
        b"beta-payload",
    ]


def test_validate_policy_flags_other_writable_directory(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    try:
        os.chmod(shared, 0o777)
    except OSError:
        pass
    policy = {
        "directory": str(shared),
        "prefix": "export-",
        "mode": 0o600,
        "overwrite": False,
    }
    problems = safe.validate_policy(policy)
    assert "directory_writable_by_others" in problems


def test_create_and_write_inside_temp_directory(tmp_path):
    path = safe.candidate_name(str(tmp_path), "export-", "deadbeef")
    descriptor = safe.create_exclusive(path, 0o600)
    try:
        os.write(descriptor, b"payload")
    finally:
        os.close(descriptor)
    assert read_bytes(path) == b"payload"
    assert os.path.abspath(os.path.dirname(path)) == os.path.abspath(str(tmp_path))


def test_create_exclusive_fails_when_target_exists(tmp_path):
    target = tmp_path / "taken.bin"
    target.write_bytes(b"taken")
    with pytest.raises(FileExistsError):
        safe.create_exclusive(str(target), 0o600)


def test_exported_mode_is_not_wider_than_policy(tmp_path, monkeypatch):
    policy = {
        "directory": str(tmp_path),
        "prefix": "export-",
        "mode": 0o600,
        "overwrite": False,
    }
    items = [
        {"name": "one", "data": b"one", "suffix": "aa11"},
        {"name": "two", "data": b"two", "suffix": "bb22"},
    ]
    modes = []
    real_open = os.open
    real_chmod = os.chmod

    def record_open(path, flags, mode=0o777, *, dir_fd=None):
        modes.append(mode)
        if dir_fd is None:
            return real_open(path, flags, mode)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    def record_chmod(path, mode, *args, **kwargs):
        modes.append(mode)
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(safe.os, "open", record_open)
    monkeypatch.setattr(safe.os, "chmod", record_chmod)
    exported = safe.export_batch(items, policy)["exported"]
    assert len(exported) == 2
    assert modes
    assert all(stat.S_IMODE(mode) & 0o177 == 0 for mode in modes)


def test_cleanup_removes_temp_file(tmp_path, monkeypatch):
    monkeypatch.setattr(safe.tempfile, "gettempdir", lambda: str(tmp_path))
    target = tmp_path / "export-clean.bin"
    target.write_bytes(b"x")
    assert safe.cleanup(str(target)) is True
    assert not target.exists()


def test_independent_batches_match_single_exports(tmp_path):
    items = [
        {"name": "alpha", "data": b"alpha", "suffix": "1a2b3c"},
        {"name": "beta", "data": b"beta", "suffix": "4d5e6f"},
    ]

    def policy_for(label):
        directory = tmp_path / label
        directory.mkdir()
        return {
            "directory": str(directory),
            "prefix": "export-",
            "mode": 0o600,
            "overwrite": False,
        }

    combined = safe.export_batch(items, policy_for("combined"))["exported"]
    first = safe.export_batch([items[0]], policy_for("first"))["exported"]
    second = safe.export_batch([items[1]], policy_for("second"))["exported"]
    assert len(combined) == 2
    assert sorted(read_bytes(path) for path in combined) == sorted(
        read_bytes(path) for path in first + second
    )
