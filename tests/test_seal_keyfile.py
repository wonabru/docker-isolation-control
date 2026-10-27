import pytest

from poi.seal import kem, keyfile

from helpers import FAST_KDF


def test_create_and_load(tmp_path):
    path = tmp_path / "client.key"
    pk = keyfile.create(path, "hasło", **FAST_KDF)
    assert (tmp_path / "client.pub").read_text().strip() == pk.hex()
    assert path.stat().st_mode & 0o777 == 0o600
    sk = keyfile.load_private(path, "hasło")
    assert kem.public_from_private(sk) == pk
    assert keyfile.load_public(tmp_path / "client.pub") == pk == keyfile.load_public(path)


def test_wrong_password(tmp_path):
    keyfile.create(tmp_path / "client.key", "good", **FAST_KDF)
    with pytest.raises(keyfile.BadPassword):
        keyfile.load_private(tmp_path / "client.key", "bad")


def test_refuses_to_overwrite(tmp_path):
    keyfile.create(tmp_path / "client.key", "pw", **FAST_KDF)
    with pytest.raises(FileExistsError):
        keyfile.create(tmp_path / "client.key", "pw", **FAST_KDF)


def test_password_from_env(monkeypatch):
    monkeypatch.setenv(keyfile.PASSWORD_ENV, "x")
    assert keyfile.get_password() == "x"
