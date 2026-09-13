import pytest

from password_manager.crypto import DecryptionError
from password_manager.vault import Vault, VaultError


def test_create_and_unlock_roundtrip(tmp_path):
    vault_path = tmp_path / "vault.dat"
    vault = Vault.create(vault_path, "master-password")
    vault.add_entry("github", "franciscmartinez7", "s3cr3t!", notes="personal account")

    reopened = Vault.unlock(vault_path, "master-password")
    entry = reopened.get_entry("github")

    assert entry.username == "franciscmartinez7"
    assert entry.password == "s3cr3t!"
    assert entry.notes == "personal account"


def test_wrong_master_password_raises(tmp_path):
    vault_path = tmp_path / "vault.dat"
    Vault.create(vault_path, "correct-password")

    with pytest.raises(DecryptionError):
        Vault.unlock(vault_path, "wrong-password")


def test_creating_over_existing_vault_raises(tmp_path):
    vault_path = tmp_path / "vault.dat"
    Vault.create(vault_path, "pw")

    with pytest.raises(VaultError):
        Vault.create(vault_path, "pw")


def test_update_and_delete_entry(tmp_path):
    vault_path = tmp_path / "vault.dat"
    vault = Vault.create(vault_path, "pw")
    vault.add_entry("service", "user", "old-password")

    vault.update_entry("service", password="new-password")
    assert vault.get_entry("service").password == "new-password"

    vault.delete_entry("service")
    assert vault.get_entry("service") is None
    assert "service" not in vault.list_services()


def test_change_master_password_reencrypts_and_preserves_data(tmp_path):
    vault_path = tmp_path / "vault.dat"
    vault = Vault.create(vault_path, "old-password")
    vault.add_entry("service", "user", "pw")

    vault.change_master_password("new-password")

    with pytest.raises(DecryptionError):
        Vault.unlock(vault_path, "old-password")

    reopened = Vault.unlock(vault_path, "new-password")
    assert reopened.get_entry("service").password == "pw"


def test_duplicate_service_rejected(tmp_path):
    vault_path = tmp_path / "vault.dat"
    vault = Vault.create(vault_path, "pw")
    vault.add_entry("service", "user", "pw1")

    with pytest.raises(VaultError):
        vault.add_entry("service", "other-user", "pw2")


def test_list_services_sorted(tmp_path):
    vault_path = tmp_path / "vault.dat"
    vault = Vault.create(vault_path, "pw")
    vault.add_entry("zeta", "u", "p")
    vault.add_entry("alpha", "u", "p")

    assert vault.list_services() == ["alpha", "zeta"]
