import pytest

from password_manager import crypto


def test_encrypt_decrypt_roundtrip():
    params = crypto.KdfParams.generate()
    key = crypto.derive_key("correct horse battery staple", params)
    plaintext = b'{"entries": {}}'

    nonce, ciphertext = crypto.encrypt(plaintext, key)
    decrypted = crypto.decrypt(nonce, ciphertext, key)

    assert decrypted == plaintext


def test_wrong_password_fails_to_decrypt():
    params = crypto.KdfParams.generate()
    key = crypto.derive_key("correct password", params)
    wrong_key = crypto.derive_key("wrong password", params)

    nonce, ciphertext = crypto.encrypt(b"secret data", key)

    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(nonce, ciphertext, wrong_key)


def test_tampered_ciphertext_is_rejected():
    params = crypto.KdfParams.generate()
    key = crypto.derive_key("a password", params)
    nonce, ciphertext = crypto.encrypt(b"secret data", key)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF

    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(nonce, bytes(tampered), key)


def test_nonces_are_not_reused():
    params = crypto.KdfParams.generate()
    key = crypto.derive_key("a password", params)
    nonce1, _ = crypto.encrypt(b"data", key)
    nonce2, _ = crypto.encrypt(b"data", key)
    assert nonce1 != nonce2


def test_kdf_params_roundtrip_through_dict():
    params = crypto.KdfParams.generate()
    restored = crypto.KdfParams.from_dict(params.to_dict())
    assert restored == params
