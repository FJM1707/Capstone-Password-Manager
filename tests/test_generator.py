import string

import pytest

from password_manager.generator import GeneratorOptions, generate_password


def test_default_length():
    pw = generate_password()
    assert len(pw) == 20


def test_custom_length():
    pw = generate_password(GeneratorOptions(length=32))
    assert len(pw) == 32


def test_only_digits():
    options = GeneratorOptions(length=50, use_lowercase=False, use_uppercase=False, use_digits=True, use_symbols=False)
    pw = generate_password(options)
    assert all(c in string.digits for c in pw)


def test_no_categories_enabled_raises():
    options = GeneratorOptions(use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False)
    with pytest.raises(ValueError):
        generate_password(options)


def test_zero_length_raises():
    with pytest.raises(ValueError):
        generate_password(GeneratorOptions(length=0))


def test_generated_passwords_are_not_all_identical():
    # Sanity check against a non-CSPRNG regression (e.g. accidentally using `random`
    # with a fixed seed) - vanishingly unlikely to collide with a real CSPRNG.
    passwords = {generate_password() for _ in range(20)}
    assert len(passwords) == 20
