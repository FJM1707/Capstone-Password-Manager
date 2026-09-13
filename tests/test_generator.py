import string

import pytest

from password_manager.generator import GeneratorOptions, generate_password, suggest_passwords_from_phrase


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


def test_suggest_from_phrase_default_count():
    suggestions = suggest_passwords_from_phrase("my dog rex loves walks")
    assert len(suggestions) == 4


def test_suggest_from_phrase_custom_count():
    suggestions = suggest_passwords_from_phrase("correct horse battery staple", count=8)
    assert len(suggestions) == 8


def test_suggest_from_phrase_empty_raises():
    with pytest.raises(ValueError):
        suggest_passwords_from_phrase("   !!! ")


def test_suggest_from_phrase_negative_suffix_raises():
    with pytest.raises(ValueError):
        suggest_passwords_from_phrase("some phrase", suffix_length=-1)


def test_suggest_from_phrase_zero_count_raises():
    with pytest.raises(ValueError):
        suggest_passwords_from_phrase("some phrase", count=0)


def test_suggest_from_phrase_varies_between_calls():
    # The random suffix must differ run to run even for the identical phrase -
    # otherwise the phrase alone would be determining the password.
    first = suggest_passwords_from_phrase("the quick brown fox")
    second = suggest_passwords_from_phrase("the quick brown fox")
    assert first != second


def test_suggest_from_phrase_single_word():
    # A one-word phrase still works; the acronym variant is short by construction
    # (one letter + random suffix), so only assert a sane minimum length.
    suggestions = suggest_passwords_from_phrase("password")
    assert len(suggestions) == 4
    assert all(len(s) >= 5 for s in suggestions)
