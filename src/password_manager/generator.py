"""Cryptographically secure password generation.

Uses `secrets`, not `random` - `random` is a Mersenne Twister PRNG that is
statistically predictable from a handful of outputs and must never be used
for anything security-sensitive, including "random" passwords.
"""

from __future__ import annotations

import re
import secrets
import string
from dataclasses import dataclass


@dataclass(frozen=True)
class GeneratorOptions:
    length: int = 20
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    symbols: str = "!@#$%^&*()-_=+[]{};:,.<>?"

    def charset(self) -> str:
        chars = ""
        if self.use_lowercase:
            chars += string.ascii_lowercase
        if self.use_uppercase:
            chars += string.ascii_uppercase
        if self.use_digits:
            chars += string.digits
        if self.use_symbols:
            chars += self.symbols
        if not chars:
            raise ValueError("At least one character category must be enabled")
        return chars


def generate_password(options: GeneratorOptions = GeneratorOptions()) -> str:
    if options.length < 1:
        raise ValueError("Password length must be at least 1")
    charset = options.charset()
    return "".join(secrets.choice(charset) for _ in range(options.length))


_LEET_MAP = str.maketrans(
    {"a": "@", "A": "@", "e": "3", "E": "3", "i": "1", "I": "1", "o": "0", "O": "0", "s": "$", "S": "$", "t": "7", "T": "7"}
)
_SEPARATORS = "!@#$%^&*-_="
_SUFFIX_CHARSET = string.ascii_letters + string.digits + "!@#$%^&*"
_MAX_WORDS_USED = 6


def _random_suffix(length: int) -> str:
    return "".join(secrets.choice(_SUFFIX_CHARSET) for _ in range(length))


def _randomize_case(text: str) -> str:
    return "".join(secrets.choice((c.upper, c.lower))() for c in text)


def _phrase_words(phrase: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9]+", phrase)


def _camel_case_variant(words: list[str], suffix_length: int) -> str:
    base = "".join(w.capitalize() for w in words[:_MAX_WORDS_USED])
    return base + _random_suffix(suffix_length)


def _leet_variant(words: list[str], suffix_length: int) -> str:
    base = "".join(w.lower() for w in words[:_MAX_WORDS_USED])
    return base.translate(_LEET_MAP) + _random_suffix(suffix_length)


def _separated_variant(words: list[str], suffix_length: int) -> str:
    sep = secrets.choice(_SEPARATORS)
    base = sep.join(w.capitalize() for w in words[:_MAX_WORDS_USED])
    return base + _random_suffix(suffix_length)


def _acronym_variant(words: list[str], suffix_length: int) -> str:
    letters = "".join(w[0] for w in words)
    # An acronym is short by construction, so it gets its own case randomization
    # (rather than relying only on the suffix) to keep its entropy reasonable.
    return _randomize_case(letters) + _random_suffix(suffix_length + 2)


_VARIANT_BUILDERS = (_camel_case_variant, _leet_variant, _separated_variant, _acronym_variant)


def suggest_passwords_from_phrase(phrase: str, count: int = 4, suffix_length: int = 4) -> list[str]:
    """Suggests passwords derived from a memorable phrase.

    The phrase only supplies structure (word boundaries, an acronym, a leet-speak
    skeleton) so the suggestions are easier to recognize/type once retrieved from
    the vault. It is NOT the source of the password's actual security: each
    suggestion also gets a `secrets`-derived random suffix, so a short, common,
    or guessable phrase (e.g. a song lyric) still can't be brute-forced just by
    guessing the phrase - the random component is what carries the entropy.
    """
    if suffix_length < 0:
        raise ValueError("suffix_length cannot be negative")
    words = _phrase_words(phrase)
    if not words:
        raise ValueError("Phrase must contain at least one letter or digit")
    if count < 1:
        raise ValueError("count must be at least 1")

    return [_VARIANT_BUILDERS[i % len(_VARIANT_BUILDERS)](words, suffix_length) for i in range(count)]
