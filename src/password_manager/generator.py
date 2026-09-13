"""Cryptographically secure password generation.

Uses `secrets`, not `random` - `random` is a Mersenne Twister PRNG that is
statistically predictable from a handful of outputs and must never be used
for anything security-sensitive, including "random" passwords.
"""

from __future__ import annotations

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
