# Password Manager

A desktop password manager, originally built as an undergraduate capstone project and
rewritten to fix its security model and add a real GUI.

## What changed from the original

The original (`PM_1.py`, single file, see git history) stored every password in **plaintext
JSON** and generated "random" passwords using Python's `random` module — a Mersenne Twister
PRNG that is predictable from its outputs and unsuitable for anything security-sensitive.
It was also CLI-only.

This version:

- Encrypts the entire vault at rest with **AES-256-GCM** (authenticated encryption — a
  tampered or corrupted file fails to decrypt instead of silently returning garbage)
- Derives the encryption key from your master password with **Argon2id**, the PHC-winning,
  OWASP-recommended KDF (memory-hard, resistant to GPU/ASIC cracking, unlike PBKDF2)
- Generates passwords with `secrets`, a CSPRNG, not `random`
- Has a real GUI, built with **PySide6**

## Security design

| Concern | Approach |
|---|---|
| Key derivation | Argon2id, 64 MiB memory / 3 iterations / 4 lanes (OWASP's current minimum for interactive logins), unique random 16-byte salt per vault |
| Encryption | AES-256-GCM, unique random 12-byte nonce per save (a fresh nonce every write — required, since reusing a (key, nonce) pair breaks GCM's confidentiality guarantee) |
| Tamper detection | GCM's authentication tag rejects any modified ciphertext, wrong password, or corrupted file with the same error, so an attacker can't distinguish "wrong password" from "tampered file" |
| At-rest format | Vault file contains only KDF params + nonce + ciphertext — no plaintext metadata about what's stored |
| Password display | Table shows passwords masked by default; must explicitly toggle "Show Passwords" |
| Clipboard | "Copy Password" clears the clipboard automatically after 20 seconds |
| Write safety | Vault saves write to a temp file and `os.replace()` into place — atomic, so a crash mid-save can't corrupt the vault |

### Threat model — what this does and doesn't protect against

Protects against: someone getting a copy of the vault file at rest (e.g. from a stolen
laptop's disk, a backup, a synced cloud folder) without the master password.

Does **not** protect against: a compromised OS while the vault is unlocked (keyloggers,
memory scraping, malware with access to the running process), a weak/guessable master
password (Argon2id raises the cost of guessing, it doesn't make a weak password strong),
or shoulder-surfing. This is a portfolio/learning project, not an audited production
credential store — don't put real high-value credentials in it.

## Project layout

```
src/password_manager/
  crypto.py      Argon2id KDF + AES-256-GCM encrypt/decrypt
  vault.py       On-disk vault format, CRUD over entries
  generator.py   Secure password generation (secrets, not random)
  gui.py         PySide6 GUI: unlock/create screen, main vault window, dialogs
  config.py      Default vault file location (~/.password_manager/vault.dat)
tests/           pytest unit tests for crypto, vault, generator
```

## Running it

```bash
python -m venv .venv
.venv\Scripts\activate          # or: source .venv/Scripts/activate
pip install -e ".[dev]"
python -m password_manager      # launches the GUI
```

First run prompts you to create a master password; the vault is stored at
`~/.password_manager/vault.dat`.

## Testing

```bash
pytest -v
```

18 tests covering: encrypt/decrypt round-trips, wrong-password rejection, tamper detection,
nonce uniqueness, vault CRUD, master-password rotation, and password-generator behavior.

## Possible next steps

- Cross-platform packaging (PyInstaller) for a distributable `.exe`/`.app`
- Optional TOTP field per entry for 2FA codes
- Auto-lock after N minutes of inactivity
