"""Password hashing and verification: Argon2id with an HMAC-SHA256 pepper.

Two separate secrets protect the stored hash, each defeating a different
attack:
  - Salt (handled internally by argon2-cffi, unique per call, stored inside
    the hash string itself): defeats rainbow tables / precomputation, but is
    NOT secret — anyone with database access can read it.
  - Pepper (PASSWORD_PEPPER, an application-level secret that never touches
    the database): means a database-only breach — a stolen backup, or a SQL
    injection bug like the one this project's Task 2 remediates — hands an
    attacker the hashes and salts, but not enough to attempt offline
    cracking at all, since every guess also requires the pepper.
"""
import hashlib
import hmac
import os

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHash, VerificationError
from dotenv import load_dotenv

load_dotenv()

_PEPPER = os.environ.get("PASSWORD_PEPPER", "")

# Explicit Argon2id (Type.ID) — the variant OWASP recommends for password
# storage, since it hybridises Argon2i (resists side-channel timing attacks)
# and Argon2d (resists GPU/ASIC cracking). Cost parameters below are
# argon2-cffi's own defaults, spelled out explicitly rather than left
# implicit: time_cost=3 iterations, memory_cost=65536 KiB (64 MiB) per hash
# attempt, parallelism=4 threads. memory_cost is what mainly gives Argon2id
# its edge over bcrypt — a would-be cracker parallelising guesses on a
# GPU/ASIC needs 64 MiB of fast memory *per concurrent guess*, which is
# expensive to scale in a way bcrypt's design doesn't force.
_hasher = PasswordHasher(type=Type.ID)


def _pre_hash_with_pepper(plain_text: str) -> str:
    """HMAC-SHA256(pepper, password) — the OWASP-recommended way to mix in a
    pepper: a keyed hash rather than raw string concatenation, which also
    normalises the input to a fixed 64-char hex string regardless of the
    original password's length, sidestepping any algorithm-specific
    input-length quirks (e.g. bcrypt's 72-byte truncation) entirely.
    """
    if not _PEPPER:
        raise RuntimeError(
            "PASSWORD_PEPPER is not set — refusing to hash without a pepper. "
            "Set it in .env (see .env.example)."
        )
    return hmac.new(_PEPPER.encode("utf-8"), plain_text.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(plain_text: str) -> str:
    """Hash a plaintext password: apply the HMAC pepper, then Argon2id-hash
    the result with a freshly generated random salt (handled internally by
    argon2-cffi — a new salt every call is what makes two hashes of the same
    input differ)."""
    peppered = _pre_hash_with_pepper(plain_text)
    return _hasher.hash(peppered)


def verify_password(plain_text: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a hash produced by hash_password."""
    peppered = _pre_hash_with_pepper(plain_text)
    try:
        return _hasher.verify(stored_hash, peppered)
    except (VerificationError, InvalidHash):
        return False


if __name__ == "__main__":
    pw = "CorrectHorseBatteryStaple"
    h1 = hash_password(pw)
    h2 = hash_password(pw)
    print(f"Input password: {pw}")
    print(f"Hash 1: {h1}")
    print(f"Hash 2: {h2}")
    print(f"Hashes differ (unique salts): {h1 != h2}")
    print(f"verify_password(pw, h1): {verify_password(pw, h1)}")
    print(f"verify_password(pw, h2): {verify_password(pw, h2)}")
    print(f"verify_password('wrong', h1): {verify_password('wrong', h1)}")
