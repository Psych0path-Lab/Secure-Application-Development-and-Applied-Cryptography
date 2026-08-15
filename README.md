# Part 3 (Q4) — Secure Application Development and Applied Cryptography

This repository remediates a Flask REST API scenario with four known weaknesses: unsalted MD5 password hashing, hardcoded API credentials, SQL injection via string-concatenated queries, and an unauthenticated `/admin` endpoint. [`app.py`](./app.py) is the fully remediated application; this README documents the threat model, each remediation, and the CI/CD security gate.

---

## Task 1 — STRIDE Threat Model

| STRIDE Category | Threat | Targeted Component | Mitigation |
|---|---|---|---|
| **S**poofing | Attacker submits repeated login attempts using a guessed/stolen username to impersonate a legitimate user | `/login` endpoint | Rate-limit login attempts per source IP/account; require MFA for privileged accounts so a correct password alone isn't sufficient proof of identity |
| **T**ampering | Attacker injects characters into the username/password fields to alter SQL query logic (SQL injection) | Database query construction in `/login` and `/register` | Parameterised queries (prepared statements) — Task 2 remediation — user input is always bound as data, never interpolated into SQL text |
| **R**epudiation | A user denies performing an admin action because no record ties the action to their identity or session | `/admin` endpoint and any state-changing routes | Structured audit logging recording authenticated user ID, token, timestamp, and action for every admin request |
| **I**nformation Disclosure | Password hashes are computed with unsalted MD5; a leaked database lets an attacker crack many passwords at once via precomputed rainbow tables | Password storage (`hash_password`) | Salted + peppered Argon2id hashing — Task 3 remediation — a unique per-user salt defeats rainbow tables, and the HMAC pepper (stored outside the database) means a database-only breach isn't sufficient to attempt offline cracking at all |
| **D**enial of Service | Attacker floods `/register` or `/login` with requests to exhaust CPU/RAM (Argon2id is deliberately slow and memory-hard) or database connections | `/register` and `/login` endpoints | Per-source-IP rate limiting and a maximum request body size in front of the expensive hashing operation |
| **E**levation of Privilege | A regular authenticated user calls `/admin` directly, since the original route performs no authorization check at all | `/admin` endpoint | Authentication + authorization middleware (`require_admin`) — Task 2 remediation — requires both a valid session token AND an `is_admin` flag |

---

## Task 2 — OWASP Top 10 Remediation

### 2a. Injection (SQL Injection)

**❌ Insecure (before) — string-concatenated SQL:**
```python
@app.route("/login", methods=["POST"])
def login():
    username = request.json["username"]
    password = request.json["password"]
    # Attacker input flows directly into the SQL string — a username like
    # `admin' --` comments out the password check entirely.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = db.execute(query)
    ...
```

**✅ Remediated (after) — parameterised query:**
```python
row = db.execute(
    "SELECT username, password_hash, is_admin FROM users WHERE username = ?",
    (username,),
).fetchone()
if row is None or not verify_password(password, row["password_hash"]):
    return jsonify({"error": "invalid credentials"}), 401
```
*(from [`app.py`](./app.py))*

The insecure version is exploitable because the database driver cannot tell the difference between "SQL written by the developer" and "SQL smuggled in through user input" — they're concatenated into one string before the driver ever sees it, so a crafted username can terminate the intended query and append arbitrary SQL. The parameterised version fixes this structurally, not just by filtering input: the `?` placeholder is sent to SQLite separately from the value bound to it, so the value is always treated as data and can never be interpreted as SQL syntax, regardless of its contents.

### 2b. Broken Access Control

**❌ Insecure (before) — no check at all:**
```python
@app.route("/admin")
def admin():
    return jsonify({"status": "ok", "users": get_all_users()})
```

**✅ Remediated (after) — authentication + authorization middleware:**
```python
@app.get("/admin")
@require_admin
def admin():
    return jsonify({"status": "ok", "message": f"welcome, {g.current_user}"})
```
*(`require_admin` defined in [`app.py`](./app.py) — validates a bearer token, checks it hasn't expired, and requires `is_admin=True`)*

The insecure version is exploitable because it performs no check whatsoever — anyone who can reach the route, authenticated or not, gets the response. The fix closes this in two layers: **authentication** (is this a valid, unexpired session token?) and **authorization** (does this specific user have `is_admin` privileges?) are both required, because authentication alone would still let any registered user reach an admin-only route.

---

## Task 3 — Secure Password Hashing

Implementation: [`crypto_utils.py`](./crypto_utils.py), using **Argon2id** (via `argon2-cffi`), plus an **HMAC-SHA256 pepper** as a second, independent layer on top of salting.

```python
_hasher = PasswordHasher(type=Type.ID)  # Argon2id explicitly

def _pre_hash_with_pepper(plain_text: str) -> str:
    if not _PEPPER:
        raise RuntimeError("PASSWORD_PEPPER is not set — refusing to hash without a pepper.")
    return hmac.new(_PEPPER.encode("utf-8"), plain_text.encode("utf-8"), hashlib.sha256).hexdigest()

def hash_password(plain_text: str) -> str:
    peppered = _pre_hash_with_pepper(plain_text)
    return _hasher.hash(peppered)  # argon2-cffi generates a fresh random salt internally, per call

def verify_password(plain_text: str, stored_hash: str) -> bool:
    peppered = _pre_hash_with_pepper(plain_text)
    try:
        return _hasher.verify(stored_hash, peppered)
    except (VerificationError, InvalidHash):
        return False
```

### Why Argon2id?

**Argon2id** is recommended for password storage because it is specifically designed to resist password-cracking attacks.

- **Memory-hard:** Requires significant memory, making GPU and ASIC-based cracking more expensive.
- **Slow by design:** Can be configured to take more time per password attempt, reducing brute-force attacks.
- **Resistant to side-channel attacks:** The **Argon2id** variant combines the benefits of Argon2i and Argon2d.
- **Supports salting:** Each password can have a unique random salt.
- **Modern standard:** Argon2id is widely recommended for new password-storage systems.

### Why add a pepper on top of the salt?

A **salt** and a **pepper** serve different purposes:

- **Salt:** A unique random value stored **alongside the password hash** in the database.
- **Pepper:** A secret value kept **separately from the database**, such as in a secrets manager or HSM.

### Why Use a Pepper?

If an attacker steals the password database, they may obtain:

**Password hashes + salts**

But they should **not** have access to the pepper.

Without the pepper, the attacker cannot properly reproduce the password-hashing process, making offline cracking significantly harder.

### Salt vs Pepper

| Feature | Salt | Pepper |
|---|---|---|
| Purpose | Prevents identical passwords from having identical hashes | Adds an additional secret |
| Unique per password | **Yes** | Usually **No** |
| Secret? | **No** | **Yes** |
| Stored with database? | **Yes** | **No** |
| Protects against database compromise | Partially | **Adds another layer of protection** |

**In short:** Use **Argon2id + a unique salt** as the baseline. A **pepper** provides an additional layer of protection if the password database is compromised, provided the pepper is stored securely and separately.

### Proof of unique salting

Actual output from running `python crypto_utils.py` (verified — not illustrative; `PASSWORD_PEPPER` was set to a throwaway test value for this run):
```
$ python crypto_utils.py
Input password: CorrectHorseBatteryStaple
Hash 1: $argon2id$v=19$m=65536,t=3,p=4$5/iIWLaFvnB8l3BBE9PhsA$n4G5QJgqPdm3K5uuMODFrCpjqgePwF7CMsl490I6Wy8
Hash 2: $argon2id$v=19$m=65536,t=3,p=4$SJGqu7XGRlRjNzQqiysCbA$kKA2nQ2cI2bPs5FGfsVkmjjUSu/kTWxMHr1rlJ46Tv4
Hashes differ (unique salts): True
verify_password(pw, h1): True
verify_password(pw, h2): True
verify_password('wrong', h1): False
```
Same input password, two structurally different hashes. The `$argon2id$v=19$m=65536,t=3,p=4$` prefix encodes the variant, version, and cost parameters (identical on both — that's expected, they're fixed algorithm settings, not secrets); the segment right after it (`5/iIWLaFvnB8l3BBE9PhsA` vs `SJGqu7XGRlRjNzQqiysCbA`) is the random salt, and it's what differs between the two runs, because argon2-cffi generates a fresh one internally every call.

### Why MD5 is unsuitable for password storage

**MD5 is unsuitable for password storage because it is fast, outdated, and vulnerable to attacks.**

- **Very fast:** Attackers can calculate billions of MD5 hashes quickly, making brute-force and dictionary attacks much easier.
- **Collision vulnerabilities:** MD5 has known cryptographic weaknesses that allow different inputs to produce the same hash.
- **No built-in salting:** MD5 does not automatically add a unique salt, making **rainbow-table attacks** practical when passwords are stored as plain MD5 hashes.
- **GPU-friendly:** Modern GPUs can crack large numbers of MD5 hashes very quickly.
- **Weak password protection:** If a password database is leaked, weak passwords protected with MD5 can often be cracked relatively quickly.
**In short:** MD5 was designed for speed and data integrity, not password protection. For passwords, use **Argon2id, bcrypt, scrypt, or PBKDF2 with a unique salt per password**.

---

## Task 4 — Secret Management

**❌ Insecure (before) — hardcoded in source:**
```python
API_KEY = "sk_live_51H8x9K2eL3mN7pQ4rS6tU8vW0xY2z"
DB_PASSWORD = "SuperSecret123!"
```

**✅ Remediated (after) — loaded from environment via python-dotenv:**
```python
from dotenv import load_dotenv
load_dotenv()

EXTERNAL_API_KEY = os.environ.get("EXTERNAL_API_KEY")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
```
*(from [`app.py`](./app.py); real values live only in a local, gitignored `.env` — see [`.env.example`](./.env.example) for the required variable names)*

`.gitignore` excludes the real file:
```
.env
```

Hardcoding secrets is dangerous even in a private repository because the secret persists in git history permanently — deleting it from the latest commit doesn't remove it from earlier commits unless history is rewritten — and a "private" repo can stop being private in an instant: it gets made public by mistake, cloned to a contractor's laptop that's later lost, forked, or pasted into a CI log. Any one of those turns a contained leak into a permanent one, since the secret can't be un-seen once exposed. This is exactly why environment-variable-based secret storage is paired with a **30–90 day rotation policy** in practice: rotation doesn't prevent a leak, but it bounds how long a leaked-and-undiscovered secret stays valid, whereas a hardcoded secret that's never rotated remains exploitable indefinitely once found.

---

## Task 5 — CI/CD Security Gate

[`​.github/workflows/security.yml`](./.github/workflows/security.yml):

```yaml
name: Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install bandit

      - name: Run Bandit SAST scan (fails on Medium/High findings)
        run: bandit -r . -ll --exclude ./venv,./.venv

      - name: Run Semgrep (optional, additional credit — informational only)
        continue-on-error: true
        run: |
          pip install semgrep
          semgrep --config p/python .
```

`bandit -r . -ll` recursively scans the repository and reports only **Medium and High** severity findings (`-ll`); Bandit's default behaviour is to exit non-zero whenever it reports any issue at or above that threshold, so no extra flag is needed to make the step — and therefore the whole job — fail the build on a Medium/High finding.

**Shift Left Security** means moving security checks earlier in the development lifecycle — from something bolted on right before (or after) release, to something run automatically at every commit and pull request, so vulnerabilities are caught while the code is still fresh in a developer's hands, which is far cheaper to fix than after deployment. This workflow implements that directly: Bandit runs on every push/PR to `main` and fails the build on Medium/High findings, which means insecure code cannot merge without a human either fixing it or consciously bypassing the gate — security feedback arrives in minutes, at the same point a failing unit test would, rather than during a separate audit weeks later.

---

## Task 6 — Supply Chain Security Statement

A software supply chain attack compromises an application not by attacking its own code, but by compromising something it depends on — a third-party library, build tool, or CI action — so malicious code rides into the application through a routine, trusted update. This project depends on three open-source libraries (Flask, argon2-cffi, python-dotenv); a supply chain attack could take the form of a maintainer's PyPI account being hijacked to publish a malicious version of one of them, or a typosquatted package name (e.g. `pyton-dotenv`) being installed by mistake. An **SBOM** (Software Bill of Materials) is a structured, machine-readable inventory of every component in the application — direct and transitive dependencies, their exact versions, and often licence and known-vulnerability status — analogous to an ingredients list, so that when a new CVE is disclosed for some deeply nested dependency, the question "are we affected?" can be answered instantly instead of by manually auditing every requirements file. **SCA** (Software Composition Analysis) tooling (e.g. `pip-audit`, GitHub Dependabot, Snyk) automates that lookup, parsing the dependency tree and cross-referencing every version — including transitive ones the developer never directly chose — against vulnerability databases. A compromised dependency here could, for example, exfiltrate `EXTERNAL_API_KEY` from the environment at import time, or execute arbitrary code during `pip install` via a malicious `setup.py`.

---

## Repository Structure

```
README.md                       this document
app.py                          remediated Flask application
crypto_utils.py                 hash_password / verify_password (Argon2id + HMAC pepper)
requirements.txt
.env.example
.gitignore
.github/workflows/security.yml  Bandit SAST gate
```

## Sources / Third-Party Libraries

- Flask — https://flask.palletsprojects.com
- argon2-cffi (PyPI) — https://pypi.org/project/argon2-cffi/
- OWASP Password Storage Cheat Sheet (pepper guidance) — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- python-dotenv — https://pypi.org/project/python-dotenv/
- Bandit — https://bandit.readthedocs.io
- OWASP Top 10 — https://owasp.org/www-project-top-ten/
