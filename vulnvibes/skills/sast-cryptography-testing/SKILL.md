---
name: sast-cryptography-testing
description: Investigate cryptographic vulnerabilities in source code including weak algorithms, hardcoded secrets, and improper key management. Use when threat model identifies CWE-327 (Use of Broken Crypto), CWE-798 (Hardcoded Credentials), CWE-326 (Inadequate Encryption), or cryptography concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Cryptography Testing Skill

## Purpose
Investigate cryptographic weaknesses by analyzing:
- **Algorithm selection** (weak vs strong)
- **Key management** practices
- **Hardcoded secrets** in code
- **Encryption implementation** correctness

## Vulnerability Types Covered

### 1. Weak Cryptographic Algorithms (CWE-327)
Use of broken or weak cryptographic algorithms.

**Weak Algorithms:**
```python
# Hash functions - WEAK
hashlib.md5(password)
hashlib.sha1(password)
DES.new(key)

# Better alternatives
hashlib.sha256(data)
bcrypt.hash(password)
AES.new(key, AES.MODE_GCM)
```

### 2. Hardcoded Credentials (CWE-798)
Secrets embedded directly in source code.

**Dangerous Patterns:**
```python
API_KEY = "sk-1234567890abcdef"
password = "admin123"
SECRET_KEY = "my-secret-key"
conn = psycopg2.connect("postgresql://user:password@host/db")
```

**Safe Patterns:**
```python
API_KEY = os.environ.get("API_KEY")
password = get_secret("db_password")
SECRET_KEY = config.secret_key
```

### 3. Inadequate Encryption Strength (CWE-326)
Insufficient key sizes or weak modes.

**Weak Configurations:**
```python
# Short key length
RSA.generate(1024)  # Should be 2048+
AES.new(key[:16])   # Only 128-bit

# Weak modes
AES.new(key, AES.MODE_ECB)  # ECB mode is insecure
```

### 4. Improper Key Management (CWE-321)
Keys stored or handled insecurely.

**Dangerous Patterns:**
```python
# Key in version control
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
"""

# Key logged or exposed
logger.info(f"Using key: {encryption_key}")
```

## Investigation Methodology

### Step 1: Find Crypto Usage
Search for cryptographic operations:
```
Patterns: hashlib, cryptography, Crypto, pycryptodome
          encrypt, decrypt, hash, sign, verify
          AES, RSA, DES, MD5, SHA
```

### Step 2: Identify Secrets
Look for potential hardcoded secrets:
```
Patterns: API_KEY, SECRET, PASSWORD, TOKEN
          private_key, secret_key, api_secret
          -----BEGIN, -----END
          sk-, pk-, ghp_, xox
```

### Step 3: Check Key Sources
Verify where keys come from:
```
Patterns: os.environ, os.getenv
          config., settings.
          vault., secrets.
```

### Step 4: Analyze Algorithm Choices
Verify algorithm strength:
```
Weak: md5, sha1, des, rc4, ecb
Strong: sha256, sha3, aes-gcm, argon2, bcrypt
```

### Step 5: Cross-Reference with Org
Use `github_org_code_search` to find:
- Common crypto libraries used
- Secret management practices
- Key rotation patterns

## Classification Criteria

**TRUE_POSITIVE:**
- Hardcoded secret in source code
- Weak algorithm used for security-critical function
- Key exposed in logs or version control

**FALSE_POSITIVE:**
- Secret loaded from environment/config
- Weak algorithm used for non-security purpose
- Test/example data, not production secrets

**UNVALIDATED:**
- Secret source is external (vault, KMS)
- Algorithm choice depends on configuration

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Evidence
- **Location**: file:line
- **Issue Type**: Weak Algorithm / Hardcoded Secret / Key Exposure
- **Details**: Specific weakness found
- **Code**: Relevant code snippet (REDACT actual secrets)

### Impact
What an attacker could do with this:
- [Impact description]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping
- **CWE-327**: Use of Broken or Risky Cryptographic Algorithm
- **CWE-798**: Use of Hardcoded Credentials
- **CWE-326**: Inadequate Encryption Strength
- **CWE-321**: Use of Hardcoded Cryptographic Key
- **CWE-328**: Reversible One-Way Hash

## Safety Rules
- ALWAYS redact actual secret values in evidence
- Replace with [REDACTED] or similar placeholder
- Only analyze code in the repository provided
- Do not attempt to use discovered secrets
