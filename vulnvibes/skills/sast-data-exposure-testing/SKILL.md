---
name: sast-data-exposure-testing
description: Investigate data exposure vulnerabilities in source code including PII leakage, sensitive data logging, and information disclosure. Use when threat model identifies CWE-200 (Information Exposure), CWE-532 (Sensitive Data in Logs), CWE-359 (Privacy Violation), or data exposure concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Data Exposure Testing Skill

## Purpose
Investigate data exposure vulnerabilities by analyzing:
- **Logging practices** (what gets logged)
- **API responses** (excessive data exposure)
- **Error handling** (information leakage)
- **Data storage** practices

## Vulnerability Types Covered

### 1. Sensitive Data in Logs (CWE-532)
PII or secrets written to log files.

**Dangerous Patterns:**
```python
# Logging sensitive data
logger.info(f"User login: {username}, password: {password}")
logger.debug(f"API response: {response.json()}")  # May contain PII
print(f"Processing credit card: {card_number}")
```

**Safe Patterns:**
```python
logger.info(f"User login: {username}")
logger.debug(f"API response status: {response.status_code}")
logger.info(f"Processing card ending in: {card_number[-4:]}")
```

### 2. Excessive Data Exposure (CWE-200)
API returns more data than necessary.

**Dangerous Patterns:**
```python
@app.route('/api/user/<id>')
def get_user(id):
    user = User.query.get(id)
    return user.to_dict()  # Returns ALL fields including password_hash, SSN, etc.
```

**Safe Patterns:**
```python
def get_user(id):
    user = User.query.get(id)
    return {
        'id': user.id,
        'name': user.name,
        'email': user.email
    }  # Only necessary fields
```

### 3. Information Disclosure in Errors (CWE-209)
Stack traces or internal details exposed to users.

**Dangerous Patterns:**
```python
except Exception as e:
    return str(e), 500  # Exposes internal error details
    return traceback.format_exc(), 500  # Full stack trace
```

**Safe Patterns:**
```python
except Exception as e:
    logger.error(f"Error: {e}", exc_info=True)
    return {"error": "An internal error occurred"}, 500
```

### 4. Privacy Violation (CWE-359)
PII exposed without proper controls.

**Dangerous Patterns:**
```python
# Exposing PII in URLs
redirect(f"/profile?ssn={user.ssn}")

# Caching sensitive data
cache.set(f"user_{id}", user.to_dict())  # Includes PII
```

## Investigation Methodology

### Step 1: Find Logging Points
Search for logging statements:
```
Patterns: logger., logging., print(, console.log
          log.info, log.debug, log.error
          sentry, bugsnag, rollbar
```

### Step 2: Identify Sensitive Data
Look for PII and sensitive fields:
```
Patterns: password, ssn, social_security
          credit_card, card_number, cvv
          email, phone, address
          api_key, token, secret
```

### Step 3: Check API Responses
Analyze what data is returned:
```
Patterns: return user, return .to_dict()
          jsonify(, json.dumps(
          response.json(), render_template
```

### Step 4: Analyze Error Handling
Check exception handling:
```
Patterns: except Exception, except:
          traceback, exc_info
          return str(e), raise
```

### Step 5: Cross-Reference with Org
Use `github_org_code_search` to find:
- Common logging patterns
- Data serialization practices
- Error handling standards

## Classification Criteria

**TRUE_POSITIVE:**
- Sensitive data (PII, secrets) logged or exposed
- Full objects returned without field filtering
- Stack traces exposed to end users

**FALSE_POSITIVE:**
- Only non-sensitive data logged
- Proper field filtering on API responses
- Errors properly sanitized for users

**UNVALIDATED:**
- Logging level configurable (may be disabled in prod)
- Data sensitivity depends on context

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Evidence
- **Location**: file:line
- **Exposure Type**: Logging / API Response / Error / Cache
- **Data Exposed**: Type of sensitive data (PII, credentials, etc.)
- **Code**: Relevant code snippet (REDACT actual data)

### Impact
- What data could be exposed
- Who could access it
- Regulatory implications (GDPR, HIPAA, etc.)

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping
- **CWE-200**: Information Exposure
- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-209**: Error Message Information Leak
- **CWE-359**: Exposure of Private Personal Information
- **CWE-615**: Sensitive Data in Comments

## Safety Rules
- ALWAYS redact actual PII/sensitive data in evidence
- Replace with [REDACTED] or [PII] placeholder
- Only analyze code in the repository provided
- Do not extract or store actual sensitive data
