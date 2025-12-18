---
name: sast-authentication-testing
description: Investigate authentication vulnerabilities in source code including missing authentication, weak authentication, and session management issues. Use when threat model identifies CWE-287 (Improper Authentication), CWE-384 (Session Fixation), CWE-306 (Missing Authentication), or authentication concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Authentication Testing Skill

## Purpose
Investigate authentication failures in source code by analyzing:
- **Authentication enforcement** on protected endpoints
- **Session management** implementation
- **Credential handling** practices
- **Authentication bypass** vectors

## Vulnerability Types Covered

### 1. Missing Authentication (CWE-306)
Sensitive functionality accessible without authentication.

**Code Patterns to Find:**
- API endpoints without auth decorators
- Admin routes missing authentication
- Sensitive operations in public routes

**Example Vulnerable Code:**
```python
@app.route('/api/admin/users')
def list_all_users():  # No @login_required
    return User.query.all()
```

### 2. Improper Authentication (CWE-287)
Authentication mechanism can be bypassed or is insufficient.

**Code Patterns to Find:**
- Weak password validation
- Hardcoded credentials
- Predictable authentication tokens
- Missing rate limiting on login

**Example Vulnerable Code:**
```python
def login(username, password):
    if password == "admin123":  # Hardcoded password check
        return create_session(username)
```

### 3. Session Fixation (CWE-384)
Session identifier not regenerated after authentication.

**Code Patterns to Find:**
- Missing session regeneration on login
- Session ID passed in URL
- Session not invalidated on logout

**Example Vulnerable Code:**
```python
def login(username, password):
    if verify_password(username, password):
        # Missing: session.regenerate()
        session['user'] = username
```

### 4. Broken Authentication (CWE-287)
General authentication weaknesses.

**Code Patterns to Find:**
- Password stored in plaintext
- Weak password hashing (MD5, SHA1)
- Missing account lockout
- Exposed session tokens in logs

## Investigation Methodology

### Step 1: Find Authentication Points
Search for login/auth handlers:
```
Patterns: def login, def authenticate, def signin
          /login, /auth, /signin
          authenticate_user, verify_credentials
```

### Step 2: Check Auth Decorators
Verify sensitive endpoints have authentication:
```
Patterns: @login_required, @authenticated
          @jwt_required, @token_required
          before_request, middleware
```

### Step 3: Analyze Session Management
Look for session handling code:
```
Patterns: session[, session.get(
          regenerate, invalidate
          set_cookie, delete_cookie
          jwt.encode, jwt.decode
```

### Step 4: Check Credential Handling
Search for password/token handling:
```
Patterns: password, secret, token, api_key
          hash, bcrypt, argon2, pbkdf2
          plaintext, base64, md5, sha1
```

### Step 5: Cross-Reference with Org
Use `github_org_code_search` to find:
- Common authentication middleware
- Shared auth libraries
- How other services handle auth

## Classification Criteria

**TRUE_POSITIVE:**
- Sensitive endpoint has no authentication
- Credentials stored/compared insecurely
- Session management has known vulnerabilities

**FALSE_POSITIVE:**
- Authentication is properly implemented
- Endpoint is intentionally public
- Session regeneration exists elsewhere

**UNVALIDATED:**
- Authentication in external service
- Complex auth flow that spans multiple files

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Evidence
- **Location**: file:line
- **Issue**: Description of the authentication weakness
- **Code**: Relevant code snippet

### Attack Scenario
How an attacker could exploit this:
1. [Steps to reproduce]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping
- **CWE-287**: Improper Authentication
- **CWE-306**: Missing Authentication for Critical Function
- **CWE-384**: Session Fixation
- **CWE-521**: Weak Password Requirements
- **CWE-613**: Insufficient Session Expiration

## Safety Rules
- Only analyze code in the repository provided
- Do not attempt to exploit or test against live systems
- Redact any sensitive data (API keys, secrets) from evidence
