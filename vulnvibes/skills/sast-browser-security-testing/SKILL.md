---
name: sast-browser-security-testing
description: Investigate browser security vulnerabilities including CORS misconfiguration, CSRF, clickjacking, and cookie security. Use when threat model identifies CWE-346 (Origin Validation), CWE-942 (Permissive CORS), CWE-352 (CSRF), CWE-1021 (Clickjacking), or browser security concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Browser Security Testing Skill

## Purpose
Investigate browser-enforced security mechanisms by analyzing:
- **CORS configuration** (origin validation, credentials handling)
- **CSRF protection** (state-changing operations + auth state)
- **Clickjacking defenses** (X-Frame-Options, CSP frame-ancestors)
- **Cookie security** (Secure, HttpOnly, SameSite attributes)

## CRITICAL: Authentication Mechanism Check

**Before flagging CORS/CSRF vulnerabilities, ALWAYS determine the authentication type first.**

| Auth Type | How to Detect | CORS Risk | CSRF Risk |
|-----------|---------------|-----------|-----------|
| **Cookies only** | `Set-Cookie`, `res.cookie()`, `httpOnly`, session middleware | HIGH if `credentials: true` | HIGH |
| **Headers + localStorage** | `localStorage.setItem`, `Authorization: Bearer`, NO `withCredentials` | LOW | LOW |
| **Mixed (both)** | Both cookie and header patterns present | MEDIUM | MEDIUM |

### Authentication Detection Steps

**Step 1: Check Backend for Cookie Usage**
```
Patterns: Set-Cookie, res.cookie(, setCookie(
          session[, req.session, session.
          httpOnly, secure: true, sameSite
```

**Step 2: Check Frontend for Credential Handling**
```
Patterns: withCredentials: true, credentials: 'include'
          credentials: 'same-origin'
          localStorage.setItem, localStorage.getItem
          sessionStorage.setItem
          Authorization: Bearer, setRequestHeader
```

**Step 3: Determine Risk Level**
- If NO cookies AND NO `withCredentials` → CORS/CSRF risk is **LOW**
- If cookies used → CORS/CSRF risk requires full investigation

## Vulnerability Types Covered

### 1. Permissive CORS Configuration (CWE-942, CWE-346)
CORS policy allows untrusted origins to read responses.

**Dangerous Patterns:**
```javascript
// Reflects any origin - DANGEROUS
app.use(cors({ origin: true, credentials: true }));

// Wildcard with credentials - INVALID but attempted
app.use(cors({ origin: '*', credentials: true }));

// Regex too permissive
origin: /\.example\.com$/  // Allows attacker-example.com
```

**Safe Patterns:**
```javascript
// Explicit allowlist
app.use(cors({
    origin: ['https://app.example.com', 'https://admin.example.com'],
    credentials: true
}));

// Dynamic with validation
origin: (origin, callback) => {
    if (ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
    } else {
        callback(new Error('Not allowed'));
    }
}
```

**Investigation Questions:**
1. What origins are allowed? (explicit list vs reflection vs regex)
2. Is `credentials: true` enabled?
3. What authentication mechanism is used? (cookies vs headers)
4. What sensitive data is in responses?

### 2. Cross-Site Request Forgery (CWE-352)
State-changing operations vulnerable to forged cross-origin requests.

**CSRF requires ALL of:**
1. ✅ Cookie-based authentication (not header-based)
2. ✅ State-changing endpoint (POST/PUT/DELETE)
3. ✅ No CSRF token validation
4. ✅ Cookies sent automatically (no SameSite=Strict)

**Dangerous Patterns:**
```python
# State-changing endpoint with cookie auth, no CSRF token
@app.route('/api/transfer', methods=['POST'])
@login_required  # Uses session cookies
def transfer_funds():
    amount = request.json['amount']
    # No CSRF token check!
    execute_transfer(amount)
```

**Safe Patterns:**
```python
# CSRF token validation
@app.route('/api/transfer', methods=['POST'])
@login_required
@csrf.exempt  # Only if intentional API endpoint with header auth
def transfer_funds():
    validate_csrf_token(request.headers.get('X-CSRF-Token'))
    # OR using SameSite=Strict cookies
```

**CSRF is NOT a risk when:**
- Authentication uses Authorization headers (not cookies)
- Frontend stores tokens in localStorage (origin-isolated)
- All cookies have SameSite=Strict
- No state-changing operations exist

### 3. Clickjacking (CWE-1021)
Page can be embedded in attacker's iframe for UI redressing.

**Dangerous Patterns:**
```python
# No framing protection
@app.route('/sensitive-action')
def sensitive_page():
    return render_template('action.html')
    # Missing X-Frame-Options or CSP frame-ancestors
```

**Safe Patterns:**
```python
# X-Frame-Options header
response.headers['X-Frame-Options'] = 'DENY'
# OR
response.headers['X-Frame-Options'] = 'SAMEORIGIN'

# CSP frame-ancestors (preferred)
response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
```

### 4. Insecure Cookie Configuration (CWE-614, CWE-1004, CWE-1275)
Authentication cookies missing security attributes.

**Dangerous Patterns:**
```javascript
// Missing Secure flag (sent over HTTP)
res.cookie('session', token);

// Missing HttpOnly (accessible via JavaScript/XSS)
res.cookie('session', token, { secure: true });

// Missing SameSite (CSRF vulnerable)
res.cookie('session', token, { secure: true, httpOnly: true });
```

**Safe Patterns:**
```javascript
res.cookie('session', token, {
    secure: true,      // HTTPS only
    httpOnly: true,    // Not accessible via JS
    sameSite: 'strict' // Not sent cross-origin
});
```

## Investigation Methodology

### Step 1: Identify Auth Mechanism (CRITICAL)
```
Search backend for: Set-Cookie, res.cookie, session
Search frontend for: withCredentials, credentials:, localStorage
```
**If header-based only (localStorage + Authorization): Most browser attacks are LOW risk**

### Step 2: Find CORS Configuration
```
Patterns: cors(, Access-Control-Allow-Origin
          origin:, credentials:
          add_header Access-Control
```

### Step 3: Identify State-Changing Endpoints
```
Patterns: POST, PUT, DELETE, PATCH
          @csrf_exempt, csrf_token
          transfer, update, delete, create
```

### Step 4: Check Security Headers
```
Patterns: X-Frame-Options, frame-ancestors
          Content-Security-Policy, CSP
          Strict-Transport-Security
```

### Step 5: Analyze Cookie Settings
```
Patterns: Set-Cookie, res.cookie(
          httpOnly, secure, sameSite
          session.cookie, cookie_params
```

### Step 6: Cross-Reference with Org
Use `github_org_code_search` to find:
- Common CORS middleware patterns
- Shared security header middleware
- Cookie configuration standards

## Classification Criteria

**TRUE_POSITIVE:**
- Permissive CORS (`origin: true`) with cookie-based auth
- State-changing endpoint without CSRF protection using cookies
- Missing clickjacking headers on sensitive pages
- Session cookies without Secure/HttpOnly/SameSite

**FALSE_POSITIVE:**
- Permissive CORS but authentication is header-based (localStorage + Bearer)
- CSRF concern but app uses SameSite=Strict cookies
- Clickjacking concern on non-sensitive public pages
- Cookies are non-sensitive (preferences, analytics)

**UNVALIDATED:**
- Auth mechanism spans multiple services
- Cookie settings in infrastructure (nginx, CDN)
- Complex SPA with mixed auth patterns

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Authentication Mechanism
- **Type**: Cookie-based / Header-based / Mixed
- **Evidence**: [How auth works in this app]
- **CORS/CSRF Baseline Risk**: HIGH / MEDIUM / LOW

### Evidence
- **Location**: file:line
- **Issue**: Description of the browser security weakness
- **Code**: Relevant code snippet

### Attack Scenario
How an attacker could exploit this:
1. [Steps to reproduce]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping

### CORS & Origin Validation
- **CWE-346**: Origin Validation Error
- **CWE-942**: Permissive Cross-domain Policy with Untrusted Domains

### CSRF
- **CWE-352**: Cross-Site Request Forgery

### Clickjacking
- **CWE-1021**: Improper Restriction of Rendered UI Layers

### Cookie Security
- **CWE-614**: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- **CWE-1004**: Sensitive Cookie Without 'HttpOnly' Flag
- **CWE-1275**: Sensitive Cookie With Improper SameSite Attribute

### Related
- **CWE-693**: Protection Mechanism Failure (general)
- **CWE-16**: Configuration (security headers)

## Cross-Skill Dependencies

This skill may need information from:
- **sast-authentication-testing**: To understand session management and auth flow
- **sast-data-exposure-testing**: To assess sensitivity of data in API responses

When authentication mechanism is unclear, invoke `sast-authentication-testing` first.

## Safety Rules
- Only analyze code in the repository provided
- Do not attempt to exploit or test against live systems
- Consider the full authentication architecture before flagging CORS/CSRF
- Redact any sensitive data from evidence
