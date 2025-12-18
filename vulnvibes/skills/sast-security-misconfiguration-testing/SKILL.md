---
name: sast-security-misconfiguration-testing
description: Investigate security misconfiguration vulnerabilities including debug modes, default credentials, overly permissive settings, and insecure defaults. Use when threat model identifies CWE-16 (Configuration), CWE-1188 (Insecure Default Initialization), CWE-276 (Incorrect Default Permissions), or configuration concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Security Misconfiguration Testing Skill

## Purpose
Investigate security misconfigurations by analyzing:
- **Debug/development modes** left enabled
- **Default credentials** and secrets
- **Overly permissive settings** (CORS, permissions)
- **Missing security headers** and protections
- **Verbose error handling** exposing internals

## CRITICAL: OWASP A05 Context

Security Misconfiguration is #5 on OWASP Top 10 because:
1. Easy to introduce, hard to detect automatically
2. Often environment-specific (dev vs prod)
3. Can expose entire application
4. Frequently exploited in real attacks

## Vulnerability Types Covered

### 1. Debug Mode in Production (CWE-489)
Development/debug settings exposing sensitive information.

**Dangerous Patterns:**
```python
# Flask/Django debug mode
DEBUG = True
app.run(debug=True)
app.config['DEBUG'] = True

# Verbose error pages
app.config['PROPAGATE_EXCEPTIONS'] = True

# Development server in production
if __name__ == '__main__':
    app.run(host='0.0.0.0')  # Using dev server

# Express.js
app.use(errorHandler({ dumpExceptions: true, showStack: true }))
```

**Safe Patterns:**
```python
# Environment-based configuration
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# Or better - never allow debug in certain environments
if os.environ.get('ENVIRONMENT') == 'production':
    DEBUG = False
    assert not app.debug, "Debug must be disabled in production"

# Use production server
# gunicorn app:app instead of app.run()
```

### 2. Default/Hardcoded Credentials (CWE-1188, CWE-798)
Note: CWE-798 overlaps with cryptography-testing but config-specific cases here.

**Dangerous Patterns:**
```python
# Default database credentials
DATABASE_URL = "postgresql://admin:admin@localhost/db"
REDIS_URL = "redis://:password123@localhost:6379"

# Default API keys in config
API_KEY = "default_api_key_12345"
SECRET_KEY = "development_secret_key"

# Admin accounts with default passwords
DEFAULT_ADMIN_PASSWORD = "admin123"
```

**Safe Patterns:**
```python
# Required environment variables
DATABASE_URL = os.environ['DATABASE_URL']  # Fails if not set
SECRET_KEY = os.environ['SECRET_KEY']

# With validation
secret = os.environ.get('SECRET_KEY')
if not secret or secret == 'development_secret_key':
    raise ValueError("Production SECRET_KEY required")
```

### 3. Overly Permissive CORS (CWE-16)
Cross-Origin Resource Sharing allowing all origins.

**Dangerous Patterns:**
```python
# Allow all origins
from flask_cors import CORS
CORS(app)  # Defaults to allow all

# Explicit wildcard
cors(app, origins='*')
app.use(cors({ origin: '*' }))

# Reflect any origin (especially dangerous with credentials)
cors(app, origins=True, supports_credentials=True)

# Regex too permissive
cors(app, origins=r'.*\.example\.com')  # Matches attacker-example.com
```

**Safe Patterns:**
```python
# Explicit allowlist
ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com'
]
CORS(app, origins=ALLOWED_ORIGINS)

# Environment-based
CORS(app, origins=os.environ['ALLOWED_ORIGINS'].split(','))
```

### 4. Missing Security Headers (CWE-16)
HTTP headers that prevent common attacks.

**Missing Headers to Check:**
```python
# Content-Security-Policy
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Strict-Transport-Security
# X-XSS-Protection (legacy but still useful)
# Referrer-Policy
# Permissions-Policy
```

**Safe Patterns:**
```python
# Flask-Talisman
from flask_talisman import Talisman
Talisman(app, content_security_policy={...})

# Manual headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response

# Express.js helmet
const helmet = require('helmet')
app.use(helmet())
```

### 5. Insecure Default Permissions (CWE-276)
Files, directories, or resources with overly permissive access.

**Dangerous Patterns:**
```python
# World-writable files
os.chmod(config_file, 0o777)
os.chmod(upload_dir, 0o777)

# Public S3 buckets
s3.put_object(Bucket='bucket', Key='file', ACL='public-read')

# Open database ports
DATABASES = {
    'default': {
        'HOST': '0.0.0.0',  # Bound to all interfaces
    }
}
```

**Safe Patterns:**
```python
# Restrictive permissions
os.chmod(config_file, 0o600)  # Owner read/write only
os.chmod(upload_dir, 0o750)   # Owner full, group read/execute

# Private by default
s3.put_object(Bucket='bucket', Key='file')  # Private is default

# Localhost only
DATABASES = {
    'default': {
        'HOST': '127.0.0.1',
    }
}
```

### 6. Verbose Error Messages (CWE-209)
Note: Also covered in data-exposure-testing, but config-specific here.

**Dangerous Patterns:**
```python
# Exposing stack traces
@app.errorhandler(Exception)
def handle_error(e):
    return str(e), 500  # Exposes internal details

# Database errors to user
except psycopg2.Error as e:
    return f"Database error: {e}", 500

# Express.js
app.use((err, req, res, next) => {
    res.status(500).send(err.stack)  # Full stack trace
})
```

**Safe Patterns:**
```python
import logging
logger = logging.getLogger(__name__)

@app.errorhandler(Exception)
def handle_error(e):
    logger.exception("Internal error")  # Log details
    return "An error occurred", 500      # Generic to user

# Different handling per environment
if app.debug:
    return str(e), 500
else:
    return "Internal server error", 500
```

### 7. Insecure Session Configuration
Session cookies without proper security attributes.

**Dangerous Patterns:**
```python
# Missing secure flags
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = None

# Short or no expiration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
```

**Safe Patterns:**
```python
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JS access
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)
```

## Investigation Methodology

### Step 1: Find Configuration Files
```
Search for: settings.py, config.py, .env
           application.yml, config.json
           docker-compose.yml, Dockerfile
           nginx.conf, apache.conf
```

### Step 2: Check Debug Settings
```
Search for: DEBUG, debug=, development
           FLASK_ENV, NODE_ENV, RAILS_ENV
           app.run(debug
```

### Step 3: Find Credential Patterns
```
Search for: password, secret, key, token
           admin, default, example
           localhost, 127.0.0.1
```

### Step 4: Check Security Headers
```
Search for: helmet, Talisman, SecurityHeaders
           Content-Security-Policy, X-Frame-Options
           add_header, setHeader
```

### Step 5: Review CORS Configuration
```
Search for: cors(, CORS(, Access-Control
           origin, credentials
           allowedOrigins, corsOptions
```

### Step 6: Check Permissions
```
Search for: chmod, chown, ACL
           0777, 0666, public-read
           world-readable, world-writable
```

## Classification Criteria

**TRUE_POSITIVE:**
- DEBUG=True in production configuration
- Hardcoded credentials in non-example files
- CORS allowing all origins with credentials
- Missing critical security headers
- World-writable sensitive files

**FALSE_POSITIVE:**
- Debug settings in development-only configs
- Example/template credentials clearly marked
- CORS restrictions appropriate for API use case
- Security headers set via reverse proxy (nginx)
- Permissions appropriate for use case

**UNVALIDATED:**
- Environment-dependent settings need runtime check
- Proxy/infrastructure may add headers
- Context needed to assess permission requirements

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Misconfiguration Type
- **Category**: Debug Mode / Credentials / CORS / Headers / Permissions
- **Environment**: Production / Development / Unknown

### Evidence
- **Location**: file:line
- **Setting**: [The misconfiguration]
- **Current Value**: [What it's set to]
- **Expected Value**: [What it should be]

### Impact
- [What can an attacker do with this misconfiguration]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping

### Configuration
- **CWE-16**: Configuration
- **CWE-1188**: Insecure Default Initialization of Resource
- **CWE-276**: Incorrect Default Permissions
- **CWE-489**: Active Debug Code

### Related
- **CWE-209**: Error Message Information Leak
- **CWE-215**: Insertion of Sensitive Information Into Debugging Code
- **CWE-668**: Exposure of Resource to Wrong Sphere

## Cross-Skill Dependencies

Configuration investigations may need:
- **sast-cryptography-testing**: For hardcoded secrets
- **sast-browser-security-testing**: For CORS/cookie settings
- **sast-data-exposure-testing**: For verbose error handling

## Environment-Specific Checks

### Docker
```dockerfile
# Dangerous
ENV DEBUG=true
ENV SECRET_KEY=development

# Check for
EXPOSE (unnecessary ports)
USER root (running as root)
```

### Kubernetes
```yaml
# Check for
securityContext: (missing or permissive)
hostNetwork: true
privileged: true
```

### Cloud (AWS/GCP/Azure)
```
# Check for
Public S3 buckets
Open security groups
IAM with admin access
```

## Safety Rules
- Only analyze code in the repository provided
- Consider environment context (dev vs prod)
- Check for environment variable overrides
- Look for infrastructure-level compensating controls
