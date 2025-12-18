---
name: sast-ssrf-testing
description: Investigate Server-Side Request Forgery (SSRF) vulnerabilities where user input controls server-initiated requests. Use when threat model identifies CWE-918 (SSRF), CWE-441 (Unintended Proxy), or server-side request concerns.
allowed-tools: Read, Grep, Glob
---

# SAST SSRF Testing Skill

## Purpose
Investigate SSRF vulnerabilities by analyzing:
- **URL construction** from user input
- **HTTP client usage** with external URLs
- **Webhook/callback** implementations
- **URL validation** and allowlisting

## CRITICAL: Microservices Context

SSRF is especially dangerous in microservices architectures because:
1. Internal services often trust requests from other internal services
2. Cloud metadata endpoints (169.254.169.254) are accessible
3. Internal APIs may lack authentication when called internally
4. Service mesh/gateway bypass is possible

## Vulnerability Types Covered

### 1. Basic SSRF (CWE-918)
User-controlled URL passed directly to HTTP client.

**Dangerous Patterns:**
```python
# Direct URL from user input
url = request.args.get('url')
response = requests.get(url)

# URL from database/config that user can modify
webhook_url = user.webhook_url
requests.post(webhook_url, json=data)

# Template-based URL construction
url = f"http://{request.args.get('host')}/api/data"
httpx.get(url)
```

**Safe Patterns:**
```python
# URL allowlisting
ALLOWED_HOSTS = ['api.trusted.com', 'cdn.trusted.com']
parsed = urlparse(url)
if parsed.netloc not in ALLOWED_HOSTS:
    raise ValueError("URL not allowed")

# Deny internal ranges
def is_internal(url):
    ip = socket.gethostbyname(urlparse(url).hostname)
    return ipaddress.ip_address(ip).is_private
```

### 2. Blind SSRF
Server makes request but response is not returned to user.

**Dangerous Patterns:**
```python
# Webhook that doesn't return response
@app.route('/webhook/register')
def register_webhook():
    url = request.json['callback_url']
    # Later, in background job:
    requests.post(url, json=event_data)  # Blind SSRF

# Image/file fetching
@app.route('/fetch-image')
def fetch_image():
    url = request.args['url']
    img = requests.get(url).content
    # Process image, don't return raw response
    return process_image(img)
```

### 3. SSRF via URL Parsers
Exploiting URL parser inconsistencies.

**Dangerous Patterns:**
```python
# Insufficient validation
url = request.args['url']
if url.startswith('https://trusted.com'):  # Bypass: https://trusted.com.evil.com
    requests.get(url)

# URL with credentials
url = f"http://user:pass@{host}/path"  # host from user input

# Protocol confusion
url = request.args['url']
if 'http' in url:  # Bypass: file:///etc/passwd?http
    requests.get(url)
```

**Safe Patterns:**
```python
from urllib.parse import urlparse

def validate_url(url):
    parsed = urlparse(url)
    # Check scheme
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid scheme")
    # Check host exactly
    if parsed.netloc != 'trusted.com':
        raise ValueError("Invalid host")
    # No credentials in URL
    if parsed.username or parsed.password:
        raise ValueError("Credentials in URL not allowed")
    return True
```

### 4. SSRF to Cloud Metadata
Accessing cloud provider metadata endpoints.

**High-Risk Targets:**
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/api/token

# GCP
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance
```

**Detection:**
```python
# Look for lack of metadata IP blocking
BLOCKED_IPS = ['169.254.169.254', '169.254.170.2']
# If no such blocking exists, flag as potential SSRF risk
```

## Investigation Methodology

### Step 1: Find HTTP Client Usage
```
Search for: requests.get, requests.post, httpx, urllib, aiohttp
           fetch(, http.client, urlopen
```

### Step 2: Trace URL Sources
For each HTTP client call:
1. Where does the URL come from?
2. Is any part user-controllable?
3. Is there validation before the request?

### Step 3: Check URL Validation
```
Search for: urlparse, is_valid_url, validate_url
           ALLOWED_HOSTS, allowlist, whitelist
           is_private, is_internal, 169.254
```

### Step 4: Identify Attack Surface
- Webhooks and callbacks
- Import/export features (URL-based)
- Proxy endpoints
- Image/file fetchers
- PDF generators (wkhtmltopdf, puppeteer)
- Document processors

### Step 5: Check Infrastructure Controls
- Is there a proxy/firewall blocking internal requests?
- Are cloud metadata endpoints blocked?
- Is there network segmentation?

## Classification Criteria

**TRUE_POSITIVE:**
- User input flows to HTTP client URL with no validation
- Webhook URL stored without validation, later used
- URL allowlist can be bypassed (regex issues, parser confusion)
- Internal/metadata endpoints not blocked

**FALSE_POSITIVE:**
- URL is hardcoded or from trusted config
- Proper allowlist with exact host matching
- Network-level controls block internal access
- URL comes from authenticated admin-only input

**UNVALIDATED:**
- Validation exists but completeness unclear
- Infrastructure controls may exist but not visible in code
- Complex URL construction with partial user input

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Attack Surface
- **Entry Point**: [How user provides URL]
- **HTTP Client**: [Library/function used]
- **Request Type**: [GET/POST, sync/async]

### Evidence
- **Location**: file:line
- **Vulnerable Code**: [Code snippet]
- **URL Source**: [Where URL originates]

### Data Flow
1. User input source → 
2. Processing/storage →
3. HTTP client sink

### Attack Scenario
How an attacker could exploit this:
1. [Steps to reproduce]
2. [Potential targets: metadata, internal APIs, etc.]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping

- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-441**: Unintended Proxy or Intermediary ('Confused Deputy')
- **CWE-611**: Improper Restriction of XML External Entity Reference (related)

## Cross-Skill Dependencies

SSRF investigations may need:
- **sast-authentication-testing**: Check if internal endpoints require auth
- **sast-authorization-testing**: Verify internal API access controls
- **sast-injection-testing**: URL injection may combine with SSRF

## Common Frameworks & Patterns

### Python
```python
# Dangerous
requests.get(url)
urllib.request.urlopen(url)
httpx.get(url)
aiohttp.ClientSession().get(url)
```

### JavaScript/Node.js
```javascript
// Dangerous
fetch(url)
axios.get(url)
http.get(url)
got(url)
```

### Go
```go
// Dangerous
http.Get(url)
client.Do(req)  // where req.URL is user-controlled
```

### Java
```java
// Dangerous
new URL(url).openConnection()
HttpClient.newHttpClient().send(request, ...)
RestTemplate.getForObject(url, ...)
```

## Safety Rules
- Only analyze code in the repository provided
- Do not attempt to make actual HTTP requests
- Consider infrastructure context (cloud, k8s, etc.)
- Check for both direct and stored SSRF scenarios
