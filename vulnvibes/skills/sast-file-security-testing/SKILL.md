---
name: sast-file-security-testing
description: Investigate file operation vulnerabilities including unrestricted file upload, path traversal in file operations, and insecure file handling. Use when threat model identifies CWE-434 (Unrestricted Upload), CWE-73 (External Control of File Path), CWE-427 (Uncontrolled Search Path), or file security concerns.
allowed-tools: Read, Grep, Glob
---

# SAST File Security Testing Skill

## Purpose
Investigate file operation vulnerabilities by analyzing:
- **File upload handling** (type, size, name validation)
- **File path construction** from user input
- **File read/write operations** with user-controlled paths
- **File execution** and dynamic loading

## Vulnerability Types Covered

### 1. Unrestricted File Upload (CWE-434)
Uploading files without proper validation can lead to RCE.

**Dangerous Patterns:**
```python
# No file type validation
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(os.path.join(UPLOAD_DIR, file.filename))
    return 'Uploaded'

# Weak validation (extension only)
if file.filename.endswith('.jpg'):
    file.save(path)  # Bypass: shell.jpg.php, shell.php.jpg

# Content-Type from client (can be forged)
if file.content_type == 'image/jpeg':
    file.save(path)
```

**Safe Patterns:**
```python
from werkzeug.utils import secure_filename
import magic

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    
    # Check extension
    if not allowed_file(file.filename):
        return 'Invalid file type', 400
    
    # Check actual content (magic bytes)
    mime = magic.from_buffer(file.read(1024), mime=True)
    file.seek(0)
    if mime not in ['image/png', 'image/jpeg', 'image/gif']:
        return 'Invalid file content', 400
    
    # Sanitize filename
    filename = secure_filename(file.filename)
    
    # Generate unique name
    filename = f"{uuid.uuid4().hex}_{filename}"
    
    file.save(os.path.join(UPLOAD_DIR, filename))
```

### 2. Path Traversal in File Operations (CWE-73, CWE-22)
User input in file paths allows accessing arbitrary files.

**Dangerous Patterns:**
```python
# Direct path concatenation
@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join(FILES_DIR, filename))
    # Attack: /download/../../../etc/passwd

# User-controlled directory
directory = request.args.get('dir')
files = os.listdir(os.path.join(BASE, directory))

# Template/config loading
template = request.args.get('template')
content = open(f"templates/{template}").read()
```

**Safe Patterns:**
```python
import os

@app.route('/download/<filename>')
def download(filename):
    # Sanitize filename
    filename = secure_filename(filename)
    
    # Resolve and validate path
    safe_path = os.path.realpath(os.path.join(FILES_DIR, filename))
    
    # Ensure path is within allowed directory
    if not safe_path.startswith(os.path.realpath(FILES_DIR)):
        return 'Access denied', 403
    
    if not os.path.exists(safe_path):
        return 'Not found', 404
    
    return send_file(safe_path)
```

### 3. Uncontrolled Search Path (CWE-427)
Loading executables or libraries from user-controlled paths.

**Dangerous Patterns:**
```python
# Dynamic import from user input
module_name = request.args.get('module')
module = __import__(module_name)

# Subprocess with user-controlled command
cmd = request.args.get('tool')
subprocess.run([cmd, '-v'])

# Loading plugins from user path
plugin_path = user_config['plugin_dir']
exec(open(os.path.join(plugin_path, 'plugin.py')).read())
```

**Safe Patterns:**
```python
# Allowlist for dynamic imports
ALLOWED_MODULES = {'math', 'json', 'datetime'}
module_name = request.args.get('module')
if module_name not in ALLOWED_MODULES:
    raise ValueError("Module not allowed")

# Absolute paths for executables
TOOL_PATH = '/usr/local/bin/approved-tool'
subprocess.run([TOOL_PATH, '-v'])
```

### 4. Insecure Temporary Files (CWE-377)
Predictable or insecure temporary file creation.

**Dangerous Patterns:**
```python
# Predictable temp file name
temp_file = f"/tmp/app_{user_id}.txt"
with open(temp_file, 'w') as f:
    f.write(data)

# Race condition in temp file
if not os.path.exists(temp_path):
    with open(temp_path, 'w') as f:
        f.write(data)
```

**Safe Patterns:**
```python
import tempfile

# Secure temp file
with tempfile.NamedTemporaryFile(delete=False) as f:
    f.write(data)
    temp_path = f.name

# Or with context manager
with tempfile.TemporaryDirectory() as tmpdir:
    # Files auto-deleted when context exits
```

### 5. Download Without Integrity Check (CWE-494)
Downloading and executing code without verification.

**Dangerous Patterns:**
```python
# Download and execute
url = config['update_url']
script = requests.get(url).text
exec(script)

# Install package from URL
os.system(f"pip install {url}")
```

**Safe Patterns:**
```python
import hashlib

# Verify checksum
expected_hash = "sha256:abc123..."
content = requests.get(url).content
actual_hash = hashlib.sha256(content).hexdigest()
if f"sha256:{actual_hash}" != expected_hash:
    raise ValueError("Integrity check failed")
```

## Investigation Methodology

### Step 1: Find File Upload Endpoints
```
Search for: request.files, multipart, upload
           save(, write(, wb, file.save
           multer, formidable, busboy
```

### Step 2: Check Upload Validation
For each upload handler:
1. Is file extension validated?
2. Is content type checked (magic bytes, not just header)?
3. Is filename sanitized?
4. Is file size limited?
5. Where is the file stored (web-accessible?)

### Step 3: Find File Path Operations
```
Search for: open(, os.path.join, send_file
           read_file, write_file, shutil
           Path(, pathlib
```

### Step 4: Trace Path Sources
For each file operation:
1. Where does the path come from?
2. Is any part user-controllable?
3. Is path normalized and validated?

### Step 5: Check for Execution Risks
```
Search for: exec(, eval(, __import__
           subprocess, os.system, popen
           require(, import(, load(
```

## Classification Criteria

**TRUE_POSITIVE:**
- File upload with no content validation
- User input directly in file path without sanitization
- Uploaded files stored in web-accessible directory
- No path traversal protection (realpath check)

**FALSE_POSITIVE:**
- Files stored outside web root with random names
- Proper content-type validation via magic bytes
- Path canonicalization with directory containment check
- Allowlist-based filename/path validation

**UNVALIDATED:**
- Validation exists but may be bypassable
- Storage location unclear
- Framework-level protections may apply

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Vulnerability Type
- **Category**: Upload / Path Traversal / Execution
- **CWE**: CWE-XXX

### Evidence
- **Location**: file:line
- **Vulnerable Code**: [Code snippet]
- **User Input Source**: [How attacker provides input]

### Attack Scenario
1. [How attacker exploits this]
2. [What they can achieve: RCE, data theft, etc.]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping

### File Upload
- **CWE-434**: Unrestricted Upload of File with Dangerous Type
- **CWE-646**: Reliance on File Name or Extension
- **CWE-351**: Insufficient Type Distinction

### Path Operations
- **CWE-73**: External Control of File Name or Path
- **CWE-22**: Path Traversal (also in injection-testing)
- **CWE-36**: Absolute Path Traversal
- **CWE-427**: Uncontrolled Search Path Element

### File Integrity
- **CWE-494**: Download of Code Without Integrity Check
- **CWE-377**: Insecure Temporary File
- **CWE-379**: Creation of Temporary File in Directory with Insecure Permissions

## Cross-Skill Dependencies

File security investigations may need:
- **sast-injection-testing**: Path traversal overlaps with injection
- **sast-authorization-testing**: Who can access uploaded files?
- **sast-authentication-testing**: Are upload endpoints authenticated?

## Common Frameworks & Patterns

### Python/Flask
```python
request.files['file']
send_file(), send_from_directory()
secure_filename()
```

### Python/Django
```python
request.FILES['file']
FileField, ImageField
MEDIA_ROOT, MEDIA_URL
```

### Node.js/Express
```javascript
multer({ dest: 'uploads/' })
req.file, req.files
fs.readFile(path)
path.join(base, userInput)
```

### Java/Spring
```java
@RequestParam("file") MultipartFile
Files.copy(file.getInputStream(), path)
new File(userPath)
```

## Safety Rules
- Only analyze code in the repository provided
- Do not attempt to upload files or access file systems
- Consider the full request lifecycle (upload → storage → retrieval)
- Check both direct file operations and framework abstractions
