---
name: sast-injection-testing
description: Investigate injection vulnerabilities in source code including SQL injection, XSS, and command injection. Use when threat model identifies CWE-89 (SQL Injection), CWE-79 (XSS), CWE-78 (OS Command Injection), or injection concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Injection Testing Skill

## Purpose
Investigate injection vulnerabilities by tracing:
- **User input sources** (requests, forms, files)
- **Data flow** from input to dangerous sinks
- **Sanitization/validation** along the path
- **Dangerous function calls** with user data

## Vulnerability Types Covered

### 1. SQL Injection (CWE-89)
User input directly inserted into SQL queries.

**Dangerous Patterns:**
```python
# String formatting in queries
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)

# String concatenation
sql = "SELECT * FROM users WHERE id = " + request.args.get('id')
```

**Safe Patterns:**
```python
# Parameterized queries
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
User.query.filter_by(id=user_id).first()
```

### 2. Cross-Site Scripting - XSS (CWE-79)
User input rendered in HTML without escaping.

**Dangerous Patterns:**
```python
# Direct rendering without escaping
return f"<div>{user_input}</div>"
render_template_string(f"Hello {name}")

# Using |safe filter incorrectly
{{ user_input|safe }}
```

**Safe Patterns:**
```python
# Template auto-escaping
render_template('page.html', name=name)
{{ user_input }}  # Auto-escaped by default
escape(user_input)
```

### 3. Command Injection (CWE-78)
User input passed to shell commands.

**Dangerous Patterns:**
```python
# Direct shell execution
os.system(f"ping {host}")
subprocess.call(f"convert {filename}", shell=True)
os.popen(f"cat {file}")
```

**Safe Patterns:**
```python
# Using arrays (no shell)
subprocess.run(["ping", host], shell=False)
# Input validation
if not re.match(r'^[\w.-]+$', host):
    raise ValueError("Invalid host")
```

### 4. Path Traversal (CWE-22)
User input used to construct file paths.

**Dangerous Patterns:**
```python
open(f"/uploads/{filename}")
os.path.join(base_dir, user_path)  # Without validation
```

## Investigation Methodology

### Step 1: Find Input Sources
Search for user input entry points:
```
Patterns: request.args, request.form, request.json
          request.get, request.data, request.files
          @app.route, def handle_
```

### Step 2: Trace to Dangerous Sinks
Find dangerous functions receiving input:
```
SQL: execute(, raw(, cursor., .query(
XSS: render_template_string, Markup(, |safe
CMD: os.system, subprocess., os.popen, eval(
Path: open(, os.path.join, read_file
```

### Step 3: Check Sanitization
Look for validation/sanitization:
```
Patterns: escape(, sanitize(, validate(
          bleach., html.escape, quote(
          parameterized, prepared
```

### Step 4: Verify Data Flow
Trace the complete path:
1. Where does user input enter?
2. Is it validated/sanitized?
3. Does it reach a dangerous sink?

### Step 5: Cross-Reference with Org
Use `github_org_code_search` to find:
- Similar patterns in other services
- Shared validation libraries
- Common injection points

## Classification Criteria

**TRUE_POSITIVE:**
- User input reaches dangerous sink without sanitization
- Parameterization is not used for SQL
- Command constructed with user input

**FALSE_POSITIVE:**
- Proper parameterization/escaping exists
- Input is validated before use
- Dangerous function not reachable with user data

**UNVALIDATED:**
- Sanitization happens in external library
- Complex data flow spanning multiple files

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Evidence
- **Location**: file:line
- **Injection Type**: SQL/XSS/Command/Path
- **Data Flow**: source → sink
- **Code**: Relevant code snippet

### Proof of Concept
Example malicious input that would exploit this:
```
[Payload example]
```

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping
- **CWE-89**: SQL Injection
- **CWE-79**: Cross-site Scripting (XSS)
- **CWE-78**: OS Command Injection
- **CWE-22**: Path Traversal
- **CWE-94**: Code Injection

## Safety Rules
- Only analyze code in the repository provided
- Do not attempt to exploit or test against live systems
- Redact any sensitive data from evidence
