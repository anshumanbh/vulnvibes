---
name: sast-deserialization-testing
description: Investigate insecure deserialization vulnerabilities that can lead to RCE or data manipulation. Use when threat model identifies CWE-502 (Deserialization of Untrusted Data), CWE-915 (Mass Assignment), or object deserialization concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Deserialization Testing Skill

## Purpose
Investigate deserialization vulnerabilities by analyzing:
- **Unsafe deserializers** (pickle, yaml, Marshal)
- **Data sources** for deserialized objects
- **Object binding** from user input (mass assignment)
- **Type coercion** and gadget chains

## CRITICAL: Why Deserialization is Dangerous

Insecure deserialization can lead to:
1. **Remote Code Execution (RCE)** - Arbitrary code via gadget chains
2. **Object Injection** - Manipulating application state
3. **Mass Assignment** - Setting unauthorized fields
4. **Denial of Service** - Resource exhaustion via nested objects

## Vulnerability Types Covered

### 1. Python Pickle Deserialization (CWE-502)
Python's pickle module executes arbitrary code during deserialization.

**Dangerous Patterns:**
```python
import pickle

# CRITICAL: Never unpickle untrusted data
data = request.get_data()
obj = pickle.loads(data)  # RCE!

# Base64-encoded pickle
import base64
encoded = request.args.get('data')
obj = pickle.loads(base64.b64decode(encoded))  # RCE!

# From file uploaded by user
with open(uploaded_file, 'rb') as f:
    obj = pickle.load(f)  # RCE!

# From Redis/cache (if attacker can poison cache)
cached = redis.get(key)
obj = pickle.loads(cached)
```

**Safe Patterns:**
```python
# Use JSON instead
import json
data = request.get_json()

# If pickle is absolutely required, use hmac signing
import hmac
def safe_loads(data, key):
    signature, payload = data.split(b':', 1)
    expected = hmac.new(key, payload, 'sha256').digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature")
    return pickle.loads(payload)
```

### 2. YAML Deserialization (CWE-502)
PyYAML with unsafe loader allows code execution.

**Dangerous Patterns:**
```python
import yaml

# CRITICAL: yaml.load without Loader
data = request.get_data()
config = yaml.load(data)  # RCE in older PyYAML versions

# Explicitly unsafe
config = yaml.load(data, Loader=yaml.UnsafeLoader)
config = yaml.unsafe_load(data)

# FullLoader still has some risks
config = yaml.load(data, Loader=yaml.FullLoader)
```

**Safe Patterns:**
```python
# Use SafeLoader
config = yaml.safe_load(data)
config = yaml.load(data, Loader=yaml.SafeLoader)

# Or use JSON for untrusted input
import json
config = json.loads(data)
```

### 3. Mass Assignment (CWE-915)
Binding user input directly to object attributes.

**Dangerous Patterns:**
```python
# Direct attribute assignment from request
user = User()
for key, value in request.json.items():
    setattr(user, key, value)  # Can set is_admin, role, etc.

# ORM update with all fields
User.query.filter_by(id=user_id).update(request.json)

# Model creation with **kwargs
user = User(**request.json)  # All fields from request

# Django example
user = User.objects.create(**request.POST.dict())
```

**Safe Patterns:**
```python
# Explicit field allowlist
ALLOWED_FIELDS = {'name', 'email', 'bio'}
data = {k: v for k, v in request.json.items() if k in ALLOWED_FIELDS}
user = User(**data)

# Pydantic/dataclass validation
from pydantic import BaseModel

class UserUpdate(BaseModel):
    name: str
    email: str
    # is_admin NOT included - cannot be set

user_data = UserUpdate(**request.json)

# Django Forms
form = UserForm(request.POST)
if form.is_valid():
    user = form.save()
```

### 4. JSON Deserialization with Custom Decoders
Custom object hooks can be exploited.

**Dangerous Patterns:**
```python
import json

# Custom decoder that instantiates classes
def object_hook(d):
    if '__class__' in d:
        cls = globals()[d['__class__']]  # Dangerous!
        return cls(**d)
    return d

data = json.loads(request.data, object_hook=object_hook)

# jsonpickle (unsafe by default)
import jsonpickle
obj = jsonpickle.decode(request.data)  # Can instantiate arbitrary classes
```

**Safe Patterns:**
```python
# Plain JSON without object hooks
data = json.loads(request.data)

# Type-safe deserialization
from pydantic import BaseModel
data = UserModel.parse_raw(request.data)

# marshmallow schemas
schema = UserSchema()
user = schema.loads(request.data)
```

### 5. Other Language Patterns

**Java:**
```java
// Dangerous
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();  // RCE via gadget chains

// Jackson with default typing
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // Dangerous!
```

**PHP:**
```php
// Dangerous
$obj = unserialize($_POST['data']);  // Object injection

// Safe
$data = json_decode($_POST['data'], true);  // Returns array
```

**Ruby:**
```ruby
# Dangerous
obj = Marshal.load(params[:data])
YAML.load(params[:config])

# Safe
data = JSON.parse(params[:data])
YAML.safe_load(params[:config])
```

## Investigation Methodology

### Step 1: Find Deserialization Functions
```
# Python
Search for: pickle.load, pickle.loads, cPickle
           yaml.load, yaml.unsafe_load
           marshal.load, shelve.open
           jsonpickle.decode

# General
Search for: deserialize, unmarshal, unserialize
           object_hook, decode(, loads(
```

### Step 2: Trace Data Sources
For each deserialization call:
1. Where does the data come from?
2. Is it user-controllable (request, file, cache)?
3. Is there any validation before deserialization?

### Step 3: Check for Mass Assignment
```
Search for: setattr(, __dict__.update
           **request, **kwargs, .update(request
           Model(**data), create(**data)
```

### Step 4: Identify Gadget Chain Risks
- What classes are available in scope?
- Are there classes with dangerous `__reduce__`, `__getstate__`?
- What libraries are imported that have known gadgets?

### Step 5: Check for Mitigations
- Input validation/sanitization
- Signing/HMAC verification
- Type restrictions
- Sandboxing

## Classification Criteria

**TRUE_POSITIVE:**
- Pickle/Marshal loads from user input
- yaml.load without SafeLoader on user data
- Mass assignment with no field filtering
- Custom object hooks that instantiate arbitrary classes

**FALSE_POSITIVE:**
- Deserializing from trusted, signed sources
- yaml.safe_load used consistently
- Explicit allowlist for mass assignment
- Pydantic/marshmallow with strict schemas

**UNVALIDATED:**
- Data source unclear (might be trusted)
- Partial validation that may be bypassable
- Framework-level protections may apply

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Vulnerability Type
- **Category**: Pickle RCE / YAML RCE / Mass Assignment / JSON Object Injection
- **Potential Impact**: RCE / Privilege Escalation / Data Manipulation

### Evidence
- **Location**: file:line
- **Dangerous Function**: [pickle.loads, yaml.load, etc.]
- **Data Source**: [request, file, cache, etc.]

### Attack Scenario
1. [How attacker provides malicious payload]
2. [What code executes or what state changes]

### Gadget Chain Analysis (if applicable)
- Libraries in scope: [list]
- Known gadgets: [if any]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping

### Deserialization
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-1321**: Improperly Controlled Modification of Object Prototype Attributes (JS)

### Mass Assignment
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes
- **CWE-1321**: Prototype Pollution (JavaScript)

### Related
- **CWE-94**: Code Injection (result of deserialization)
- **CWE-470**: Use of Externally-Controlled Input to Select Classes or Code

## Cross-Skill Dependencies

Deserialization investigations may need:
- **sast-injection-testing**: Code injection as result
- **sast-authorization-testing**: Mass assignment to privilege fields
- **sast-authentication-testing**: Session object manipulation

## Known Gadget Libraries

### Python
- `subprocess`, `os` - Command execution
- `requests` - SSRF chains
- Various ORMs - SQL execution

### Java
- Commons Collections
- Spring Framework
- Jackson, Fastjson

### .NET
- TypeNameHandling.Auto
- BinaryFormatter, NetDataContractSerializer

## Safety Rules
- Only analyze code in the repository provided
- Do not attempt to craft or execute payloads
- Consider the full data flow from source to sink
- Check for signing/validation mechanisms
