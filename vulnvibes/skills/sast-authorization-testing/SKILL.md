---
name: sast-authorization-testing
description: Investigate authorization vulnerabilities in source code including IDOR, privilege escalation, and missing access controls. Use when threat model identifies CWE-639 (IDOR), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-269 (Privilege Escalation), or access control concerns.
allowed-tools: Read, Grep, Glob
---

# SAST Authorization Testing Skill

## Purpose
Investigate authorization failures in source code by tracing:
- **User identity checks** (horizontal privilege escalation / IDOR)
- **Role/privilege verification** (vertical privilege escalation)
- **Resource ownership validation** rules
- **Function-level access controls**

## Vulnerability Types Covered

### 1. Insecure Direct Object Reference - IDOR (CWE-639)
User can access other users' resources by manipulating object IDs.

**Code Patterns to Find:**
- Direct use of user-supplied IDs without ownership checks
- Missing `user_id == current_user.id` comparisons
- API endpoints accepting resource IDs without authorization

**Example Vulnerable Code:**
```python
@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    return User.query.get(user_id).to_dict()  # No check if current user can access
```

### 2. Vertical Privilege Escalation (CWE-269)
User performs actions requiring higher privileges.

**Code Patterns to Find:**
- Admin endpoints without role checks
- Missing `@admin_required` or `@role_required` decorators
- Role modification endpoints accessible to regular users

**Example Vulnerable Code:**
```python
@app.route('/admin/delete_user', methods=['POST'])
def delete_user():  # No @admin_required
    User.query.filter_by(id=request.json['id']).delete()
```

### 3. Missing Authorization (CWE-862)
Actions execute without ANY authorization check.

**Code Patterns to Find:**
- API endpoints with no authentication decorator
- Direct database operations without auth context
- Sensitive operations in unauthenticated routes

### 4. Incorrect Authorization (CWE-863)
Wrong authorization logic applied.

**Code Patterns to Find:**
- Flawed ownership checks (checking wrong field)
- OR instead of AND in permission checks
- Race conditions in authorization

## Investigation Methodology

### Step 1: Identify Entry Points
Search for affected routes/endpoints from PR changes:
```
Grep for: @app.route, @router, def handle_, async def
```

### Step 2: Trace Authorization Decorators
Look for authorization decorators/middleware:
```
Patterns: @require_auth, @login_required, @admin_only
          @permission_required, @role_required
          authorize!, can?, has_permission
```

### Step 3: Check Ownership Validation
Search for ownership checks in handlers:
```
Patterns: current_user.id ==, request.user.id
          .filter(user_id=, owner_id=
          belongs_to?, owned_by
```

### Step 4: Cross-Reference with Org
Use `github_org_code_search` to find:
- How other endpoints implement authz
- Shared auth middleware/decorators
- Common security patterns in the org

### Step 5: Verify Data Flow
Trace from user input → database query:
- Is the resource ID validated against user context?
- Can a user access resources they don't own?

## Classification Criteria

**TRUE_POSITIVE:**
- No authorization check exists for sensitive operation
- Ownership check is missing or bypassable
- Role check uses wrong comparison logic

**FALSE_POSITIVE:**
- Proper authorization decorator exists
- Ownership validation is implemented correctly
- Access is intentionally public

**UNVALIDATED:**
- Authorization logic is in middleware not visible in PR
- Complex dynamic authorization that can't be statically analyzed

## Output Format

```markdown
### Verdict
- **verdict**: TRUE_POSITIVE or FALSE_POSITIVE
- **confidence_score**: 1-10
- **risk_level**: LOW, MEDIUM, HIGH, or CRITICAL

### Evidence
- **Location**: file:line
- **Issue**: Description of the authorization gap
- **Code**: Relevant code snippet

### Attack Scenario
How an attacker could exploit this:
1. [Steps to reproduce]

### Recommendations
- [Specific fix with code example]
```

## CWE Mapping
- **CWE-639**: Authorization Bypass Through User-Controlled Key (IDOR)
- **CWE-269**: Improper Privilege Management
- **CWE-862**: Missing Authorization
- **CWE-863**: Incorrect Authorization
- **CWE-284**: Improper Access Control

## Safety Rules
- Only analyze code in the repository provided
- Do not attempt to exploit or test against live systems
- Redact any sensitive data (API keys, secrets) from evidence
