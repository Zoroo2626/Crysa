"""Privilege escalation reasoning hints.

These hints guide the LLM to detect horizontal and vertical
privilege escalation vulnerabilities.
"""

HINT = """
## Privilege Escalation Analysis

You are looking for code where a user can gain access to resources or
actions that should be restricted to a different privilege level.

### Two types of escalation:

**Horizontal**: User A accesses user B's data (same privilege level).
Example: Changing user_id in the request to view another user's profile.

**Vertical**: Regular user accesses admin functionality.
Example: A non-admin user accessing /admin/dashboard or calling admin-only APIs.

### What to look for:

1. **Frontend-only role checks**: The code relies on the client to hide
   admin buttons or routes. The backend doesn't enforce the same role check.

2. **User-supplied role data**: The role or permission level is read from
   the request body instead of from the authenticated session.
   Example: `is_admin = request.json.get("is_admin")`

3. **Missing role middleware on admin routes**: Admin endpoints that don't
   have role-based access control middleware.

4. **Role checks from JWT claims without verification**: The code reads
   a "role" field from a JWT but doesn't verify the JWT was signed by
   the server, allowing forged tokens.

5. **Broken access control chains**: A chain of middleware where one
   middleware assumes another has already checked permissions, but the
   check is actually missing.

6. **Overly broad permissions**: A role like "editor" that accidentally
   has permission to do everything an admin can do.

7. **Self-role modification**: An endpoint that lets users update their
   own profile and doesn't prevent them from changing their role field.

### Vulnerable pattern (vertical):
```
@app.get("/admin/users")
def list_all_users(request: Request):
    # BAD: No role check — any authenticated user sees all users
    users = User.query.all()
    return [{"id": u.id, "email": u.email} for u in users]
```

### Vulnerable pattern (horizontal):
```
@app.get("/api/profile/{user_id}")
def get_profile(user_id: int, current_user=Depends(get_user)):
    # BAD: No check that user_id matches current_user.id
    profile = Profile.get(user_id=user_id)
    return profile
```

### Key questions:
- Can a regular user reach admin endpoints?
- Does the code trust the client to enforce access restrictions?
- Is the role/permission sourced from a trusted, server-side location?
"""
