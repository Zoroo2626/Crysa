"""Authentication bypass reasoning hints.

These hints are injected into the LLM prompt to sharpen its focus
on authentication flaws and bypass vectors.
"""

HINT = """
## Authentication Bypass Analysis

You are looking for routes, endpoints, or code paths where authentication
checks are missing, incomplete, or can be circumvented.

### What to look for:

1. **Missing auth on sensitive routes**: Any route that handles user data,
   modifies state, or performs privileged actions but has NO authentication
   middleware or decorator.

2. **Auth after the operation**: The code performs the sensitive operation
   FIRST and checks auth AFTER. For example, writing to the database before
   verifying the user is logged in.

3. **Bypassable middleware**: Auth middleware that can be skipped by:
   - Adding a specific header (e.g., X-Skip-Auth)
   - Using a specific HTTP method the middleware doesn't cover
   - Requesting a path with different casing or trailing slash
   - Sending the request before middleware is fully loaded

4. **Password reset token issues**: Reset tokens that are:
   - Not tied to a specific user account
   - Not invalidated after use
   - Valid indefinitely (no expiry)
   - Predictable or brute-forceable

5. **Account enumeration**: Login, registration, or password reset flows
   that reveal whether an email/username exists through:
   - Different error messages ("user not found" vs "wrong password")
   - Different response times
   - Different HTTP status codes

6. **Session fixation**: The application accepts a session ID from the user
   and doesn't regenerate it after successful authentication.

7. **Session invalidation**: Sessions that remain valid after:
   - Password change
   - Logout
   - Account deactivation

### Vulnerable pattern:
```
@app.post("/api/admin/users")
def create_user(data: UserCreate):
    # BAD: No auth check at all
    user = User.create(**data.dict())
    return user
```

### Another vulnerable pattern (auth after action):
```
@app.post("/api/transfer")
def transfer_money(data: TransferRequest):
    # BAD: Transfer happens before auth check
    perform_transfer(data.from_account, data.to_account, data.amount)
    if not current_user.is_authenticated:
        raise HTTPException(401)
    return {"status": "complete"}
```

### Key questions:
- Can this endpoint be called without any credentials?
- Does the auth check happen BEFORE the sensitive operation?
- Can the auth mechanism be bypassed with crafted requests?
"""
