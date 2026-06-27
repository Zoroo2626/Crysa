"""Sensitive data exposure reasoning hints.

These hints guide the LLM to detect where sensitive data might
be leaked through API responses, logs, or error messages.
"""

HINT = """
## Sensitive Data Exposure Analysis

You are looking for code that leaks sensitive information through
API responses, error messages, logs, or debug endpoints.

### What to look for:

1. **PII in API responses**: Endpoints that return more user data than
   needed. Common over-exposure:
   - Returning password hashes, even hashed ones
   - Including phone numbers, addresses, SSNs in list endpoints
   - Returning another user's email or personal data
   - Internal user IDs, database keys in public responses

2. **Internal identifiers**: Responses that expose:
   - Database auto-increment IDs (use UUIDs instead)
   - Internal system paths or server names
   - Version numbers that reveal tech stack
   - Internal service URLs or ports

3. **Stack traces in production**: Error handlers that return full
   stack traces, file paths, or line numbers to the client.
   These reveal the tech stack and internal structure.

4. **Debug endpoints left enabled**: Development endpoints that are
   still accessible in production:
   - /debug, /_debug, /admin/debug
   - Django debug toolbar
   - Flask debugger
   - Swagger/OpenAPI docs with sensitive schemas
   - Database query endpoints

5. **Verbose error messages**: Errors that reveal implementation details:
   - "Table 'users' doesn't exist" (reveals DB structure)
   - "File not found: /home/app/config/secrets.yaml" (reveals paths)
   - "Connection refused to 10.0.1.5:5432" (reveals internal network)

6. **Logging sensitive fields**: Code that logs:
   - Passwords, tokens, or API keys
   - Full request bodies containing PII
   - Credit card numbers or bank details
   - Session tokens or cookies

7. **Response headers leaking info**: Headers like:
   - X-Powered-By revealing the framework
   - Server header revealing the web server and version
   - Debug headers left from development

### Vulnerable pattern (over-exposure):
```
@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    user = await User.get(id=user_id)
    # BAD: Returns everything including password_hash, ssn, internal fields
    return user.dict()
```

### Secure pattern:
```
@app.get("/api/users/{user_id}")
async def get_user(user_id: int, current_user=Depends(get_user)):
    user = await User.get(id=user_id)
    # GOOD: Only return public-safe fields
    return {
        "id": user.public_id,
        "name": user.name,
        "avatar": user.avatar_url,
    }
```

### Vulnerable pattern (logging):
```
def process_login(request):
    logger.info(f"Login attempt: {request.json()}")
    # BAD: Logs the full request including password
```

### Key questions:
- Does the response include data the caller doesn't need?
- Are error messages safe to show to an attacker?
- Are debug/development features disabled in production?
- Do logs contain secrets or PII?
"""
