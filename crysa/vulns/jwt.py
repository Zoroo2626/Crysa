"""JWT and token issue reasoning hints.

These hints guide the LLM to detect JWT implementation flaws
and token handling vulnerabilities.
"""

HINT = """
## JWT and Token Issue Analysis

You are looking for flaws in how JWTs (JSON Web Tokens) and other
authentication tokens are created, verified, and managed.

### What to look for:

1. **Algorithm confusion**: The code accepts the algorithm from the JWT
   header instead of enforcing it. An attacker can change the algorithm:
   - Set "alg": "none" to skip verification entirely
   - Switch from RS256 to HS256 and sign with the public key
   - Use a weaker algorithm the server accepts

2. **Missing signature verification**: The code decodes the JWT payload
   without verifying the signature. Common in libraries where decode
   and verify are separate functions.

3. **No expiry or very long expiry**: Tokens that are valid forever
   or for an unreasonable time (e.g., 365 days). If a token is stolen,
   it can be used indefinitely.

4. **Sensitive data in payload**: JWTs are base64-encoded, not encrypted.
   Storing passwords, SSNs, or internal IDs in the payload exposes them
   to anyone who intercepts the token.

5. **No token invalidation on logout**: The application logs the user
   out on the client side but doesn't invalidate the token server-side.
   A stolen token remains valid until it expires.

6. **Weak or hardcoded secrets**: JWT signing secrets that are:
   - Hardcoded in the source code
   - Common values like "secret", "password", or the app name
   - Too short (less than 256 bits for HS256)
   - Shared across environments

7. **Token in URL**: JWT passed as a query parameter instead of in
   headers. Query params are logged in server logs, browser history,
   and proxy logs.

### Vulnerable pattern (algorithm confusion):
```
import jwt

def verify_token(token: str) -> dict:
    # BAD: Algorithm from the token header is used
    return jwt.decode(token, SECRET_KEY, algorithms=["RS256", "HS256", "none"])
```

### Secure pattern:
```
import jwt

def verify_token(token: str) -> dict:
    # GOOD: Only one algorithm allowed, none explicitly excluded
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
```

### Vulnerable pattern (no verification):
```
import base64

def get_user_from_token(token: str) -> dict:
    # BAD: Just decoding payload without verification
    payload = token.split('.')[1]
    return json.loads(base64.b64decode(payload))
```

### Key questions:
- Does the code enforce a specific signing algorithm?
- Is the signature actually verified before using the payload?
- Can tokens be used after logout?
- Is the signing secret strong and properly managed?
"""
