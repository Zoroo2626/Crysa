"""Mass assignment reasoning hints.

These hints guide the LLM to detect mass assignment vulnerabilities
where users can set fields they shouldn't have access to.
"""

HINT = """
## Mass Assignment Analysis

You are looking for code that binds user-supplied data directly to
database models or internal objects without filtering which fields
the user is allowed to set.

### What to look for:

1. **Direct model binding from request body**: The code takes the entire
   request body and passes it to the ORM model constructor or update method
   without an allowlist.

2. **Privilege escalation via mass assignment**: A user can set fields like:
   - role, is_admin, is_superuser, permissions
   - account_balance, credits, price
   - email_verified, account_status
   - owner_id, created_by (to impersonate)

3. **Framework-specific patterns**:
   - **Django**: `User.objects.create(**request.data)` instead of using
     a serializer with explicit fields
   - **Rails**: Using `params.require(:user).permit!` or missing `permit()`
   - **FastAPI/Pydantic**: Using the same model for input and database
     operations with `model.update(data.dict())`
   - **Express**: `User.create(req.body)` without picking specific fields
   - **Laravel**: `User::create($request->all())` instead of
     `$request->only(['name', 'email'])`

4. **Partial update endpoints**: PUT/PATCH endpoints that accept any
   field in the body and apply all of them to the model.

5. **Nested objects**: Mass assignment through nested JSON objects where
   inner fields are not validated.

### Vulnerable pattern (FastAPI):
```
class UserUpdate(BaseModel):
    name: str
    email: str
    is_admin: bool = False  # This field exists in the model

@app.put("/api/users/me")
def update_user(data: UserUpdate, user=Depends(get_user)):
    # BAD: User can set is_admin=True in the request body
    user.update(data.dict())
    return user
```

### Secure pattern (FastAPI):
```
class UserUpdate(BaseModel):
    name: str
    email: str

class AdminUserUpdate(UserUpdate):
    is_admin: bool

@app.put("/api/users/me")
def update_user(data: UserUpdate, user=Depends(get_user)):
    # GOOD: Only name and email are in the input model
    user.update(data.dict())
    return user
```

### Vulnerable pattern (Express):
```
router.put('/users/:id', async (req, res) => {
    // BAD: All body fields are spread into the update
    await User.findByIdAndUpdate(req.params.id, { ...req.body });
});
```

### Key questions:
- Does the code use an allowlist of permitted fields?
- Can a user set security-sensitive fields like role, balance, or status?
- Are input models separate from database models?
"""
