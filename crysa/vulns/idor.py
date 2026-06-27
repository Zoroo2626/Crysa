"""IDOR (Insecure Direct Object Reference) reasoning hints.

These hints are injected into the LLM prompt to sharpen its focus
on object-level authorization flaws.
"""

HINT = """
## IDOR (Insecure Direct Object Reference) Analysis

You are looking for a specific pattern: the code references a resource by an ID
(either in the URL, request body, query parameter, or path parameter) but does NOT
verify that the requesting user is authorized to access that specific resource.

### What to look for:

1. **Direct ID from user input**: The handler takes an ID from the request
   (e.g., order_id, user_id, file_id) and uses it to fetch, update, or delete
   a resource WITHOUT checking ownership.

2. **Sequential or predictable IDs**: Numeric auto-increment IDs in URLs like
   /api/orders/123 are trivially enumerable. If there's no ownership check,
   any authenticated user can iterate through IDs.

3. **GraphQL mutations**: A mutation like `updateOrder(id: $id, ...)` that
   doesn't verify the caller owns the order. GraphQL is especially prone
   because the schema often exposes all object IDs.

4. **Missing checks on CRUD operations**: The code checks authentication
   (is the user logged in?) but not authorization (does this user own
   this specific resource?).

5. **Nested resource access**: Accessing /users/456/orders/789 where the code
   checks if the user is authenticated but doesn't verify user 456 matches
   the authenticated user, or that order 789 belongs to user 456.

### Vulnerable pattern:
```
@router.put("/orders/{order_id}")
async def update_order(order_id: int, data: OrderUpdate, user=Depends(get_user)):
    # BAD: Only checks authentication, not ownership
    order = await Order.get(id=order_id)
    order.update(data.dict())
    return order
```

### Secure pattern:
```
@router.put("/orders/{order_id}")
async def update_order(order_id: int, data: OrderUpdate, user=Depends(get_user)):
    # GOOD: Filters by both ID and owner
    order = await Order.get(id=order_id, user_id=user.id)
    if not order:
        raise HTTPException(404, "Order not found")
    order.update(data.dict())
    return order
```

### Key question to ask:
"If I am user A, and I change the ID in the request to point to user B's
resource, will the server let me read, modify, or delete it?"

If the answer is yes or unclear, flag it as IDOR.
"""
