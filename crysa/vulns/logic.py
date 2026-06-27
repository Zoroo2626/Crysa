"""Business logic flaw reasoning hints.

These hints guide the LLM to detect logic vulnerabilities that
allow attackers to abuse the intended workflow of an application.
"""

HINT = """
## Business Logic Flaw Analysis

You are looking for code where the application's business logic can
be manipulated to produce unintended outcomes. These are the hardest
vulnerabilities to find with static analysis because they require
understanding the intended workflow.

### What to look for:

1. **Price manipulation**: Checkout or payment flows where the price
   is calculated from client-side data or can be modified in the request.
   Example: Sending `{"price": 0.01}` in the order body.

2. **Quantity/limit bypasses**: The code trusts client-side quantity
   values. Negative quantities to credit money, zero quantities to
   get free items, or quantities exceeding available stock.

3. **Race conditions**: Time-of-check to time-of-use (TOCTOU) bugs:
   - Double-spending a coupon code
   - Double-redeeming a reward
   - Withdrawing more than account balance by sending parallel requests
   - Buying more than available stock with concurrent requests

4. **Workflow step skipping**: Multi-step processes (checkout, onboarding,
   verification) where the backend doesn't verify the user completed
   each preceding step. Example: Jumping from step 1 to step 3.

5. **Negative value inputs**: Fields like quantity, amount, or price
   that accept negative numbers. A negative quantity in a return
   could credit money to the attacker.

6. **Coupon/discount abuse**:
   - Applying a coupon multiple times
   - Combining coupons that should be mutually exclusive
   - Using a coupon after it's expired or for wrong products
   - Stacking percentage discounts to get items for free

7. **State manipulation**: Changing order status directly (e.g.,
   from "pending" to "completed") without going through the proper
   payment flow.

### Vulnerable pattern (race condition):
```
@app.post("/api/redeem-coupon")
async def redeem_coupon(code: str, user=Depends(get_user)):
    coupon = await Coupon.get(code=code)
    if coupon and coupon.is_valid:
        # BAD: Check and redeem are not atomic
        coupon.is_valid = False
        await coupon.save()
        await credit_account(user.id, coupon.value)
        return {"credited": coupon.value}
```

### Vulnerable pattern (price manipulation):
```
@app.post("/api/checkout")
async def checkout(order: OrderRequest, user=Depends(get_user)):
    # BAD: Price comes from client
    total = order.price * order.quantity
    await charge_user(user.id, total)
```

### Secure pattern (server-side calculation):
```
@app.post("/api/checkout")
async def checkout(order: OrderRequest, user=Depends(get_user)):
    # GOOD: Price calculated server-side
    product = await Product.get(id=order.product_id)
    total = product.price * order.quantity
    await charge_user(user.id, total)
```

### Key questions:
- Can a user skip steps in a multi-step process?
- Are business values (price, quantity, discount) calculated server-side?
- Can parallel requests cause the same action to execute twice?
- Can negative or zero values produce unintended outcomes?
"""
