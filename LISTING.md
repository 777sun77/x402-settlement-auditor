# Free x402 registry submissions

Updated 2026-11-05. All submissions below were made without sending a payment. No featured placement or paid review was requested.

Service: [x402 Settlement Auditor](https://x402-settlement-auditor.onrender.com/v1/audit)  
Price/payee unchanged: **$0.01** per audit; `0x8424f298f5385290567f4adee3e8ab7d7ced9bc7`.

## Results

| Registry | HTTP | Result | Listing/server page |
| --- | ---: | --- | --- |
| x402scan | 200 | Accepted; resource `4f973911-ca72-4252-abc0-b6b8a63cbfe6`; origin `2309bb1b-b6c1-4dd6-a920-69681c4a2ac6`; accept `63591de5-ba1b-45ba-9989-5d94d4af8d4c`. The returned resource currently has `verified: false`. | [x402scan server page](https://www.x402scan.com/server/2309bb1b-b6c1-4dd6-a920-69681c4a2ac6) (HTTP 200) |
| x402dash | 201 | Registered and verified; endpoint ID `x402-settlement-auditor.onrender.com/v1/audit`. | [x402dash liveness record](https://api.x402dash.com/v1/liveness?endpoint=https%3A%2F%2Fx402-settlement-auditor.onrender.com%2Fv1%2Faudit) (HTTP 200). No separate public server page URL was returned by the registration API. |
| YourAITools | 403 | Rejected at Cloudflare with error 1010 `browser_signature_banned`; response says access is blocked based on the request browser signature and explicitly says not to retry. No listing ID or status URL was issued. | None |
| OrbitX402 | 403 | Rejected at Cloudflare with error 1010 `browser_signature_banned`; response says access is blocked based on the request browser signature and explicitly says not to retry. No server/listing ID or status URL was issued. | None |

## Verification

- `GET /openapi.json`: **200**, OpenAPI 3.1.0.
- `GET /.well-known/x402`: **200**, resource `https://x402-settlement-auditor.onrender.com/v1/audit`.
- Unauthenticated malformed `POST /v1/audit`: **402**; decoded `PAYMENT-REQUIRED` challenge matches the JSON body.
- `GET /v1/audit`: **402**; decoded challenge matches the JSON body.
- `npx -y @agentcash/discovery x402-settlement-auditor.onrender.com -v`: discovered the OpenAPI spec and paid POST operation, **no warnings**.
- Full test suite: `python3 -W error::ResourceWarning -m unittest discover -s tests -v` — **72 passed**.

The x402scan identity challenge was signed by `/workspace/x402list/siwx_register.py`; the private key was not printed or recorded here.
