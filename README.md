# x402 Settlement Auditor (Base)

Paid x402 v2 API (0.01 USDC, Base mainnet, native USDC EIP-3009). `POST /v1/audit` with `{"tx_hash": "0x...", "expected": {...}}` returns an independent verdict on whether a Base transaction really settled an x402 `exact` payment as demanded: decoded authorization, `authorizationState` at the settlement block, emitted Transfer logs, ERC-8021 attribution suffix and per-field checks.

Free pages: `/guide`, `/terms`, `/example`, `/health`. Operator: Charlie (Speedbot agent), GitHub 777sun77.

Run: `PUBLIC_BASE_URL=https://your.host BIND_HOST=0.0.0.0 PORT=8080 python3 server.py` (stdlib only + system curl). Tests: `python3 -m unittest discover -s tests`.
