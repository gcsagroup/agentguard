# Pro / Enterprise billing

AgentGuard uses a **local entitlement store** (`policies/entitlement.json`) so Pro features can be gated offline.

## Dev activate

```bash
# Issue a token (dev secret unless AGENTGUARD_LICENSE_SECRET is set)
TOKEN=$(cargo run -q -p guard-cli -- entitlement-issue --license-id demo-1 --plan pro)
echo "$TOKEN"

cargo run -p guard-cli -- entitlement-activate --token "$TOKEN" --store policies/entitlement.json
cargo run -p guard-cli -- entitlement-status
```

## Webhook apply (file / one-shot)

```bash
cargo run -p guard-cli -- billing-webhook \
  --file eval/fixtures/billing_webhook_purchase.json \
  --store /tmp/ag-ent.json
```

## Local HTTP webhook receiver

```bash
# Terminal A
cargo run -p guard-cli -- billing-webhook-serve --bind 127.0.0.1:8787 --store /tmp/ag-ent.json

# Terminal B
curl -sS -X POST http://127.0.0.1:8787/webhook/billing \
  -H 'Content-Type: application/json' \
  -d '{"type":"purchase","license_id":"curl-1","plan":"pro"}'
curl -sS http://127.0.0.1:8787/health
```

## Production note
Point Stripe/Paddle/App Store webhooks at `POST /webhook/billing` (or adapt the JSON shape). The local store format stays the same; replace the shared-secret token scheme when you wire live providers.

## Feature flags
| Plan | unlimited_audit | custom_rules | enterprise_export |
|------|-----------------|--------------|-------------------|
| Free | ❌ | ❌ | ❌ |
| Pro | ✅ | ✅ | ❌ |
| Enterprise | ✅ | ✅ | ✅ |
