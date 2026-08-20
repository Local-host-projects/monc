# MONC App Architecture

## Payment lifecycle (async state machine)

```text
merchant creates a fixed payment intent through the merchant API (status: pending)
  |  checkout page verifies intent context (merchant/domain/product/amount/initiator)
  |  owner proves ownership with token + pattern; browser signs the exact intent
  v
MONC policy verdict (fail closed)
  +------------ ALLOWED (authorized) -------------+          DENIED -> terminal
  |                                               |
  v                                               |
customer starts ALAT Authenticator consent:      |
  status: consent_pending / customer_action_required
  |  sandbox: demo approval code; live: ALAT app
  v
Wema consent approved  -> MONC funds merchant wallet (debited -> processing)
  |  FundWallet / ProcessClientTransfer with intent-bound reference
  v
Wema payout confirmed -> merchant ledger credited ONCE (successful)
  +  reconciliation via transhistoryV2 / ledger review
  x  failure/reversal -> fails closed, nothing credited
```

State is carried on `PaymentIntent` (`status`, `wema_state`, `wema_reference`,
`settlement_reference`, `settlement_provider_reference`, `source_account_masked`,
`merchant_credited`, `state_reason`). `GET /api/payment-intents/{id}/status` advances the
machine exactly one Wema hop per call (consent poll → fund → confirm) and is idempotent.

## Trust boundaries

- The merchant receives only a verdict and settlement detail, never PAN, CVV, pattern,
  private key, or the reconstructed server half.
- The merchant API receives structured checkout context and must sign it in production.
- The agent receives a scoped payment capability, never a MONC secret. Agent delegation is
  the next implementation slice.
- The backend stores encrypted server-half material and encrypted policy; `MONC_SECRET_KEY`
  protects policy encryption in this prototype (production: KMS/HSM).
- Money never moves without a policy verdict **and** ALAT Authenticator customer consent.

## Wema adapter

`app/wema.py`:

- `WemaGateway` — the boundary interface.
- `SandboxWemaGateway` — deterministic in-memory lifecycle used by default; no credentials,
  no network. Drives the whole demo (consent codes, wallet funding, history).
- `AlatWemaGateway` — live adapter built from the four Wema OpenAPI specs:
  `pwba-authenticator` (consent), `debit-wallet` (enquiry/NIP), `credit-wallet`
  (payout/confirm), `ws-acct-mgt` (account check/reconciliation). Requires
  `WEMA_SUBSCRIPTION_KEY`; uses `WEMA_CHANNEL_ID` and `WEMA_ACCOUNT_API_KEY` where
  the spec declares `access`/`x-api-key` headers.

Every Wema response is normalized through `unwrap()` (envelope strip) and
`normalize_wema_state()` into the MONC vocabulary:
`initiated / pending / customer_action_required / processing / successful / failed / reversed / unknown`.
Failure of any Wema call fails the intent closed. Sandbox/Playground mode selection is via
`MONC_WEMA_MODE`; base URLs default to `https://apiplayground.alat.ng` and are overridable.

## Card data boundary

The form demonstrates local encryption only. It must never receive real card data in
development. A live product should use a PCI-compliant browser tokenization flow or
Wema/acquirer-hosted fields; MONC should authorize and settle a processor token, not PAN/CVV.
Customer consent moves money from a Wema/ALAT account, not a raw card.

## Cryptography status

- AES-GCM for local card/signing-package encryption and server policy encryption.
- P-256 ECDSA binds authorization to an exact payment intent.
- Signature + policy verdict authorize; the Wema consent hop is a separate customer action.
- Browser PBKDF2 is a WebCrypto-only fallback; audited Argon2id WASM must replace
  `patternKey()` before any production security claim.
- The server never receives the pattern. Rate limits, device binding, replay protection and
  recovery need additional design.

## Next implementation slices

1. Native QR reader/export and encrypted token file import.
2. Passkey/device enrollment so the pattern unlocks a hardware-backed signing key.
3. Agent registrations, delegation scopes, expiry, request signatures, human approval
   thresholds.
4. Merchant webhook signing, idempotency, domain verification, product-catalog hashes.
5. Live validation against the ALAT Playground with Wema-provided credentials; confirm the
   `channelId` settlement destination, ALAT approval deep-link and exact status enums, then
   flip `MONC_WEMA_MODE=playground`.
6. PostgreSQL migrations, CSRF protection, rate limits, secrets management, structured
   audit retention, and observability.