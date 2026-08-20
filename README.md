# MONC App

FastAPI monolith prototype for controlled third-party (human/AI agent) payment authorization, backed by Wema/ALAT accounts.

## Run

```powershell
cd "$env:USERPROFILE\Desktop\monc-app"
py -3.12 -m venv .venv312
.\.venv312\Scripts\Activate.ps1
pip install -r requirements.txt
$env:MONC_SECRET_KEY = "local-development-secret-change-me"
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/`.

## Payment lifecycle (authorization is not settlement)

```text
merchant creates a fixed payment intent (POS /api/v1/payment-intents)
  -> customer checkout verifies intent, pattern, token, anonymous locator, policy
  -> MONC returns ALLOWED and pins the intent to the owner's instrument (status: authorized)
  -> customer starts ALAT Authenticator consent (status: consent_pending / customer_action_required)
  -> ALAT Authenticator approves the exact Wema debit
  -> MONC funds the merchant wallet and polls Wema          (status: debited -> processing)
  -> Wema confirms the payout; MONC credits the merchant ledger once (status: successful)
  -> any failure/reversal fails closed and never credits the merchant
```

Authorize (`POST /api/payment-intents/{id}/authorize`) performs the ownership proof and policy
verdict only. Money moves exclusively through the consent lifecycle:

- `POST /api/payment-intents/{id}/consent` — starts ALAT Authenticator consent for a customer
  Wema account; returns `wema_reference`, MONC state and a sandbox-only demo code.
- `POST /api/payment-intents/{id}/approve` — sandbox-only simulation of the ALAT approval;
  in live mode approval happens inside the ALAT app and MONC only polls.
- `GET /api/payment-intents/{id}/status` — idempotently advances the state machine one Wema
  hop per call and returns the full lifecycle plus the merchant ledger.

## Wema adapter

`app/wema.py` implements the gateway boundary in two modes:

| Mode | Behavior |
| --- | --- |
| `sandbox` (default, no credentials) | deterministic in-memory account enquiry, consent codes, wallet funding and reconciliation |
| `playground` / `production` | live ALAT Playground calls over HTTP using the partner OpenAPI specs |

Live mode uses the four Wema API groups:

- **pwba-authenticator** — `POST /api/EcommerceTransfer/v2/transfer-fund-request`,
  `GET /api/EcommerceTransfer/CheckTransactionStatus/{channelId}/{ref}` → ALAT customer consent.
- **debit-wallet** — `GET /api/Shared/GetAllBanks`, `GET /api/Shared/AccountNameEnquiry/Wallet/{acct}`,
  `GET /api/Shared/GetNIPCharges`, `POST /api/Shared/ProcessClientTransfer` →
  outbound NIP payout for non-Wema merchants.
- **credit-wallet** — `POST /api/IntraBankTransfer/FundWallet`,
  `GET /api/IntraBankTransfer/ConfirmClientTransferStatus/{ref}` → intra-bank Wema payout.
- **ws-acct-mgt** — `GET .../GetAccountV2/accountNumber/{acct}`,
  `POST .../CustomerAccount/transhistoryV2` → account check + reconciliation.

All responses are normalized from the common Wema envelope
(`result/errorMessage/errorMessages/hasError`) into MONC states:
`initiated / pending / customer_action_required / processing / successful / failed / reversed / unknown`.

### Live credential setup

Obtain keys from the Wema Playground portal, then:

```env
MONC_WEMA_MODE=playground
WEMA_SUBSCRIPTION_KEY=...      # Ocp-Apim-Subscription-Key for all four API groups
WEMA_CHANNEL_ID=...            # ecommerce channel; also the `access` header value
WEMA_ACCOUNT_API_KEY=...       # x-api-key for ws-acct-mgt account maintenance
```

Implementation goes ahead with placeholders, but live calls are blocked until Wema provides these.
Two open contracts still need Wema confirmation:

1. The destination/merchant account behind the PWBA `channelId` (suspense/settlement account).
2. Production callback or deep-link flow for ALAT Authenticator approval and exact status enums.

## API example

After merchant onboarding, keep the one-time API key in a backend environment variable:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/payment-intents \
  -H 'Content-Type: application/json' \
  -H 'X-MONC-API-Key: monc_test_...' \
  -d '{"order_id":"ORDER-1","amount_minor":450000,"currency":"NGN","product_name":"Textbook","product_type":"education","product_code":"9780132350884","checkout_domain":"shop.example.ng","initiator_type":"agent"}'
```

## Tests

```powershell
.\.venv312\Scripts\python.exe -m pytest tests -q
```

Covers policy compilation/fail-closed behaviour, policy encryption, the Wema adapter
(sandbox lifecycle, state normalization, ALAT mock-transport requests) and the full
authorize → consent → approve → settle API lifecycle.

## Deliberate boundaries

- `playground`/`production` modes require `WEMA_SUBSCRIPTION_KEY`; the gateway refuses to
  invent banking endpoints when credentials are missing.
- The demo accepts card details only to demonstrate local encryption; never test with a live
  card. A production build must use a PCI tokenization provider and store only processor
  tokens client-side.
- Browser PBKDF2 is a temporary WebCrypto fallback; the protocol contract is Argon2id and
  audited Argon2id WASM must replace `patternKey()` before production.
- The backend uses encrypted-at-rest policy (AES-GCM) and encrypted server-half material.
  Production requires managed key custody, rate limits, CSRF protection, migrations, durable
  idempotency, passkeys, and regulated compliance controls.