import hashlib
import os
from dataclasses import dataclass, field

import httpx


PLAYGROUND_HOST = "https://apiplayground.alat.ng"
WEMA_BANK_CODE = "035"

STATE_INITIATED = "initiated"
STATE_PENDING = "pending"
STATE_CUSTOMER_ACTION = "customer_action_required"
STATE_PROCESSING = "processing"
STATE_SUCCESSFUL = "successful"
STATE_FAILED = "failed"
STATE_REVERSED = "reversed"
STATE_UNKNOWN = "unknown"


def _to_major(amount_minor: int) -> int:
    """MONC transacts in minor units (kobo); Wema transfer APIs take Naira."""
    if amount_minor % 100:
        raise ValueError("Wema amount must be a whole Naira value in minor units")
    return amount_minor // 100


_SUCCESS_MARKERS = {"success", "successful", "succeeded", "approved", "completed", "settled", "paid", "successful.",
                    "00", "good", "ok", "0"}
_CUSTOMER_MARKERS = {"customer_action_required", "action required", "pending approval", "awaiting authorization",
                     "awaiting consent", "needs approval", "otp", "pending customer"}
_PENDING_MARKERS = {"initiated", "pending", "processing", "in progress", "submitted", "received", "queued",
                    "unconfirmed"}
_REVERSED_MARKERS = {"reversed", "reversal", "chargeback", "refunded", "returned"}
_FAILED_MARKERS = {"failed", "fail", "declined", "cancelled", "rejected", "error", "timeout", "insufficient",
                   "invalid", "not allowed", "not successful"}


def normalize_wema_state(raw: object) -> str:
    """Map a Wema status string/field into the MONC canonical state vocabulary."""
    text = str(raw or "").strip().lower()
    if not text:
        return STATE_UNKNOWN
    if text in _SUCCESS_MARKERS:
        return STATE_SUCCESSFUL
    if any(m in text for m in _CUSTOMER_MARKERS):
        return STATE_CUSTOMER_ACTION
    if any(m in text for m in _REVERSED_MARKERS):
        return STATE_REVERSED
    if any(m in text for m in _PENDING_MARKERS):
        return STATE_PROCESSING
    if any(m in text for m in _FAILED_MARKERS):
        return STATE_FAILED
    return STATE_UNKNOWN


def unwrap(payload: object) -> dict:
    """Strip the common Wema envelope {result,errorMessage,hasError,...} down to result."""
    if isinstance(payload, dict) and "hasError" in payload:
        return payload.get("result") or {}
    if isinstance(payload, dict):
        return payload
    return {}


def envelope_error(payload: object) -> str | None:
    if not isinstance(payload, dict) or not payload.get("hasError"):
        return None
    msgs = payload.get("errorMessages") or []
    return payload.get("errorMessage") or (msgs[0] if msgs else "Wema returned hasError=true")


@dataclass
class AccountResult:
    valid: bool
    account_name: str
    provider_reference: str
    city: str = ""


@dataclass
class ConsentResult:
    reference: str
    state: str
    message: str
    demo_code: str | None = None
    provider_reference: str | None = None


@dataclass
class TransferResult:
    successful: bool
    state: str
    platform_reference: str | None
    message: str


@dataclass
class ReconciliationResult:
    matched: bool
    state: str
    entries: list = field(default_factory=list)
    message: str = ""


class WemaGateway:
    """Boundary for Wema/ALATPay. Sandbox is deterministic; ALAT is live-credential driven."""

    mode = "base"

    def account_name_enquiry(self, account_number: str) -> AccountResult:
        raise NotImplementedError

    def verify_account(self, account_number: str) -> AccountResult:
        return self.account_name_enquiry(account_number)

    def get_all_banks(self) -> list:
        raise NotImplementedError

    def get_nip_charges(self) -> list:
        raise NotImplementedError

    def get_account(self, account_number: str) -> dict:
        raise NotImplementedError

    def transaction_history(self, account_number: str, frm: str = "", to: str = "", keyword: str = "") -> list:
        raise NotImplementedError

    def initiate_consent(self, source_account: str, amount_minor: int, reference: str, narration: str,
                         channel_id: str = "") -> ConsentResult:
        raise NotImplementedError

    def check_consent_status(self, reference: str) -> ConsentResult:
        raise NotImplementedError

    def approve_consent(self, reference: str, code: str = "") -> ConsentResult:
        raise NotImplementedError

    def fund_wallet(self, destination_account: str, amount_minor: int, reference: str, narration: str,
                    channel_id: str = "") -> TransferResult:
        raise NotImplementedError

    def process_transfer(self, destination_account: str, destination_bank_code: str, destination_account_name: str,
                         amount_minor: int, reference: str, narration: str, channel_id: str = "") -> TransferResult:
        raise NotImplementedError

    def confirm_transfer_status(self, reference: str, channel_id: str = "") -> TransferResult:
        raise NotImplementedError

    def reconcile(self, account_number: str, keyword: str = "") -> ReconciliationResult:
        raise NotImplementedError

    def settle(self, account_fingerprint: str, amount_minor: int, reference: str) -> str:
        raise NotImplementedError


SANDBOX_CONSENTS: dict = {}
SANDBOX_TRANSFERS: dict = {}
SANDBOX_HISTORY: list = []
SANDBOX_CITIES = ["lagos", "abuja", "port harcourt", "ibadan", "kano", "enugu"]


def _sbx_digest(*parts: str) -> str:
    return hashlib.sha256(":".join(parts).encode()).hexdigest()


class SandboxWemaGateway(WemaGateway):
    """Deterministic in-memory Wema. No network, no credentials; drives the full MONC lifecycle."""

    mode = "sandbox"

    def account_name_enquiry(self, account_number: str) -> AccountResult:
        valid = account_number.isdigit() and len(account_number) == 10
        suffix = account_number[-4:] if valid else ""
        city = ""
        if valid:
            seed = int(_sbx_digest("account", account_number)[:8], 16)
            city = SANDBOX_CITIES[seed % len(SANDBOX_CITIES)]
        return AccountResult(valid, f"MONC SANDBOX BUSINESS {suffix}" if valid else "", f"wema_sbx_{suffix}", city)

    def get_all_banks(self) -> list:
        return [
            {"bankCode": WEMA_BANK_CODE, "bankName": "Wema Bank PLC"},
            {"bankCode": "044", "bankName": "Access Bank"},
            {"bankCode": "058", "bankName": "GTBank"},
        ]

    def get_nip_charges(self) -> list:
        return [
            {"minAmount": 1.0, "maxAmount": 5000.0, "charge": 10.0},
            {"minAmount": 5000.01, "maxAmount": 50000.0, "charge": 25.0},
            {"minAmount": 50000.01, "maxAmount": 500000.0, "charge": 50.0},
        ]

    def get_account(self, account_number: str) -> dict:
        if not (account_number.isdigit() and len(account_number) == 10):
            return {"accountNo": account_number, "accountStatus": "invalid", "availableBalance": 0.0}
        seed = int(_sbx_digest("account", account_number)[:8], 16)
        return {
            "accountId": f"acct_{account_number[-4:]}",
            "accountNo": account_number,
            "accountName": self.account_name_enquiry(account_number).account_name,
            "availableBalance": float(seed % 5_000_000 + 250_000) / 100,
            "clearedBalance": 0.0,
            "accountStatus": "active",
            "currency": "NGN",
        }

    def transaction_history(self, account_number: str, frm: str = "", to: str = "", keyword: str = "") -> list:
        return [h for h in SANDBOX_HISTORY if h.get("account") == account_number and
                (not keyword or keyword.lower() in h.get("reference", "").lower() or keyword.lower() in h.get("narration", "").lower())]

    def initiate_consent(self, source_account: str, amount_minor: int, reference: str, narration: str,
                         channel_id: str = "") -> ConsentResult:
        if not self.account_name_enquiry(source_account).valid:
            return ConsentResult(reference, STATE_FAILED, "Source account failed Wema account enquiry")
        ref = "wema_sbx_cn_" + _sbx_digest(source_account, str(amount_minor), reference)[:16]
        code = _sbx_digest("code", ref)[:6]
        SANDBOX_CONSENTS[ref] = {
            "state": STATE_CUSTOMER_ACTION, "source": source_account, "amount_minor": amount_minor,
            "reference": reference, "narration": narration, "code": code,
        }
        SANDBOX_HISTORY.append({"account": source_account, "reference": ref, "narration": narration, "type": "consent",
                                "amount": _to_major(amount_minor), "state": STATE_CUSTOMER_ACTION})
        return ConsentResult(ref, STATE_CUSTOMER_ACTION, "ALAT Authenticator consent required", code, ref)

    def check_consent_status(self, reference: str) -> ConsentResult:
        entry = SANDBOX_CONSENTS.get(reference)
        if not entry:
            return ConsentResult(reference, STATE_UNKNOWN, "Unknown consent reference")
        return ConsentResult(reference, entry["state"], f"Consent {entry['state']}", entry.get("code"), reference)

    def approve_consent(self, reference: str, code: str = "") -> ConsentResult:
        entry = SANDBOX_CONSENTS.get(reference)
        if not entry:
            return ConsentResult(reference, STATE_UNKNOWN, "Unknown consent reference")
        if code and code != entry["code"]:
            entry["state"] = STATE_FAILED
            return ConsentResult(reference, STATE_FAILED, "Consent code rejected")
        if entry["state"] == STATE_SUCCESSFUL:
            return ConsentResult(reference, STATE_SUCCESSFUL, "Consent already approved", entry.get("code"), reference)
        entry["state"] = STATE_SUCCESSFUL
        SANDBOX_HISTORY.append({"account": entry["source"], "reference": reference, "narration": entry["narration"],
                                "type": "consent", "amount": _to_major(entry["amount_minor"]), "state": STATE_SUCCESSFUL})
        return ConsentResult(reference, STATE_SUCCESSFUL, "Consent approved", entry.get("code"), reference)

    def fund_wallet(self, destination_account: str, amount_minor: int, reference: str, narration: str,
                    channel_id: str = "") -> TransferResult:
        check = self.account_name_enquiry(destination_account)
        if not check.valid:
            return TransferResult(False, STATE_FAILED, None, "Destination account failed Wema account enquiry")
        existing = SANDBOX_TRANSFERS.get(reference)
        if existing:
            return TransferResult(True, existing["state"], existing["platform"], "Settlement already initiated")
        platform_ref = "wema_sbx_set_" + _sbx_digest(destination_account, str(amount_minor), reference)[:16]
        SANDBOX_TRANSFERS[reference] = {"platform": platform_ref, "state": STATE_SUCCESSFUL, "amount_minor": amount_minor}
        SANDBOX_HISTORY.append({"account": destination_account, "reference": reference, "platform_ref": platform_ref,
                                "narration": narration, "type": "fund_wallet", "amount": _to_major(amount_minor),
                                "state": STATE_SUCCESSFUL})
        return TransferResult(True, STATE_SUCCESSFUL, platform_ref, "Wallet funded")

    def process_transfer(self, destination_account: str, destination_bank_code: str, destination_account_name: str,
                         amount_minor: int, reference: str, narration: str, channel_id: str = "") -> TransferResult:
        if destination_bank_code != WEMA_BANK_CODE:
            return TransferResult(False, STATE_FAILED, None,
                                  "Sandbox adapter only supports intra-bank Wema wallet settlement; configure a Wema account")
        return self.fund_wallet(destination_account, amount_minor, reference, narration, channel_id)

    def confirm_transfer_status(self, reference: str, channel_id: str = "") -> TransferResult:
        entry = SANDBOX_TRANSFERS.get(reference)
        if not entry:
            return TransferResult(False, STATE_UNKNOWN, None, "Unknown settlement reference")
        return TransferResult(True, entry["state"], entry["platform"], f"Settlement {entry['state']}")

    def reconcile(self, account_number: str, keyword: str = "") -> ReconciliationResult:
        entries = self.transaction_history(account_number, keyword=keyword)
        matched = any(e.get("state") == STATE_SUCCESSFUL for e in entries)
        state = STATE_SUCCESSFUL if matched else STATE_UNKNOWN
        return ReconciliationResult(matched, state, entries, f"{len(entries)} ledger entries reviewed")

    def settle(self, account_fingerprint: str, amount_minor: int, reference: str) -> str:
        return "wema_sbx_set_" + _sbx_digest(account_fingerprint, str(amount_minor), reference)[:16]


class AlatWemaGateway(WemaGateway):
    """Live Wema/ALATPay adapter built from the partner OpenAPI specs in the repo notes.

    Envelope normalization keeps RAW Wema fields, maps statuses to the MONC state vocabulary,
    and keeps settlement/consent references for audit-reconciliation.
    """

    def __init__(self, mode: str = "playground", transport: httpx.BaseTransport | None = None):
        self.mode = mode
        self.subscription_key = os.getenv("WEMA_SUBSCRIPTION_KEY", "")
        self.channel_id = os.getenv("WEMA_CHANNEL_ID", "")
        self.account_api_key = os.getenv("WEMA_ACCOUNT_API_KEY", "")
        if not self.subscription_key:
            raise RuntimeError(f"{mode} mode requires WEMA_SUBSCRIPTION_KEY")
        pwba = os.getenv("WEMA_PWBA_BASE_URL", f"{PLAYGROUND_HOST}/pwba-authenticator")
        debit = os.getenv("WEMA_DEBIT_BASE_URL", f"{PLAYGROUND_HOST}/debit-wallet")
        credit = os.getenv("WEMA_CREDIT_BASE_URL", f"{PLAYGROUND_HOST}/credit-wallet")
        account = os.getenv("WEMA_ACCOUNT_BASE_URL", f"{PLAYGROUND_HOST}/ws-acct-mgt")
        headers = {"Ocp-Apim-Subscription-Key": self.subscription_key, "Accept": "application/json"}
        self._pwba = httpx.Client(base_url=pwba, headers=headers, timeout=20, transport=transport)
        self._debit = httpx.Client(base_url=debit, headers=headers, timeout=20, transport=transport)
        self._credit = httpx.Client(base_url=credit, headers=headers, timeout=20, transport=transport)
        self._account = httpx.Client(base_url=account, headers={**headers, "x-api-key": self.account_api_key},
                                     timeout=20, transport=transport)

    def _access(self, client: httpx.Client, channel_id: str = "") -> dict:
        channel = channel_id or self.channel_id
        return {"access": channel} if channel else {}

    # --- account enquiry / onboarding -------------------------------------
    def account_name_enquiry(self, account_number: str) -> AccountResult:
        try:
            r = self._debit.get(f"/api/Shared/AccountNameEnquiry/Wallet/{account_number}",
                                headers=self._access(self._debit))
            r.raise_for_status()
            payload = r.json()
        except httpx.HTTPError as exc:
            return AccountResult(False, "", f"wema_http_{type(exc).__name__}")
        error = envelope_error(payload)
        body = unwrap(payload)
        name = body.get("accountName") or body.get("name") or ""
        valid = bool(name) and not error and not payload.get("hasError")
        return AccountResult(valid, name, body.get("accountNumber") or account_number)

    def get_all_banks(self) -> list:
        r = self._debit.get("/api/Shared/GetAllBanks")
        r.raise_for_status()
        body = unwrap(r.json())
        return body if isinstance(body, list) else body.get("banks") or []

    def get_nip_charges(self) -> list:
        r = self._debit.get("/api/Shared/GetNIPCharges")
        r.raise_for_status()
        body = unwrap(r.json())
        return body.get("chargeFees") if isinstance(body, dict) else body or []

    def get_account(self, account_number: str) -> dict:
        r = self._account.get(f"/api/AccountMaintenance/CustomerAccount/GetAccountV2/accountNumber/{account_number}")
        r.raise_for_status()
        return unwrap(r.json())

    def transaction_history(self, account_number: str, frm: str = "", to: str = "", keyword: str = "") -> list:
        body = {"accountNumber": account_number, "from": frm, "to": to, "keyWord": keyword}
        r = self._account.post("/api/AccountMaintenance/CustomerAccount/transhistoryV2", json=body)
        r.raise_for_status()
        payload = r.json()
        result = unwrap(payload)
        if isinstance(result, list):
            return result
        for key in ("transactions", "data", "reports", "paymentReports", "records"):
            if isinstance(result.get(key), list):
                return result[key]
        return []

    # --- ALAT Authenticator customer consent -------------------------------
    def initiate_consent(self, source_account: str, amount_minor: int, reference: str, narration: str,
                         channel_id: str = "") -> ConsentResult:
        body = {"amount": _to_major(amount_minor), "sourceAccountNumber": source_account,
                "channelId": channel_id or self.channel_id, "narration": narration, "transactionReference": reference}
        r = self._pwba.post("/api/EcommerceTransfer/v2/transfer-fund-request", json=body)
        r.raise_for_status()
        payload = r.json()
        error = envelope_error(payload)
        if error:
            return ConsentResult(reference, STATE_FAILED, error, None, None)
        result = unwrap(payload)
        raw_state = result.get("status") or result.get("message") or ""
        return ConsentResult(
            reference=result.get("transactionReference") or reference,
            state=normalize_wema_state(raw_state),
            message=result.get("message") or error or "Consent initiated",
            provider_reference=result.get("plateformTransactionRef") or result.get("platformTransactionReference"),
        )

    def check_consent_status(self, reference: str) -> ConsentResult:
        channel = self.channel_id
        r = self._pwba.get(f"/api/EcommerceTransfer/CheckTransactionStatus/{channel}/{reference}")
        r.raise_for_status()
        payload = r.json()
        error = envelope_error(payload)
        result = unwrap(payload)
        raw_state = result.get("status") or result.get("message") or (STATE_UNKNOWN if error else "")
        return ConsentResult(
            reference=reference,
            state=STATE_FAILED if error else normalize_wema_state(raw_state),
            message=error or result.get("message") or "Consent status checked",
            provider_reference=result.get("platformTransactionReference") or result.get("plateformTransactionRef"),
        )

    def approve_consent(self, reference: str, code: str = "") -> ConsentResult:
        return ConsentResult(reference, STATE_FAILED,
                             "Approval is an ALAT Authenticator action; MONC polls status, it does not approve.")

    # --- settlement ---------------------------------------------------------
    def fund_wallet(self, destination_account: str, amount_minor: int, reference: str, narration: str,
                    channel_id: str = "") -> TransferResult:
        body = {"securityInfo": "", "destinationAccountNumber": destination_account,
                "amount": _to_major(amount_minor), "narration": narration, "transactionReference": reference,
                "useCustomNarration": True}
        r = self._credit.post("/api/IntraBankTransfer/FundWallet", json=body,
                              headers=self._access(self._credit, channel_id))
        r.raise_for_status()
        payload = r.json()
        error = envelope_error(payload)
        result = unwrap(payload)
        if error or payload.get("hasError"):
            return TransferResult(False, STATE_FAILED, None, error or "FundWallet rejected the request")
        raw_state = result.get("status") or result.get("message") or STATE_SUCCESSFUL
        state = normalize_wema_state(raw_state)
        return TransferResult(state in (STATE_SUCCESSFUL,), state,
                              result.get("platformTransactionReference") or result.get("plateformTransactionRef"),
                              result.get("message") or "Wallet funding initiated")

    def process_transfer(self, destination_account: str, destination_bank_code: str, destination_account_name: str,
                         amount_minor: int, reference: str, narration: str, channel_id: str = "") -> TransferResult:
        body = {"securityInfo": "", "amount": _to_major(amount_minor), "destinationBankCode": destination_bank_code,
                "destinationBankName": "", "destinationAccountNumber": destination_account,
                "destinationAccountName": destination_account_name, "sourceAccountNumber": "",
                "narration": narration, "transactionReference": reference, "useCustomNarration": True}
        r = self._debit.post("/api/Shared/ProcessClientTransfer", json=body,
                             headers=self._access(self._debit, channel_id))
        r.raise_for_status()
        payload = r.json()
        error = envelope_error(payload)
        result = unwrap(payload)
        if error or payload.get("hasError"):
            return TransferResult(False, STATE_FAILED, None, error or "ProcessClientTransfer rejected the request")
        raw_state = result.get("status") or result.get("message") or STATE_SUCCESSFUL
        state = normalize_wema_state(raw_state)
        return TransferResult(state in (STATE_SUCCESSFUL,), state,
                              result.get("platformTransactionReference") or result.get("plateformTransactionRef"),
                              result.get("message") or "NIP transfer initiated")

    def confirm_transfer_status(self, reference: str, channel_id: str = "") -> TransferResult:
        r = self._credit.get(f"/api/IntraBankTransfer/ConfirmClientTransferStatus/{reference}",
                             headers=self._access(self._credit, channel_id))
        r.raise_for_status()
        payload = r.json()
        error = envelope_error(payload)
        result = unwrap(payload)
        if error or payload.get("hasError"):
            return TransferResult(False, STATE_FAILED, None, error or "Status confirmation failed")
        raw_state = result.get("status") or result.get("message") or STATE_UNKNOWN
        state = normalize_wema_state(raw_state)
        return TransferResult(state in (STATE_SUCCESSFUL,), state,
                              result.get("platformTransactionReference") or result.get("plateformTransactionRef"),
                              result.get("message") or "Settlement status confirmed")

    def reconcile(self, account_number: str, keyword: str = "") -> ReconciliationResult:
        entries = self.transaction_history(account_number, keyword=keyword)
        successful = [e for e in entries if normalize_wema_state(e.get("status") or e.get("responseCode")) == STATE_SUCCESSFUL]
        matched = any(keyword.lower() in str(e.get("transactionRef") or e.get("reference") or "").lower() for e in successful)
        return ReconciliationResult(bool(successful) and matched, STATE_SUCCESSFUL if matched else STATE_UNKNOWN,
                                    entries, f"{len(successful)} successful entries matched")

    def settle(self, account_fingerprint: str, amount_minor: int, reference: str) -> str:
        result = self.fund_wallet(account_fingerprint, amount_minor, reference, f"MONC settlement {reference}")
        return result.platform_reference or ""


def get_wema_gateway() -> WemaGateway:
    mode = os.getenv("MONC_WEMA_MODE", "sandbox")
    if mode == "sandbox":
        return SandboxWemaGateway()
    return AlatWemaGateway(mode=mode)
