"""Signature ordering for explicitly declared Shopee authentication scopes."""
import hashlib
import hmac
import re

from .credentials import CredentialError, CredentialSnapshot


def sign(key: str, base: str) -> str:
    return hmac.new(key.encode(), base.encode(), hashlib.sha256).hexdigest()


def signed_parameters(snapshot: CredentialSnapshot, path: str, timestamp: int, scope: str) -> dict:
    if not re.fullmatch(r"/api/v2/[A-Za-z0-9_/-]+", path) or ".." in path:
        raise CredentialError("Invalid API path")
    if scope not in ("public", "shop", "merchant", "principal", "user"):
        raise CredentialError("Unsupported authentication scope")
    base = f"{snapshot.partner_id}{path}{timestamp}"
    values = {"partner_id": snapshot.partner_id, "timestamp": timestamp}
    if scope != "public":
        if snapshot.scope != scope or snapshot.subject_id is None or not snapshot.access_token:
            raise CredentialError("Credential scope mismatch")
        base += f"{snapshot.access_token}{snapshot.subject_id}"
        values.update(access_token=snapshot.access_token, **{scope + "_id": snapshot.subject_id})
    values["sign"] = sign(snapshot.partner_key, base)
    return values
