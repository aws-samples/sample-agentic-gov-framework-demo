"""
Shared signing fakes: pinned key ARNs, a pins file
writer and a mocked KMS client whose describe_key always fails the test (no
signer or verifier may resolve an alias).
"""
import json
from unittest.mock import MagicMock

from governance_common import signing

ACCOUNT = "123456789012"
REGION = "us-east-1"
REGISTRY_KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/11111111-2222-3333-4444-555555555555"
GATE_KEY_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/66666666-7777-8888-9999-000000000000"
ATTACKER_KEY_ARN = "arn:aws:kms:us-east-1:999999999999:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KEY_ARNS = {signing.PURPOSE_REGISTRY: REGISTRY_KEY_ARN, signing.PURPOSE_GATE: GATE_KEY_ARN}


def pins_document(keys=None, ages=None, account=ACCOUNT, region=REGION):
    return {"format": signing.PINS_FORMAT, "account": account, "region": region,
            "keys": dict(KEY_ARNS if keys is None else keys),
            "max_signature_age_seconds": dict(ages or {})}


def pins(**kwargs):
    return signing.parse_key_pins(pins_document(**kwargs))


def write_pins(path, **kwargs):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(pins_document(**kwargs), f)
    return str(path)


def _no_alias_lookup(**kwargs):
    raise AssertionError("describe_key must never be called (aliases are not resolved)")


def kms_client(valid=True):
    client = MagicMock()
    client.describe_key.side_effect = _no_alias_lookup
    client.sign.return_value = {"Signature": b"\x30\x45fake-der-signature"}
    client.verify.return_value = {"SignatureValid": valid}
    return client


def kms_envelope(purpose, payload, *, version, client=None, signed_by="arn:aws:sts::123456789012:assumed-role/x/y",
                 now=None, pinned=None):
    return signing.sign(purpose, payload, kms_client=client or kms_client(), signed_by=signed_by,
                        version=version, pins=pinned or pins(), now=now)
