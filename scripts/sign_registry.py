#!/usr/bin/env python3
"""
Sign the approved-models registry. Exactly one mode:

  --kms        Model Risk approver only. Signs data/approved_models.json with
               the registry key pinned in data/signing_key_pins.json (run
               scripts/pin_signing_keys.py first; no alias is resolved; needs
               kms:Sign, i.e. the fsi-model-risk-approver role) and writes ONLY
               data/approved_models.json.kms.sig. Never touches the committed
               local-dev data/approved_models.json.sig.
  --local-dev  Writes ONLY data/approved_models.json.sig with the public
               local-dev key (tests, console, `make gate`, demos). Refused in
               a deployed runtime. Deploy verification always refuses it.

The envelope (v3) signs signed_at, the registry's registry_version
("2026-Q3" or "2026-Q3.1") and signed_by (the STS caller ARN for --kms); a
malformed registry_version is refused.

Usage:
    AWS_PROFILE=<model-risk-approver profile> python scripts/sign_registry.py --kms
    python scripts/sign_registry.py --local-dev
"""
import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from governance_common import signing  # noqa: E402
from model_assurance import DEFAULT_REGISTRY_PATH, parse_registry_version  # noqa: E402

REGION = os.environ.get("AWS_REGION", "us-east-1")
LOCAL_DEV_SIGNED_BY = "local-dev"


def _session():
    """The approver's own AWS session (AWS_PROFILE); a test seam."""
    import boto3  # deferred: --local-dev needs no AWS SDK
    return boto3.Session()


def _write_atomic(path: str, envelope: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(envelope, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Sign the approved-models registry")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--kms", action="store_true",
                      help="KMS-sign (Model Risk approver); writes only <registry>.kms.sig")
    mode.add_argument("--local-dev", action="store_true",
                      help="Local-dev sign; writes only <registry>.sig")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY_PATH,
                        help="Registry path (default: data/approved_models.json)")
    args = parser.parse_args(argv)

    with open(args.registry, "rb") as f:
        payload = f.read()
    try:
        version = json.loads(payload.decode("utf-8")).get("registry_version")
        parse_registry_version(version)
    except (ValueError, AttributeError) as exc:
        print(f"✗ refusing to sign: {exc}")
        return 1

    if args.local_dev:
        if signing.in_deployed_runtime():
            print("✗ --local-dev signing is refused in a deployed runtime")
            return 1
        envelope = signing.sign(signing.PURPOSE_REGISTRY, payload, local_dev=True,
                                signed_by=LOCAL_DEV_SIGNED_BY, version=version)
        out = args.registry + ".sig"
        _write_atomic(out, envelope)
        print(f"✓ wrote {os.path.relpath(out, PROJECT_ROOT)} (LOCAL_DEV_HMAC_SHA256; never accepted for deploy)")
        return 0

    try:
        pins = signing.load_key_pins()
    except signing.SignatureInvalidError as exc:
        print(f"✗ {exc}; run scripts/pin_signing_keys.py and commit data/signing_key_pins.json")
        return 1
    if not pins.key_arn(signing.PURPOSE_REGISTRY) or pins.region != REGION:
        print(f"✗ data/signing_key_pins.json pins no registry key for {REGION}; "
              "run scripts/pin_signing_keys.py")
        return 1
    session = _session()
    kms = session.client("kms", region_name=REGION)
    signer_arn = session.client("sts", region_name=REGION).get_caller_identity()["Arn"]
    envelope = signing.sign(signing.PURPOSE_REGISTRY, payload, kms_client=kms, signed_by=signer_arn,
                            version=version, pins=pins)
    out = args.registry + ".kms.sig"
    _write_atomic(out, envelope)
    print(f"✓ wrote {os.path.relpath(out, PROJECT_ROOT)} (KMS_ECDSA_SHA_256, signed by {signer_arn})")
    print("  commit data/approved_models.json.kms.sig, then run make deploy from a clean tree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
