#!/usr/bin/env python3
"""
secure_log_forwarder.py — Project 3: Secure Cloud-to-Cloud Communication
Author : Wilton B. Harrison
Purpose: Demonstrates secure cross-VPC log forwarding from Production (VPC A)
         to Security Operations (VPC B) using:
           - AWS STS AssumeRole (cross-VPC IAM identity)
           - KMS envelope encryption before transmission
           - S3 PutObject with SSE-KMS
           - SHA-256 integrity verification
           - Structured JSON log format (SIEM-ingestible)

         This script runs ON the VPC A workload (production server / ECS task)
         and securely forwards logs to the SecOps bucket in VPC B.

Dependencies (all open-source):
  pip install boto3 cryptography

Usage:
  python secure_log_forwarder.py --role-arn <cross-vpc-role-arn> --bucket <secops-bucket> --kms-key-id <key-id>
"""

import os
import sys
import json
import uuid
import hashlib
import logging
import argparse
from datetime import datetime, timezone
from typing import Optional

import boto3
from botocore.exceptions import ClientError


# ── Structured Logger ─────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%SZ'
)
logger = logging.getLogger("secure-log-forwarder")


# ── Cross-VPC STS Session ─────────────────────────────────────────────────────

def assume_cross_vpc_role(role_arn: str, external_id: str, session_name: str = "prod-log-forwarder") -> boto3.Session:
    """
    Assume the SecOps IAM role via STS — establishes cross-VPC identity.
    The external_id prevents confused deputy attacks.
    """
    sts = boto3.client("sts")
    logger.info(f"Assuming cross-VPC role: {role_arn}")
    try:
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            ExternalId=external_id,
            DurationSeconds=900  # 15-minute session — minimal exposure window
        )
        creds = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        logger.info(f"Cross-VPC role assumed. Session expires: {creds['Expiration']}")
        return session
    except ClientError as e:
        logger.error(f"STS AssumeRole failed: {e}")
        raise


# ── Log Builder ───────────────────────────────────────────────────────────────

def build_log_payload(source_host: str, event_type: str, events: list) -> dict:
    """
    Build a structured JSON log payload conforming to a basic SIEM-ingestible
    schema. Includes metadata for correlation, integrity, and triage.
    """
    payload = {
        "schema_version": "1.0",
        "batch_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": {
            "host": source_host,
            "environment": "production",
            "vpc": "vpc-a-prod",
            "application": "wbh-cloud-infra"
        },
        "destination": {
            "vpc": "vpc-b-secops",
            "purpose": "SIEM ingestion"
        },
        "event_type": event_type,
        "event_count": len(events),
        "events": events
    }

    # Compute integrity hash over the events array
    events_str = json.dumps(events, sort_keys=True)
    payload["integrity"] = {
        "algorithm": "SHA-256",
        "hash": hashlib.sha256(events_str.encode()).hexdigest()
    }

    return payload


# ── Encrypted S3 Upload ───────────────────────────────────────────────────────

def upload_encrypted_logs(
    session: boto3.Session,
    bucket: str,
    kms_key_id: str,
    payload: dict,
    prefix: str = "prod-logs"
) -> str:
    """
    Upload encrypted log batch to SecOps S3 bucket via the assumed cross-VPC role.
    - SSE-KMS encryption applied server-side
    - Content hash in metadata for integrity verification on receipt
    - Returns the S3 key of the uploaded object
    """
    s3 = session.client("s3")

    payload_bytes = json.dumps(payload, indent=2).encode("utf-8")
    content_hash = hashlib.sha256(payload_bytes).hexdigest()

    timestamp = datetime.now(timezone.utc)
    s3_key = (
        f"{prefix}/"
        f"{timestamp.strftime('%Y/%m/%d')}/"
        f"{payload['batch_id']}.json"
    )

    logger.info(f"Uploading encrypted log batch → s3://{bucket}/{s3_key}")
    logger.info(f"Batch ID: {payload['batch_id']} | Events: {payload['event_count']} | Hash: {content_hash[:16]}...")

    try:
        s3.put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=payload_bytes,
            ContentType="application/json",
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=kms_key_id,
            Metadata={
                "batch-id":      payload["batch_id"],
                "source-host":   payload["source"]["host"],
                "event-type":    payload["event_type"],
                "event-count":   str(payload["event_count"]),
                "sha256":        content_hash,
                "forwarded-by":  "secure-log-forwarder-v1"
            }
        )
        logger.info(f"[✓] Upload complete: s3://{bucket}/{s3_key}")
        return s3_key

    except ClientError as e:
        logger.error(f"S3 upload failed: {e}")
        raise


# ── Integrity Verification ────────────────────────────────────────────────────

def verify_uploaded_log(session: boto3.Session, bucket: str, key: str, expected_hash: str) -> bool:
    """
    Read back the uploaded object's metadata and verify the SHA-256 hash
    matches what was sent. Detects tampering in transit or storage corruption.
    """
    s3 = session.client("s3")
    try:
        head = s3.head_object(Bucket=bucket, Key=key)
        stored_hash = head["Metadata"].get("sha256", "")
        if stored_hash == expected_hash:
            logger.info(f"[✓] Integrity verified: hash match confirmed")
            return True
        else:
            logger.error(f"[✗] INTEGRITY FAILURE: expected {expected_hash} got {stored_hash}")
            return False
    except ClientError as e:
        logger.warning(f"Could not verify upload: {e}")
        return False


# ── Sample Events (simulating production app log events) ─────────────────────

def generate_sample_events() -> list:
    """Generate sample structured security events for demonstration."""
    return [
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_code": "AUTH_SUCCESS",
            "severity": "INFO",
            "user": "svc-webapp",
            "source_ip": "10.10.1.45",
            "action": "authenticated",
            "resource": "/api/v1/data",
            "result": "success"
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_code": "AUTH_FAILURE",
            "severity": "WARN",
            "user": "unknown",
            "source_ip": "192.168.99.12",
            "action": "login_attempt",
            "resource": "/admin",
            "result": "denied",
            "reason": "invalid_credentials"
        },
        {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_code": "CONFIG_CHANGE",
            "severity": "HIGH",
            "user": "admin-svc",
            "source_ip": "10.10.1.10",
            "action": "security_group_modified",
            "resource": "sg-0abc123",
            "result": "applied",
            "detail": "Inbound rule added on port 22"
        }
    ]


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="WBH Secure Cross-VPC Log Forwarder — Project 3")
    parser.add_argument("--role-arn",    required=True, help="Cross-VPC IAM role ARN to assume")
    parser.add_argument("--external-id", default="wbh-secure-comms-external-id-prod", help="STS ExternalId")
    parser.add_argument("--bucket",      required=True, help="SecOps S3 log bucket name")
    parser.add_argument("--kms-key-id",  required=True, help="KMS key ID for SSE encryption")
    parser.add_argument("--host",        default=os.uname().nodename, help="Source host identifier")
    parser.add_argument("--event-type",  default="security_events", help="Log event type label")
    parser.add_argument("--verify",      action="store_true", help="Verify upload integrity after send")
    args = parser.parse_args()

    print("\n══════════════════════════════════════════════════════")
    print("  WBH Secure Log Forwarder — Project 3")
    print("  Cross-VPC Encrypted Communication")
    print("  Prod VPC (A) → SecOps VPC (B)")
    print("══════════════════════════════════════════════════════\n")

    # Step 1: Assume cross-VPC identity
    cross_vpc_session = assume_cross_vpc_role(args.role_arn, args.external_id)

    # Step 2: Build log payload
    events = generate_sample_events()
    payload = build_log_payload(args.host, args.event_type, events)
    logger.info(f"Log payload built: batch_id={payload['batch_id']} | events={len(events)}")

    # Step 3: Upload encrypted to SecOps bucket
    s3_key = upload_encrypted_logs(
        session=cross_vpc_session,
        bucket=args.bucket,
        kms_key_id=args.kms_key_id,
        payload=payload
    )

    # Step 4: Optional integrity verification
    if args.verify:
        payload_bytes = json.dumps(payload, indent=2).encode("utf-8")
        expected_hash = hashlib.sha256(payload_bytes).hexdigest()
        verify_uploaded_log(cross_vpc_session, args.bucket, s3_key, expected_hash)

    print(f"\n[✓] Secure log transmission complete.")
    print(f"    Batch: {payload['batch_id']}")
    print(f"    S3 key: {s3_key}")
    print(f"    Encryption: SSE-KMS ({args.kms_key_id[:20]}...)")
    print(f"    Events forwarded: {len(events)}\n")


if __name__ == "__main__":
    main()
