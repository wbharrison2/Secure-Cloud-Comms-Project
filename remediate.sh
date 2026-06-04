#!/usr/bin/env bash
# remediate.sh — Enterprise Project 6: Zero-Trust Security Operations Platform
# Incident investigation, manual response, and platform verification tool.
# Usage: ./remediate.sh [--verify] [--list-findings] [--quarantine INSTANCE_ID]
#                       [--rotate-key] [--region REGION]
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[$(date '+%H:%M:%S')] INFO  $*${NC}"; }
success() { echo -e "${GREEN}[$(date '+%H:%M:%S')] OK    $*${NC}"; }
warn()    { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN  $*${NC}"; }
error()   { echo -e "${RED}[$(date '+%H:%M:%S')] ERROR $*${NC}" >&2; exit 1; }

AWS_REGION="us-east-1"
ACTION="verify"
INSTANCE_ID=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --verify)           ACTION="verify"; shift ;;
    --list-findings)    ACTION="list"; shift ;;
    --quarantine)       ACTION="quarantine"; INSTANCE_ID="$2"; shift 2 ;;
    --rotate-key)       ACTION="rotate"; shift ;;
    --region)           AWS_REGION="$2"; shift 2 ;;
    *) error "Unknown argument: $1" ;;
  esac
done

info "Pre-flight: checking AWS credentials and tools"
for cmd in aws jq terraform; do
  command -v "$cmd" &>/dev/null || error "Required tool not found: $cmd"
done
aws sts get-caller-identity --region "$AWS_REGION" &>/dev/null || error "AWS credentials invalid"
success "Credentials valid"

verify_platform() {
  info "Verifying Zero-Trust SecOps platform health"

  info "GuardDuty status"
  DETECTOR_ID=$(terraform output -raw guardduty_detector_id 2>/dev/null \
    || aws guardduty list-detectors --region "$AWS_REGION" --query 'DetectorIds[0]' --output text)
  [[ "$DETECTOR_ID" == "None" || -z "$DETECTOR_ID" ]] && warn "GuardDuty not enabled!" \
    || success "GuardDuty detector: $DETECTOR_ID"

  info "Security Hub status"
  SH_STATUS=$(aws securityhub describe-hub --region "$AWS_REGION" --query 'HubArn' --output text 2>/dev/null || echo "")
  [[ -z "$SH_STATUS" ]] && warn "Security Hub not enabled!" \
    || success "Security Hub active: $SH_STATUS"

  info "CloudTrail status"
  TRAIL_STATUS=$(aws cloudtrail get-trail-status \
    --name "${TF_VAR_project_name:-wbh-zerotrust-secops}-trail" \
    --region "$AWS_REGION" \
    --query 'IsLogging' --output text 2>/dev/null || echo "unknown")
  [[ "$TRAIL_STATUS" == "True" ]] && success "CloudTrail logging: ACTIVE" \
    || warn "CloudTrail status: $TRAIL_STATUS"

  info "AWS Config recorder status"
  CONFIG_STATUS=$(aws configservice describe-configuration-recorder-status \
    --region "$AWS_REGION" \
    --query 'ConfigurationRecordersStatus[0].recording' --output text 2>/dev/null || echo "false")
  [[ "$CONFIG_STATUS" == "true" ]] && success "Config recorder: RECORDING" \
    || warn "Config recorder: $CONFIG_STATUS"

  info "Transit Gateway status"
  TGW_COUNT=$(aws ec2 describe-transit-gateways \
    --filters "Name=tag:Project,Values=Enterprise-ZeroTrust-SecOps" \
    --region "$AWS_REGION" \
    --query 'length(TransitGateways)' --output text 2>/dev/null || echo "0")
  [[ "$TGW_COUNT" -gt 0 ]] && success "Transit Gateway: $TGW_COUNT found" \
    || warn "Transit Gateway not found — Terraform may not be applied yet"

  info "OpenSearch SIEM status"
  OS_STATUS=$(aws opensearch describe-domain \
    --domain-name "wbh-zerotrust-secops-siem" \
    --region "$AWS_REGION" \
    --query 'DomainStatus.Processing' --output text 2>/dev/null || echo "NotFound")
  [[ "$OS_STATUS" == "false" ]] && success "OpenSearch SIEM: ACTIVE" \
    || info "OpenSearch status: $OS_STATUS"

  info "Kinesis Firehose log pipeline"
  FIREHOSE_STATUS=$(aws firehose describe-delivery-stream \
    --delivery-stream-name "${TF_VAR_project_name:-wbh-zerotrust-secops}-logs-to-opensearch" \
    --region "$AWS_REGION" \
    --query 'DeliveryStreamDescription.DeliveryStreamStatus' --output text 2>/dev/null || echo "NotFound")
  [[ "$FIREHOSE_STATUS" == "ACTIVE" ]] && success "Firehose pipeline: ACTIVE" \
    || info "Firehose status: $FIREHOSE_STATUS"

  echo ""
  success "Platform verification complete"
}

list_findings() {
  info "Listing HIGH/CRITICAL security findings"

  DETECTOR_ID=$(terraform output -raw guardduty_detector_id 2>/dev/null \
    || aws guardduty list-detectors --region "$AWS_REGION" --query 'DetectorIds[0]' --output text)

  if [[ "$DETECTOR_ID" != "None" && -n "$DETECTOR_ID" ]]; then
    info "GuardDuty HIGH findings (severity >= 7.0)"
    FINDING_IDS=$(aws guardduty list-findings \
      --detector-id "$DETECTOR_ID" \
      --finding-criteria '{"Criterion":{"severity":{"Gte":7},"service.archived":{"Eq":["false"]}}}' \
      --region "$AWS_REGION" \
      --query 'FindingIds' --output json 2>/dev/null || echo "[]")

    FINDING_COUNT=$(echo "$FINDING_IDS" | jq 'length')
    if [[ "$FINDING_COUNT" -eq 0 ]]; then
      success "No active HIGH/CRITICAL GuardDuty findings"
    else
      warn "$FINDING_COUNT HIGH/CRITICAL findings found"
      aws guardduty get-findings \
        --detector-id "$DETECTOR_ID" \
        --finding-ids $(echo "$FINDING_IDS" | jq -r '.[]' | tr '\n' ' ') \
        --region "$AWS_REGION" \
        --query 'Findings[].{Type:Type,Severity:Severity,Instance:Resource.InstanceDetails.InstanceId,Time:UpdatedAt}' \
        --output table 2>/dev/null || echo "Could not retrieve finding details"
    fi
  fi

  info "Security Hub CRITICAL/HIGH findings (active)"
  aws securityhub get-findings \
    --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},{"Value":"HIGH","Comparison":"EQUALS"}]}' \
    --query 'Findings[0:10].{Title:Title,Severity:Severity.Label,ProductName:ProductName,UpdatedAt:UpdatedAt}' \
    --output table \
    --region "$AWS_REGION" 2>/dev/null || warn "Security Hub not enabled or no findings"
}

quarantine_instance() {
  [[ -z "$INSTANCE_ID" ]] && error "Instance ID required: --quarantine i-xxxxx"
  warn "Manual quarantine: $INSTANCE_ID"

  INSTANCE_STATE=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$AWS_REGION" \
    --query 'Reservations[0].Instances[0].State.Name' \
    --output text 2>/dev/null || echo "not-found")

  [[ "$INSTANCE_STATE" == "not-found" ]] && error "Instance $INSTANCE_ID not found"
  info "Current state: $INSTANCE_STATE"

  read -rp "$(echo -e "${RED}QUARANTINE instance $INSTANCE_ID? This will STOP it. [y/N]: ${NC}")" CONFIRM
  [[ "$CONFIRM" =~ ^[Yy]$ ]] || { info "Aborted"; exit 0; }

  aws ec2 stop-instances --instance-ids "$INSTANCE_ID" --region "$AWS_REGION"
  aws ec2 create-tags --resources "$INSTANCE_ID" --region "$AWS_REGION" --tags \
    Key=SecurityStatus,Value=QUARANTINED \
    Key=QuarantineTime,Value="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    Key=QuarantineMethod,Value=ManualRemediation

  success "Instance $INSTANCE_ID quarantined and tagged"
  warn "Next steps: review CloudTrail, analyze VPC Flow Logs in OpenSearch, check GuardDuty findings"
}

rotate_key() {
  info "Checking KMS key rotation status"
  KMS_KEY_ID=$(terraform output -raw kms_key_id 2>/dev/null || error "Run: terraform output kms_key_id")

  ROTATION_STATUS=$(aws kms get-key-rotation-status \
    --key-id "$KMS_KEY_ID" \
    --region "$AWS_REGION" \
    --query 'KeyRotationEnabled' --output text)

  [[ "$ROTATION_STATUS" == "true" ]] \
    && success "KMS auto-rotation already enabled for $KMS_KEY_ID" \
    || {
      warn "Auto-rotation not enabled. Enabling now..."
      aws kms enable-key-rotation --key-id "$KMS_KEY_ID" --region "$AWS_REGION"
      success "Auto-rotation enabled for CMK $KMS_KEY_ID"
    }
}

case "$ACTION" in
  verify)      verify_platform ;;
  list)        list_findings ;;
  quarantine)  quarantine_instance ;;
  rotate)      rotate_key ;;
  *) error "Unknown action: $ACTION" ;;
esac
