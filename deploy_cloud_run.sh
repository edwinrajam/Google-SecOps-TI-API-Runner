#!/usr/bin/env bash
# =============================================================================
# Google SecOps (Chronicle) & GTI API Runner — Cloud Run Deployment Script
# Author: Edwin Raja
# =============================================================================
set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${2:-us-central1}"
SERVICE_NAME="${3:-secops-gti-api-runner}"

if [ -z "$PROJECT_ID" ]; then
  echo "Usage: ./deploy_cloud_run.sh <GCP_PROJECT_ID> [REGION] [SERVICE_NAME]"
  exit 1
fi

echo "==================================================================="
echo " Deploying $SERVICE_NAME to Google Cloud Run (Hardened)"
echo " Project: $PROJECT_ID | Region: $REGION"
echo "==================================================================="

# Generate a strong Fernet AES-256 master key if SECOPS_ENCRYPTION_KEY is not already set in environment
if [ -z "${SECOPS_ENCRYPTION_KEY:-}" ]; then
  SECOPS_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
fi

gcloud run deploy "$SERVICE_NAME" \
  --source . \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --platform managed \
  --no-allow-unauthenticated \
  --set-env-vars="SECOPS_ENCRYPTION_KEY=${SECOPS_ENCRYPTION_KEY}" \
  --memory=512Mi \
  --cpu=1 \
  --max-instances=3

echo "==================================================================="
echo " Deployment Complete!"
echo " Grant yourself Cloud Run Invoker access:"
echo "   gcloud run services add-iam-policy-binding $SERVICE_NAME \\"
echo "     --project=$PROJECT_ID --region=$REGION \\"
echo "     --member='user:$(gcloud config get-value account 2>/dev/null)' \\"
echo "     --role='roles/run.invoker'"
echo "==================================================================="
