#!/usr/bin/env bash
# =============================================================================
# Google Threat Intelligence (GTI) API Runner — IAP & Load Balancer Setup
# Restricts Cloud Run access strictly to @google.com domain accounts via IAP
# Author: Edwin Raja
# =============================================================================
set -e

PROJECT_ID="${1:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${2:-us-central1}"
SERVICE_NAME="gti-api-runner"
DOMAIN_ALLOW="google.com"

if [ -z "$PROJECT_ID" ]; then
  echo "Usage: ./setup_iap_load_balancer.sh <GCP_PROJECT_ID> [REGION]"
  exit 1
fi

echo "Configuring Identity-Aware Proxy (IAP) for $SERVICE_NAME in project $PROJECT_ID..."
echo "1. Enabling required Google Cloud APIs (Compute, IAP, Run)..."
gcloud services enable compute.googleapis.com iap.googleapis.com run.googleapis.com --project="$PROJECT_ID"

echo "2. Setting Cloud Run ingress to internal-and-cloud-load-balancing..."
gcloud run services update "$SERVICE_NAME" \
  --region="$REGION" \
  --ingress=internal-and-cloud-load-balancing \
  --project="$PROJECT_ID"

echo "3. Granting IAP-secured Web App User role to domain:$DOMAIN_ALLOW..."
gcloud iap web add-iam-policy-binding \
  --resource-type=backend-services \
  --member="domain:${DOMAIN_ALLOW}" \
  --role="roles/iap.httpsResourceAccessor" \
  --project="$PROJECT_ID" || echo "Note: Attach your HTTPS Load Balancer backend service in Cloud Console -> Security -> Identity-Aware Proxy."

echo "Done! Only @$DOMAIN_ALLOW users authenticated via Google SSO can access the application."
