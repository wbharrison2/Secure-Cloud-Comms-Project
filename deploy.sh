#!/usr/bin/env bash
set -euo pipefail

# Artisan Gem Works — Project 6 Zero Trust deploy script
# Prerequisites: aws CLI, kubectl, istioctl, helm, git
# Run from the repository root after configuring AWS credentials.

NAMESPACE="artisan-gem-works"
CLUSTER_NAME="artisan-gem-works"
AWS_REGION="us-west-2"

echo "=== Artisan Gem Works — Project 6 Zero Trust Deploy ==="
echo ""

echo "[1/8] Configuring kubectl..."
aws eks update-kubeconfig --region "$AWS_REGION" --name "$CLUSTER_NAME"

echo "[2/8] Installing Istio (production profile)..."
if ! command -v istioctl &>/dev/null; then
  echo "  ERROR: istioctl not found. Install from https://istio.io/latest/docs/setup/getting-started/"
  exit 1
fi
istioctl install --set profile=production -y

echo "[3/8] Installing External Secrets Operator..."
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm upgrade --install external-secrets external-secrets/external-secrets \
  --namespace external-secrets --create-namespace \
  --set installCRDs=true --wait

echo "[4/8] Installing Falco..."
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  --values falco/falco-values.yaml --wait

echo "[5/8] Applying Kubernetes manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/service-account.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f external-secrets/secret-store.yaml
kubectl apply -f external-secrets/external-secret.yaml

echo "  Waiting for ExternalSecret to sync from AWS Secrets Manager..."
kubectl wait --for=condition=Ready externalsecret/agw-secrets \
  -n "$NAMESPACE" --timeout=120s

kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/hpa.yaml
kubectl apply -f k8s/pdb.yaml
kubectl apply -f k8s/network-policy.yaml

echo "[6/8] Applying Istio resources..."
kubectl apply -f istio/peer-authentication.yaml
kubectl apply -f istio/authorization-policy.yaml
kubectl apply -f istio/gateway.yaml
kubectl apply -f istio/virtual-service.yaml

echo "[7/8] Installing ArgoCD..."
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
kubectl wait --for=condition=Available deployment/argocd-server \
  -n argocd --timeout=300s
kubectl apply -f argocd/application.yaml

echo "[8/8] Verifying deployment..."
kubectl rollout status deployment/agw-app -n "$NAMESPACE" --timeout=300s

echo ""
echo "=== Deploy complete ==="
echo ""
kubectl get pods -n "$NAMESPACE"
echo ""
kubectl get peerauthentication,authorizationpolicy,gateway,virtualservice -n "$NAMESPACE"
echo ""
kubectl get externalsecret -n "$NAMESPACE"
echo ""

INGRESS=$(kubectl get svc istio-ingressgateway -n istio-system \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "pending")
echo "Ingress Gateway: $INGRESS"
echo ""
echo "ArgoCD dashboard: kubectl port-forward svc/argocd-server -n argocd 8080:443"
ARGO_PASS=$(kubectl get secret argocd-initial-admin-secret -n argocd \
  -o jsonpath="{.data.password}" 2>/dev/null | base64 -d || echo "(already changed)")
echo "ArgoCD admin password: $ARGO_PASS"
