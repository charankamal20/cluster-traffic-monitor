#!/bin/bash
set -e

# Configuration
TEST_ID=$(date +%s)
REQUEST_COUNT=5
NAMESPACE="kube-system" # Traefik is here
TARGET_HOST="httpbin.local"

echo "================================================================"
echo "Starting Gateway Tracer Validation (ID: $TEST_ID)"
echo "Via Ingress: $TARGET_HOST"
echo "================================================================"

# 1. Resolve Gateway Endpoint (Traefik NodePort)
# Get Node IP
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | head -n 1)
# Get Traefik NodePort (web port 80)
NODE_PORT=$(kubectl get svc -n kube-system traefik -o jsonpath='{.spec.ports[?(@.name=="web")].nodePort}')

GATEWAY_URL="http://$NODE_IP:$NODE_PORT"
echo "[1] Gateway Endpoint: $GATEWAY_URL"

# 2. Start Validator Pod (Inside cluster for reachability reliability)
# We use in-cluster validator to hit the NodePort. This simulates "external" entering via NodePort.
VALIDATOR_POD="gateway-val"
echo "[2] Ensuring Validator Pod '$VALIDATOR_POD'..."
if ! kubectl get pod "$VALIDATOR_POD" -n default > /dev/null 2>&1; then
    kubectl run "$VALIDATOR_POD" -n default --image=curlimages/curl --restart=Never -- sleep 3600
    kubectl wait --for=condition=ready pod/"$VALIDATOR_POD" -n default --timeout=60s
fi

# 3. Find Tracer on the SAME Node as Traefik
# Traffic flow: Validator -> NodePort -> Traefik Pod -> Httpbin Pod
# We want to catch the ingress at Traefik.
TRAEFIK_POD=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=traefik -o jsonpath="{.items[0].metadata.name}")
TRAEFIK_NODE=$(kubectl get pod -n kube-system "$TRAEFIK_POD" -o jsonpath='{.spec.nodeName}')

echo "    Traefik is running on node: $TRAEFIK_NODE"
TRACER_POD=$(kubectl get pods -n kube-system -l app=http-tracer --field-selector spec.nodeName="$TRAEFIK_NODE" -o jsonpath="{.items[0].metadata.name}")

if [ -z "$TRACER_POD" ]; then
    echo "Error: Could not find tracer pod on node $TRAEFIK_NODE"
    exit 1
fi
echo "    Monitoring Tracer: $TRACER_POD"


# 4. Generate Traffic
echo "[3] Generating Traffic..."
kubectl exec -n default "$VALIDATOR_POD" -- /bin/sh -c "
    for i in \$(seq 1 $REQUEST_COUNT); do
        echo \"Sending Request \$i...\"
        curl -s -H \"Host: $TARGET_HOST\" \"$GATEWAY_URL/get?validation_id=$TEST_ID&req_num=\$i\" > /dev/null || echo \"Request Failed\"
        sleep 1
    done
"

# 5. Wait for logs
echo "[4] Waiting 5s for logs to flush..."
sleep 5

# 6. Verify Logs
echo "[5] Verifying Logs..."
LOG_CONTENT=$(kubectl exec -n kube-system "$TRACER_POD" -- cat /var/log/http-tracer/traces.log 2>/dev/null || true)

# Count matches
# We look for the Host header to be reliable
MATCHES=$(echo "$LOG_CONTENT" | grep "validation_id=$TEST_ID" | grep "\"type\":\"REQUEST\"" | wc -l)

echo "----------------------------------------------------------------"
echo "Results:"
echo "  Sent:     $REQUEST_COUNT"
echo "  Captured: $MATCHES"
echo "----------------------------------------------------------------"

if [ "$MATCHES" -ge "$REQUEST_COUNT" ]; then
    echo "✅ PASS: Gateway traffic captured successfully!"
    echo "Sample Trace:"
    echo "$LOG_CONTENT" | grep "validation_id=$TEST_ID" | head -n 1
else
    echo "❌ FAIL: Expected at least $REQUEST_COUNT traces, but found $MATCHES."
    echo "Debug Info (Last 20 lines):"
    echo "$LOG_CONTENT" | tail -n 20
    exit 1
fi
