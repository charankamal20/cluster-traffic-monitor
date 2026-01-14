#!/bin/bash
set -e

# Configuration
TEST_ID=$(date +%s)
REQUEST_COUNT=5
TARGET_SVC="httpbin"
NAMESPACE="default"
VALIDATOR_POD="manual-val"  # Use the stable pod name

# 1. Ensure Validator Pod Exists
echo "[1] Ensuring Validator Pod '$VALIDATOR_POD'..."
if ! kubectl get pod "$VALIDATOR_POD" -n "$NAMESPACE" > /dev/null 2>&1; then
    echo "    Creating validator pod..."
    kubectl run "$VALIDATOR_POD" --image=curlimages/curl --restart=Never -- sleep 3600
    kubectl wait --for=condition=ready pod/"$VALIDATOR_POD" -n "$NAMESPACE" --timeout=60s
else
    echo "    Validator pod already exists."
fi

# Resolve Target Pod IP
TARGET_POD_IP=$(kubectl get pod -n "$NAMESPACE" -l app="$TARGET_SVC" -o jsonpath='{.items[0].status.podIP}')
TARGET_URL="http://$TARGET_POD_IP/get"

echo "================================================================"
echo "Starting Tracer Validation (ID: $TEST_ID)"
echo "Target: $TARGET_URL (Resolved from Service $TARGET_SVC)"
echo "Requests: $REQUEST_COUNT"
echo "================================================================"

# 2. Get Node Name of Validator (to check the right tracer logs)
NODE_NAME=$(kubectl get pod "$VALIDATOR_POD" -n "$NAMESPACE" -o jsonpath='{.spec.nodeName}')
echo "    Validator is running on node: $NODE_NAME"

# 3. Find Tracer on the SAME Node
echo "[2] Finding Tracer Pod on node $NODE_NAME..."
TRACER_POD=$(kubectl get pods -n kube-system -l app=http-tracer --field-selector spec.nodeName="$NODE_NAME" -o jsonpath="{.items[0].metadata.name}")

if [ -z "$TRACER_POD" ]; then
    echo "Error: Could not find tracer pod on node $NODE_NAME."
    exit 1
fi
echo "    Found Tracer: $TRACER_POD"

# 4. Generate Traffic
echo "[3] Generating Traffic..."
kubectl exec "$VALIDATOR_POD" -n "$NAMESPACE" -- /bin/sh -c "
    for i in \$(seq 1 $REQUEST_COUNT); do
        echo \"Sending Request \$i...\"
        curl -s \"$TARGET_URL?validation_id=$TEST_ID&req_num=\$i\" > /dev/null
        sleep 1
    done
"

# 5. Wait for logs
echo "[4] Waiting 10s for logs to flush..."
sleep 10

# 6. Verify Logs
echo "[5] Verifying Logs from $TRACER_POD..."
LOG_CONTENT=$(kubectl exec -n kube-system "$TRACER_POD" -- cat /var/log/http-tracer/traces.log)

# Count matches
MATCHES=$(echo "$LOG_CONTENT" | grep "validation_id=$TEST_ID" | grep "\"type\":\"REQUEST\"" | wc -l)

echo "----------------------------------------------------------------"
echo "Results:"
echo "  Sent:     $REQUEST_COUNT"
echo "  Captured: $MATCHES"
echo "----------------------------------------------------------------"

if [ "$MATCHES" -ge "$REQUEST_COUNT" ]; then
    echo "✅ PASS: All requests captured successfully!"
    echo "Sample Log Entry:"
    echo "$LOG_CONTENT" | grep "validation_id=$TEST_ID" | grep "\"type\":\"REQUEST\"" | head -n 1
else
    echo "❌ FAIL: Expected $REQUEST_COUNT requests, but found $MATCHES."
    echo "Debug Info (Last 20 lines of log):"
    echo "$LOG_CONTENT" | tail -n 20
    exit 1
fi
