#!/bin/bash

# test_traffic.sh - Generate diverse traffic to test the HTTP tracer

TARGET_URL="http://httpbin.default.svc.cluster.local"
NAMESPACE="default"
CLIENT_POD="http-test-client"

echo "🚀 Starting Traffic Generation Test..."
echo "Target: $TARGET_URL"

# Helper to run curl in the test pod
run_curl() {
    local cmd="$1"
    echo "---------------------------------------------------"
    echo "Executing: $cmd"
    kubectl exec -n $NAMESPACE $CLIENT_POD -- $cmd
    echo ""
}

# 1. Basic HTTP Methods
echo "📦 Testing Basic HTTP Methods..."
run_curl "curl -s -X GET $TARGET_URL/get"
run_curl "curl -s -X POST $TARGET_URL/post -d 'hello=world'"
run_curl "curl -s -X PUT $TARGET_URL/put -d 'update=true'"
run_curl "curl -s -X DELETE $TARGET_URL/delete"
# PATCH/HEAD for full protocol coverage
run_curl "curl -s -X PATCH $TARGET_URL/patch -d 'patch=work'"
run_curl "curl -s -I $TARGET_URL/headers"

# 2. Large Body (Testing Stream Reassembly)
echo "🐘 Testing Large Payload (Stream Reassembly)..."
# Create a 20KB payload
run_curl "curl -s -X POST $TARGET_URL/post -H 'Content-Type: text/plain' --data-binary @/etc/services"

# 3. Compression (Testing Decompression)
echo "🗜️ Testing Compression (Gzip)..."
run_curl "curl -s -H 'Accept-Encoding: gzip' $TARGET_URL/gzip -o /dev/null -v"

echo "🗜️ Testing Compression (Brotli)..."
run_curl "curl -s -H 'Accept-Encoding: br' $TARGET_URL/brotli -o /dev/null -v"

# 4. Sensitive Data (Testing Redaction)
echo "🔒 Testing Sensitive Data Redaction..."
run_curl "curl -s -X POST $TARGET_URL/post -H 'Authorization: Bearer my-secret-token' -H 'X-API-Key: 12345-secret' -d '{\"password\":\"supersecret\"}'"

# 5. Health Check (Testing Filtering)
echo "🏥 Testing Health Check Filtering (Should NOT appear in logs)..."
run_curl "curl -s $TARGET_URL/health"
run_curl "curl -s $TARGET_URL/readyz"

echo "✅ Test Complete! Check tracer logs for verification."
