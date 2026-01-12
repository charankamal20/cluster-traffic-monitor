#!/bin/bash
# echo "Deploying test services..."
# kubectl apply -f test/testdeployment.yaml
# kubectl wait --for=condition=ready pod -l app=httpbin --timeout=60s

echo "----------------------------------------------------------------"
echo "1. Generating POST request with JSON body..."
kubectl run test-curl-post --image=curlimages/curl --rm -it --restart=Never -- curl -v -X POST http://httpbin.default.svc.cluster.local/post \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello from eBPF tracer", "status": "testing full capture", "data": [1, 2, 3]}'

echo "----------------------------------------------------------------"
echo "2. Generating request with custom headers..."
kubectl run test-curl-headers --image=curlimages/curl --rm -it --restart=Never -- curl -v http://httpbin.default.svc.cluster.local/headers \
  -H "X-Tracing-Test: True" \
  -H "X-Custom-ID: 98765"

echo "----------------------------------------------------------------"
echo "Done. Check the tracer logs to see these requests!"
