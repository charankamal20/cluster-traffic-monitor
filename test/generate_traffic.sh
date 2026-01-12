#!/bin/bash
# Test script to generate HTTP traffic for the tracer

echo "Starting HTTP test server on port 8080..."
python3 -m http.server 8080 &
SERVER_PID=$!

# Give server time to start
sleep 2

echo "Generating HTTP requests..."
for i in {1..5}; do
    echo "Request $i..."
    curl -s http://localhost:8080/ > /dev/null
    sleep 1
done

echo "Stopping server..."
kill $SERVER_PID

echo "Test complete!"
