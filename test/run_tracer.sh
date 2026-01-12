#!/bin/bash
# Simple test script to run the tracer and generate HTTP traffic

echo "========================================="
echo "HTTP Tracer Test Script"
echo "========================================="
echo ""
echo "This script will:"
echo "1. Start the tracer (requires sudo)"
echo "2. Generate HTTP traffic with curl"
echo "3. Display captured events"
echo ""
echo "Press Ctrl+C to stop the tracer"
echo ""
echo "Starting tracer in 3 seconds..."
sleep 3

# Run the tracer
# Note: This needs to be run with sudo
/home/classikh/code/work/testing/go/tracer/bin/tracer-tp
