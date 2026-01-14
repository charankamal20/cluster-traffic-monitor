.PHONY: all generate build clean vmlinux

all: vmlinux generate build

# Generate vmlinux.h from running kernel
vmlinux:
	@echo "Generating vmlinux.h..."
	@mkdir -p ebpf/headers
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/headers/vmlinux.h

# Generate Go bindings from eBPF C code
generate:
	@echo "Generating eBPF Go bindings..."
	@go generate ./cmd/tracer

# Build the binary
build: generate
	@echo "Building binary..."
	@go build -o bin/http-tracer ./cmd/tracer

# Clean generated files
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f cmd/tracer/bpf_*

# Run the tracer (requires root)
run: build
	@echo "Running tracer (requires root)..."
	@sudo ./bin/http-tracer


image: 
	@docker build -t classikh/http-tracer:v4 .


push: image
	@docker push classikh/http-tracer:v4

deploy: 
	@kubectl apply -f k8s/serviceaccount.yaml
	@kubectl apply -f k8s/daemonset.yaml
	kubectl get daemonset -n kube-system http-tracer
	kubectl get pods -n kube-system -l app=http-tracer

logs: 
	kubectl logs -n kube-system -l app=http-tracer --tail=50 -f


test: 
	kubectl apply -f test/test-deployment.yaml
	kubectl wait --for=condition=ready pod -l app=httpbin --timeout=60s
	kubectl wait --for=condition=ready pod -l app=http-test-client --timeout=60s

test-ew: 
	kubectl run test-pod --image=curlimages/curl --rm -it --restart=Never -- curl http://httpbin.default.svc.cluster.local/get

test-ns:
	kubectl run test-pod --image=curlimages/curl --rm -it --restart=Never -- curl http://google.com
