package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// PodInfo holds basic pod metadata
type PodInfo struct {
	Name      string
	Namespace string
	IP        string
	NodeName  string
}

// Watcher monitors K8s pods and maintains an IP -> PodInfo map
type Watcher struct {
	client       *kubernetes.Clientset
	podMap       map[string]*PodInfo // Pod IP -> PodInfo
	serviceMap   map[string][]string // Pod IP -> []ServiceNames (from Endpoints)
	serviceIPMap map[string]string   // Service ClusterIP -> "namespace/servicename"
	mu           sync.RWMutex
	stopCh       chan struct{}
}

// NewWatcher creates a new K8s watcher
func NewWatcher() (*Watcher, error) {
	// In-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig (for local testing mostly, but here we assume inside cluster)
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return &Watcher{
		client:       clientset,
		podMap:       make(map[string]*PodInfo),
		serviceMap:   make(map[string][]string),
		serviceIPMap: make(map[string]string),
		stopCh:       make(chan struct{}),
	}, nil
}

// Start begins watching pods, services, and endpoints
func (w *Watcher) Start(ctx context.Context) error {
	slog.Info("Starting K8s Watcher (Pods, Services & Endpoints)...")

	// 1. Pods
	if err := w.startPodWatcher(ctx); err != nil {
		return err
	}

	// 2. Services (for ClusterIP resolution)
	go w.startServiceWatcher(ctx)

	// 3. Endpoints
	go w.startEndpointWatcher(ctx)

	return nil
}

func (w *Watcher) startPodWatcher(ctx context.Context) error {
	// Initial list
	pods, err := w.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list pods: %w", err)
	}

	w.mu.Lock()
	for _, pod := range pods.Items {
		w.updatePod(&pod)
	}
	w.mu.Unlock()

	slog.Info("Initial pod cache built", "count", len(pods.Items))

	// Watch loop
	go func() {
		resourceVersion := pods.ResourceVersion
		for {
			select {
			case <-ctx.Done():
				return
			default:
				watchOpts := metav1.ListOptions{
					Watch:           true,
					ResourceVersion: resourceVersion,
				}
				watcher, err := w.client.CoreV1().Pods("").Watch(ctx, watchOpts)
				if err != nil {
					slog.Warn("Error watching pods, retrying...", "error", err)
					time.Sleep(5 * time.Second)
					continue
				}

				for event := range watcher.ResultChan() {
					pod, ok := event.Object.(*corev1.Pod)
					if !ok {
						continue
					}

					// Update ResourceVersion from event
					resourceVersion = pod.ResourceVersion

					w.mu.Lock()
					switch event.Type {
					case "ADDED", "MODIFIED":
						w.updatePod(pod)
					case "DELETED":
						w.deletePod(pod)
					}
					w.mu.Unlock()
				}
			}
		}
	}()
	return nil
}

func (w *Watcher) startEndpointWatcher(ctx context.Context) {
	// Initial List
	eps, err := w.client.CoreV1().Endpoints("").List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Warn("Error listing endpoints", "error", err)
	} else {
		w.mu.Lock()
		for _, ep := range eps.Items {
			w.updateEndpoint(&ep)
		}
		w.mu.Unlock()
		slog.Info("Initial endpoint cache built", "count", len(eps.Items))
	}

	resourceVersion := ""
	if eps != nil {
		resourceVersion = eps.ResourceVersion
	}

	// Loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
			watchOpts := metav1.ListOptions{
				Watch:           true,
				ResourceVersion: resourceVersion,
			}
			watcher, err := w.client.CoreV1().Endpoints("").Watch(ctx, watchOpts)
			if err != nil {
				slog.Warn("Error watching endpoints, retrying...", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for event := range watcher.ResultChan() {
				ep, ok := event.Object.(*corev1.Endpoints)
				if !ok {
					continue
				}

				w.mu.Lock()
				switch event.Type {
				case "ADDED", "MODIFIED":
					w.updateEndpoint(ep)
				case "DELETED":
					w.deleteEndpoint(ep)
				}
				w.mu.Unlock()
			}
		}
	}
}

// startServiceWatcher watches Service resources to track ClusterIPs
func (w *Watcher) startServiceWatcher(ctx context.Context) {
	// Initial List
	svcs, err := w.client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Warn("Error listing services", "error", err)
	} else {
		w.mu.Lock()
		for _, svc := range svcs.Items {
			w.updateService(&svc)
		}
		w.mu.Unlock()
		slog.Info("Initial service cache built", "count", len(svcs.Items))
	}

	resourceVersion := ""
	if svcs != nil {
		resourceVersion = svcs.ResourceVersion
	}

	// Watch loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
			watchOpts := metav1.ListOptions{
				Watch:           true,
				ResourceVersion: resourceVersion,
			}
			watcher, err := w.client.CoreV1().Services("").Watch(ctx, watchOpts)
			if err != nil {
				slog.Warn("Error watching services, retrying...", "error", err)
				time.Sleep(5 * time.Second)
				continue
			}

			for event := range watcher.ResultChan() {
				svc, ok := event.Object.(*corev1.Service)
				if !ok {
					continue
				}

				// Update ResourceVersion
				resourceVersion = svc.ResourceVersion

				w.mu.Lock()
				switch event.Type {
				case "ADDED", "MODIFIED":
					w.updateService(svc)
				case "DELETED":
					w.deleteService(svc)
				}
				w.mu.Unlock()
			}
		}
	}
}

func (w *Watcher) updatePod(pod *corev1.Pod) {
	if pod.Status.PodIP != "" {
		w.podMap[pod.Status.PodIP] = &PodInfo{
			Name:      pod.Name,
			Namespace: pod.Namespace,
			IP:        pod.Status.PodIP,
			NodeName:  pod.Spec.NodeName,
		}
	}
}

func (w *Watcher) deletePod(pod *corev1.Pod) {
	if pod.Status.PodIP != "" {
		delete(w.podMap, pod.Status.PodIP)
	}
}

func (w *Watcher) updateEndpoint(ep *corev1.Endpoints) {
	// Simple map rebuild for the key (lazy approach, or incremental)
	// Since mapping is IP -> []Services, and one IP can be in many services.
	// We need to be careful not to overwrite.
	// Actually for simplicity, let's just re-scan all IPs in this endpoint and add this service.
	// But removing is hard.
	// Better approach:
	// A simpler map: IP -> ServiceName (Last write wins? Or list?)
	// User asked for "Resolve IPs to Namespace and Service Name".
	// Let's store unique list.

	svcName := fmt.Sprintf("%s/%s", ep.Namespace, ep.Name)

	for _, subset := range ep.Subsets {
		for _, addr := range subset.Addresses {
			if addr.IP == "" {
				continue
			}
			w.addServiceToIP(addr.IP, svcName)
		}
	}
}

func (w *Watcher) deleteEndpoint(ep *corev1.Endpoints) {
	svcName := fmt.Sprintf("%s/%s", ep.Namespace, ep.Name)
	// Full scan likely needed to clean up? Or just don't worry about leaks for now?
	// To do it right: we'd need a reverse map or iterate.
	// For this task, let's implement a naive removal if possible, otherwise skip.
	// Leaking service names on IP reuse is possible but rare in short term.
	// Let's do nothing for delete for now to avoid complexity unless required.
	// Ideally we keep a map[EndpointUID] -> []IPs to clean up.
	// BUT, strict correctness: iterate map? No, expensive.
	// Let's iterate map since map is likely smallish (Active Pods).
	for ip, services := range w.serviceMap {
		newServices := []string{}
		for _, s := range services {
			if s != svcName {
				newServices = append(newServices, s)
			}
		}
		if len(newServices) == 0 {
			delete(w.serviceMap, ip)
		} else {
			w.serviceMap[ip] = newServices
		}
	}
}

func (w *Watcher) addServiceToIP(ip, svc string) {
	services := w.serviceMap[ip]
	for _, s := range services {
		if s == svc {
			return // Already exists
		}
	}
	w.serviceMap[ip] = append(services, svc)
}

// updateService tracks Service ClusterIP
func (w *Watcher) updateService(svc *corev1.Service) {
	// Only track ClusterIP services (not NodePort, LoadBalancer, etc.)
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return
	}

	svcName := fmt.Sprintf("%s/%s", svc.Namespace, svc.Name)
	w.serviceIPMap[svc.Spec.ClusterIP] = svcName
}

// deleteService removes Service ClusterIP from tracking
func (w *Watcher) deleteService(svc *corev1.Service) {
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		delete(w.serviceIPMap, svc.Spec.ClusterIP)
	}
}

// GetPodByIP returns pod info for a given IP
func (w *Watcher) GetPodByIP(ip string) *PodInfo {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if info, ok := w.podMap[ip]; ok {
		return info
	}
	return nil
}

// GetServicesByIP returns list of services for a given IP
func (w *Watcher) GetServicesByIP(ip string) []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if svcs, ok := w.serviceMap[ip]; ok {
		return svcs // Returns copy? No, slice reference. Caller shouldn't mutate.
	}
	return nil
}

// GetPodURI returns a friendly string "namespace/podname" for an IP
func (w *Watcher) GetPodURI(ip string) string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// 1. Try Service ClusterIP first (most common for destinations)
	if svcName, ok := w.serviceIPMap[ip]; ok {
		return fmt.Sprintf("svc:%s", svcName)
	}

	// 2. Try Endpoint-based service (pod IP with service)
	if svcs, ok := w.serviceMap[ip]; ok && len(svcs) > 0 {
		// Return first service + pod name hint if available
		svc := svcs[0] // Just pick first
		if pod, ok := w.podMap[ip]; ok {
			return fmt.Sprintf("svc:%s (pod:%s)", svc, pod.Name)
		}
		return fmt.Sprintf("svc:%s", svc)
	}

	// 3. Try Pod only
	if info, ok := w.podMap[ip]; ok {
		return fmt.Sprintf("%s/%s", info.Namespace, info.Name)
	}

	return ip // Fallback to IP if unknown
}
