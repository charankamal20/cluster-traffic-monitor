package k8s

import (
	"context"
	"fmt"
	"log"
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
	client *kubernetes.Clientset
	podMap map[string]*PodInfo // IP -> PodInfo
	mu     sync.RWMutex
	stopCh chan struct{}
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
		client: clientset,
		podMap: make(map[string]*PodInfo),
		stopCh: make(chan struct{}),
	}, nil
}

// Start begins watching pods
func (w *Watcher) Start(ctx context.Context) error {
	log.Println("Starting K8s Pod Watcher...")

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

	log.Printf("Initial pod cache built: %d pods", len(pods.Items))

	// Watch loop
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				watchOpts := metav1.ListOptions{
					Watch:           true,
					ResourceVersion: pods.ResourceVersion,
				}
				watcher, err := w.client.CoreV1().Pods("").Watch(ctx, watchOpts)
				if err != nil {
					log.Printf("Error watching pods: %v. Retrying...", err)
					time.Sleep(5 * time.Second)
					continue
				}

				for event := range watcher.ResultChan() {
					pod, ok := event.Object.(*corev1.Pod)
					if !ok {
						continue
					}

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

// GetPodByIP returns pod info for a given IP
func (w *Watcher) GetPodByIP(ip string) *PodInfo {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if info, ok := w.podMap[ip]; ok {
		return info
	}
	return nil
}

// GetPodURI returns a friendly string "namespace/podname" for an IP
func (w *Watcher) GetPodURI(ip string) string {
	info := w.GetPodByIP(ip)
	if info == nil {
		return ip // Fallback to IP if unknown
	}
	return fmt.Sprintf("%s/%s", info.Namespace, info.Name)
}
