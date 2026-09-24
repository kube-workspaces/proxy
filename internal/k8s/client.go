// Package k8s provides a minimal Kubernetes client for the proxy service.
// It only needs read access to Workspace and Image CRs.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	workspaceGVR = schema.GroupVersionResource{
		Group:    "kubeworkspaces.io",
		Version:  "v1alpha1",
		Resource: "workspaces",
	}
	imageGVR = schema.GroupVersionResource{
		Group:    "kubeworkspaces.io",
		Version:  "v1alpha1",
		Resource: "images",
	}
)

// Client provides read-only access to Workspace and Image CRs.
type Client struct {
	dynamic dynamic.Interface

	// Cache for Image CRs (refreshed every 30 seconds)
	imageCache      []unstructured.Unstructured
	imageCacheMu    sync.RWMutex
	imageCacheTime  time.Time
	imageCacheTTL   time.Duration

	// Cache for workspace image lookups (namespace/name → image ref)
	wsImageCache    map[string]wsImageEntry
	wsImageCacheMu  sync.RWMutex
	wsImageCacheTTL time.Duration
}

type wsImageEntry struct {
	image              string
	preservePathPrefix bool
	fetched            time.Time
}

// WorkspaceInfo holds the image reference and proxy-relevant metadata for a workspace.
type WorkspaceInfo struct {
	Image              string
	PreservePathPrefix bool
}

// DynamicClient returns the underlying dynamic Kubernetes client.
// Used by the auth package to read AuthConfig, User CRs, and Secrets.
func (c *Client) DynamicClient() dynamic.Interface {
	return c.dynamic
}

// NewClient creates a new Kubernetes client configured from in-cluster or kubeconfig.
func NewClient() (*Client, error) {
	config, err := getConfig()
	if err != nil {
		return nil, err
	}

	// Increase QPS/Burst to avoid client-side throttling.
	// The proxy makes multiple API calls per request (auth + workspace + image lookups).
	config.QPS = 50
	config.Burst = 100

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create dynamic client: %w", err)
	}

	return &Client{
		dynamic:         dynClient,
		imageCacheTTL:   30 * time.Second,
		wsImageCache:    make(map[string]wsImageEntry),
		wsImageCacheTTL: 10 * time.Second,
	}, nil
}

// GetWorkspaceImage returns the container image reference for a workspace CR.
// Results are cached for wsImageCacheTTL to reduce API calls.
func (c *Client) GetWorkspaceImage(ctx context.Context, namespace, name string) (string, error) {
	info := c.GetWorkspaceInfo(ctx, namespace, name)
	if info == nil {
		return "", fmt.Errorf("workspace %s/%s not found or invalid", namespace, name)
	}
	return info.Image, nil
}

// GetWorkspaceInfo returns workspace metadata (image + annotations) with caching.
func (c *Client) GetWorkspaceInfo(ctx context.Context, namespace, name string) *WorkspaceInfo {
	key := namespace + "/" + name

	// Check cache first
	c.wsImageCacheMu.RLock()
	if entry, ok := c.wsImageCache[key]; ok && time.Since(entry.fetched) < c.wsImageCacheTTL {
		c.wsImageCacheMu.RUnlock()
		return &WorkspaceInfo{Image: entry.image, PreservePathPrefix: entry.preservePathPrefix}
	}
	c.wsImageCacheMu.RUnlock()

	obj, err := c.dynamic.Resource(workspaceGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil
	}

	// Check annotation for preserve-path-prefix
	annotations := obj.GetAnnotations()
	preservePathPrefix := annotations["kubeworkspaces.io/preserve-path-prefix"] == "true"

	// Extract spec.template.spec.containers[0].image
	spec, _ := obj.Object["spec"].(map[string]interface{})
	if spec == nil {
		return nil
	}
	template, _ := spec["template"].(map[string]interface{})
	if template == nil {
		return nil
	}
	podSpec, _ := template["spec"].(map[string]interface{})
	if podSpec == nil {
		return nil
	}
	containers, _ := podSpec["containers"].([]interface{})
	if len(containers) == 0 {
		return nil
	}
	container, _ := containers[0].(map[string]interface{})
	if container == nil {
		return nil
	}
	image, _ := container["image"].(string)

	// Update cache
	c.wsImageCacheMu.Lock()
	c.wsImageCache[key] = wsImageEntry{image: image, preservePathPrefix: preservePathPrefix, fetched: time.Now()}
	c.wsImageCacheMu.Unlock()

	return &WorkspaceInfo{Image: image, PreservePathPrefix: preservePathPrefix}
}

// ImageProxyConfig describes proxy behavior for an image.
type ImageProxyConfig struct {
	NeedsNoOpSW              bool
	WebSocketPaths           []string
	RewriteHostAbsolutePaths bool
	CustomRequestHeaders     map[string]string
	InjectBaseTag            bool
	Scheme                   string
	TLSSkipVerify            bool
	// TLSInsecure is deprecated in favour of Scheme + TLSSkipVerify.
	TLSInsecure        bool
	PreservePathPrefix bool
	AudioPort          int32
	// Port: the workspace Service port to proxy to. 0 means default 80.
	Port int32
}

// GetImageProxyConfig finds an Image CR by its container image reference and returns its proxy config.
// Returns nil if no Image CR matches or the image has no proxy config.
// Image CRs are cached for imageCacheTTL to reduce API calls.
func (c *Client) GetImageProxyConfig(ctx context.Context, imageRef string) *ImageProxyConfig {
	items := c.getCachedImages(ctx)
	if items == nil {
		return nil
	}

	for i := range items {
		cfg := extractProxyConfig(&items[i], imageRef)
		if cfg != nil {
			return cfg
		}
	}
	return nil
}

// getCachedImages returns the cached list of Image CRs, refreshing if expired.
func (c *Client) getCachedImages(ctx context.Context) []unstructured.Unstructured {
	c.imageCacheMu.RLock()
	if c.imageCache != nil && time.Since(c.imageCacheTime) < c.imageCacheTTL {
		items := c.imageCache
		c.imageCacheMu.RUnlock()
		return items
	}
	c.imageCacheMu.RUnlock()

	// Cache miss or expired — fetch fresh
	list, err := c.dynamic.Resource(imageGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	c.imageCacheMu.Lock()
	c.imageCache = list.Items
	c.imageCacheTime = time.Now()
	c.imageCacheMu.Unlock()

	return list.Items
}

// extractProxyConfig checks if an Image CR matches the given image reference
// and extracts its proxyConfig if present.
func extractProxyConfig(obj *unstructured.Unstructured, imageRef string) *ImageProxyConfig {
	spec, ok := obj.Object["spec"].(map[string]interface{})
	if !ok {
		return nil
	}

	// Check if this Image CR's spec.image matches
	image := strField(spec, "image")
	if image != imageRef {
		return nil
	}

	pc, ok := spec["proxyConfig"].(map[string]interface{})
	if !ok {
		return nil
	}

	cfg := &ImageProxyConfig{
		NeedsNoOpSW:              boolField(pc, "needsNoopSW"),
		RewriteHostAbsolutePaths: boolField(pc, "rewriteHostAbsolutePaths"),
		InjectBaseTag:            boolField(pc, "injectBaseTag"),
		Scheme:                   stringField(pc, "scheme"),
		TLSSkipVerify:            boolField(pc, "tlsSkipVerify"),
		TLSInsecure:              boolField(pc, "tlsInsecure"),
		PreservePathPrefix:       boolField(pc, "preservePathPrefix"),
		AudioPort:                int32Field(pc, "audioPort"),
		Port:                     int32Field(pc, "port"),
	}

	if paths, ok := pc["websocketPaths"].([]interface{}); ok {
		for _, p := range paths {
			if s, ok := p.(string); ok {
				cfg.WebSocketPaths = append(cfg.WebSocketPaths, s)
			}
		}
	}

	if headers, ok := pc["customRequestHeaders"].(map[string]interface{}); ok {
		cfg.CustomRequestHeaders = make(map[string]string, len(headers))
		for k, v := range headers {
			if s, ok := v.(string); ok {
				cfg.CustomRequestHeaders[k] = s
			}
		}
	}

	return cfg
}

func getConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("unable to determine home directory: %w", err)
			}
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("unable to build kubeconfig: %w", err)
		}
	}
	return config, nil
}

func strField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func boolField(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func stringField(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func int32Field(m map[string]interface{}, key string) int32 {
	switch v := m[key].(type) {
	case float64:
		return int32(v)
	case int64:
		return int32(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int32(n)
		}
	}
	return 0
}

// Ensure json import is used (for potential future use with Number parsing)
var _ = json.Number("")
