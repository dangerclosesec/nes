package nes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dangerclosesec/nes/internal/metrics"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/html"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// LoadBalancer represents a load balancer that manages traffic distribution
// across multiple backend servers. It includes configuration settings,
// reverse proxies, metrics, TLS configuration, certificate management,
// health status monitoring, and connection handling for both WebSocket and
// gRPC connections. It also manages HTTP servers and container-related
// operations.
//
// Fields:
// - config: Configuration settings for the load balancer.
// - proxies: A map of reverse proxies for routing traffic to backend servers.
// - metrics: An HTTP ServeMux for serving metrics endpoints.
// - tlsConfig: TLS configuration for secure communication.
// - certManager: Manager for automatic certificate management.
// - health: Health status monitoring for the load balancer.
// - Mu: A read-write mutex for synchronizing access to shared resources.
// - done: A channel used to signal the shutdown of the load balancer.
// - wsConns: A concurrent map for managing WebSocket connections.
// - grpcConns: A concurrent map for managing gRPC connections.
// - servers: A slice of HTTP servers managed by the load balancer.
// - upgrader: WebSocket upgrader for handling WebSocket connections.
// - containerCache: Cache for storing container-related data.
// - resolver: Resolver for managing container-related operations.
type LoadBalancer struct {
	config         *LoadBalancerConfig
	proxies        map[string]*httputil.ReverseProxy
	metrics        *http.ServeMux
	tlsConfig      *tls.Config
	certManager    *autocert.Manager
	health         *HealthStatus
	Mu             sync.RWMutex
	done           chan struct{}
	wsConns        sync.Map
	grpcConns      sync.Map
	servers        []*http.Server
	upgrader       websocket.Upgrader
	containerCache *ContainerCache
	resolver       *ContainerResolver
}

// GetHealth returns the current health status of the LoadBalancer.
// It acquires a read lock to ensure thread-safe access to the health status.
func (lb *LoadBalancer) GetHealth() *HealthStatus {
	lb.Mu.RLock()
	defer lb.Mu.RUnlock()
	return lb.health
}

type LoadBalancerOption func(*LoadBalancer) error

func LoadBalancerWithHttp(addr string) LoadBalancerOption {
	return func(lb *LoadBalancer) error {

		return nil
	}
}

func LoadBalancerWithTls(addr string, tlsConfig *tls.Config) LoadBalancerOption {
	return func(lb *LoadBalancer) error {

		return nil
	}
}

// ContainerCache maintains a cache of active containers and their health status
type ContainerCache struct {
	containers map[string]*Container
	mu         sync.RWMutex
}

type Container struct {
	ID       string
	Service  string
	Host     string
	Port     int
	Healthy  bool
	LastSeen time.Time
}

// HealthStatus represents the complete health state of the system
type HealthStatus struct {
	Healthy          bool             `json:"healthy"`
	LastCheck        time.Time        `json:"last_check"`
	LastError        error            `json:"-"`
	LastErrorTime    time.Time        `json:"last_error_time"`
	LastErrorStr     string           `json:"last_error,omitempty"`
	FailedEndpoints  map[string]error `json:"-"`
	ConsecutiveFails int              `json:"consecutive_fails"`
	ActiveContainers map[string]bool  `json:"active_containers"`
}

// NewLoadBalancer creates a new load balancer instance
func NewLoadBalancer(m *Manager) (*LoadBalancer, error) {
	lb := &LoadBalancer{
		config:  m.Config.LoadBalancer,
		proxies: make(map[string]*httputil.ReverseProxy),
		health: &HealthStatus{
			Healthy:          true,
			FailedEndpoints:  make(map[string]error),
			ActiveContainers: make(map[string]bool),
		},
		done: make(chan struct{}),
		containerCache: &ContainerCache{
			containers: make(map[string]*Container),
		},
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				// Implement origin checking based on config
				return true
			},
		},
		resolver: NewContainerResolver(m.Client),
	}

	lb.resolver.Start()

	// Initialize ACME if enabled
	if m.Config.LoadBalancer.UseACME {
		if err := lb.setupACME(); err != nil {
			return nil, fmt.Errorf("failed to setup ACME: %w", err)
		}
	}

	// Initialize proxies
	if err := lb.initializeProxies(); err != nil {
		return nil, fmt.Errorf("failed to initialize proxies: %w", err)
	}

	return lb, nil
}

func (lb *LoadBalancer) setupACME() error {
	cache := autocert.DirCache(lb.config.ACMECache)
	if lb.config.ACMECache == "" {
		cache = autocert.DirCache("./certs") // Default cache directory
	}

	lb.certManager = &autocert.Manager{
		Cache:      cache,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(lb.config.Domains...),
		Email:      lb.config.ACMEEmail,
	}

	lb.tlsConfig = lb.certManager.TLSConfig()
	lb.tlsConfig.NextProtos = []string{"h2", "http/1.1"} // Enable HTTP/2 support

	return nil
}

func (lb *LoadBalancer) initializeProxies() error {
	for path, route := range lb.config.Routes {
		proxy, err := lb.createProxy(path, route)
		if err != nil {
			return fmt.Errorf("failed to create proxy for path %s: %w", path, err)
		}
		lb.proxies[path] = proxy
	}
	return nil
}

func (lb *LoadBalancer) createProxy(path string, route Route) (*httputil.ReverseProxy, error) {
	director := func(req *http.Request) {
		// Resolve container port and get actual host/port
		hostIP, hostPort, err := lb.resolver.ResolveTarget(route.Service, route.Port)
		if err != nil {
			log.Printf("Failed to resolve service %s: %v", route.Service, err)
			return
		}

		req.URL.Scheme = "http"
		req.URL.Host = fmt.Sprintf("%s:%d", hostIP, hostPort)

		// Handle path rewriting if needed
		if strings.HasSuffix(path, "/") {
			// Remove the path prefix while preserving the rest of the path
			req.URL.Path = strings.TrimPrefix(req.URL.Path, path)
			// if !strings.HasPrefix(req.URL.Path, "/") {
			// 	req.URL.Path = "/" + req.URL.Path
			// }
		}

		// Add any custom headers
		if route.Auth.Type != "" {
			switch route.Auth.Type {
			case "oauth2":
				// Add OAuth2 headers
			case "api_key":
				// Add API key headers
			}
		}
	}

	// Create custom transport with timeout and keep-alive
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Create the reverse proxy with response rewriting
	proxy := &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		},
		ModifyResponse: func(r *http.Response) error {
			if !strings.HasSuffix(path, "/") {
				return nil // No modification needed
			}

			// Handle redirects
			if r.StatusCode == http.StatusMovedPermanently ||
				r.StatusCode == http.StatusFound ||
				r.StatusCode == http.StatusTemporaryRedirect ||
				r.StatusCode == http.StatusPermanentRedirect {

				if location := r.Header.Get("Location"); location != "" {
					// Parse the location URL
					locationURL, err := url.Parse(location)
					if err != nil {
						return fmt.Errorf("failed to parse location header: %w", err)
					}

					// Reconstruct the path with the original prefix
					if !strings.HasPrefix(locationURL.Path, path) {
						newPath := strings.TrimSuffix(path, "/") + locationURL.Path
						locationURL.Path = newPath
						r.Header.Set("Location", locationURL.String())
					}
				}
			}

			// Handle HTML content
			if strings.Contains(r.Header.Get("Content-Type"), "text/html") {
				oldBody, err := io.ReadAll(r.Body)
				if err != nil {
					return fmt.Errorf("failed to read response body: %w", err)
				}
				r.Body.Close()

				// Rewrite HTML content
				newBody := rewriteHTMLPaths(oldBody, path)

				// Update response
				r.Body = io.NopCloser(bytes.NewReader(newBody))
				r.Header.Set("Content-Length", fmt.Sprint(len(newBody)))
				r.ContentLength = int64(len(newBody))
			}

			// Handle JSON content
			if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				oldBody, err := io.ReadAll(r.Body)
				if err != nil {
					return fmt.Errorf("failed to read response body: %w", err)
				}
				r.Body.Close()

				// Rewrite JSON content
				newBody := rewriteJSONPaths(oldBody, path)

				// Update response
				r.Body = io.NopCloser(bytes.NewReader(newBody))
				r.Header.Set("Content-Length", fmt.Sprint(len(newBody)))
				r.ContentLength = int64(len(newBody))
			}

			return nil
		},
	}

	return proxy, nil
}

// rewriteHTMLPaths modifies HTML content to include the correct paths
func rewriteHTMLPaths(body []byte, prefix string) []byte {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		log.Printf("Failed to parse HTML: %v", err)
		return body
	}

	var rewriteNode func(*html.Node)
	rewriteNode = func(n *html.Node) {
		if n.Type == html.ElementNode {
			// Rewrite attributes that contain URLs
			for i, attr := range n.Attr {
				switch attr.Key {
				case "href", "src", "action", "data-url":
					if strings.HasPrefix(attr.Val, "/") && !strings.HasPrefix(attr.Val, prefix) {
						n.Attr[i].Val = strings.TrimSuffix(prefix, "/") + attr.Val
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rewriteNode(c)
		}
	}

	rewriteNode(doc)

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		log.Printf("Failed to render HTML: %v", err)
		return body
	}

	return buf.Bytes()
}

// rewriteJSONPaths modifies JSON content to include the correct paths
func rewriteJSONPaths(body []byte, prefix string) []byte {
	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return body
	}

	var rewriteValue func(interface{}) interface{}
	rewriteValue = func(v interface{}) interface{} {
		switch val := v.(type) {
		case string:
			if strings.HasPrefix(val, "/") && !strings.HasPrefix(val, prefix) {
				return strings.TrimSuffix(prefix, "/") + val
			}
			return val
		case map[string]interface{}:
			newMap := make(map[string]interface{})
			for k, v := range val {
				newMap[k] = rewriteValue(v)
			}
			return newMap
		case []interface{}:
			newArray := make([]interface{}, len(val))
			for i, v := range val {
				newArray[i] = rewriteValue(v)
			}
			return newArray
		default:
			return val
		}
	}

	modifiedData := rewriteValue(data)
	newBody, err := json.Marshal(modifiedData)
	if err != nil {
		return body
	}

	return newBody
}

func (m *Manager) StartLoadBalancer(opts ...LoadBalancerOption) error {
	lb, err := NewLoadBalancer(m)
	if err != nil {
		return fmt.Errorf("failed to create load balancer: %w", err)
	}

	m.LoadBalancer = lb

	// Start the load balancer
	if err := lb.Start(opts...); err != nil {
		return fmt.Errorf("failed to start load balancer: %w", err)
	}

	// Setup graceful shutdown
	go func() {
		<-m.Ctx.Done() // Wait for shutdown signal
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := lb.Shutdown(ctx); err != nil {
			log.Printf("Error during load balancer shutdown: %v", err)
		}
	}()

	return nil
}

// StartLoadBalancer starts the load balancer with the given options
func (lb *LoadBalancer) Start(opts ...LoadBalancerOption) error {
	// Apply options
	for _, opt := range opts {
		if err := opt(lb); err != nil {
			return fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Start HTTP server
	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%s:80", lb.config.BindIP),
		Handler: h2c.NewHandler(lb, &http2.Server{}),
	}
	lb.servers = append(lb.servers, httpServer)

	go func() {
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server if TLS is enabled
	if lb.tlsConfig != nil {
		httpsServer := &http.Server{
			Addr:      fmt.Sprintf("%s:443", lb.config.BindIP),
			Handler:   lb,
			TLSConfig: lb.tlsConfig,
		}
		lb.servers = append(lb.servers, httpsServer)

		go func() {
			if err := httpsServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
				log.Printf("HTTPS server error: %v", err)
			}
		}()
	}

	// Start health checking
	go lb.healthCheckLoop()

	return nil
}

// Shutdown gracefully shuts down the load balancer
func (lb *LoadBalancer) Shutdown(ctx context.Context) error {
	// Signal shutdown
	close(lb.done)

	// Create wait group for tracking shutdown progress
	var wg sync.WaitGroup

	// Shutdown all servers
	for _, server := range lb.servers {
		wg.Add(1)
		go func(srv *http.Server) {
			defer wg.Done()
			if err := srv.Shutdown(ctx); err != nil {
				log.Printf("Error during server shutdown: %v", err)
			}
		}(server)
	}

	// Close all WebSocket connections
	lb.wsConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(*websocket.Conn); ok {
			conn.Close()
		}
		return true
	})

	// Close all gRPC connections
	lb.grpcConns.Range(func(key, value interface{}) bool {
		if conn, ok := value.(net.Conn); ok {
			conn.Close()
		}
		return true
	})

	// Wait for all shutdowns to complete or context to expire
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (lb *LoadBalancer) healthCheckLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-lb.done:
			return
		case <-ticker.C:
			lb.performHealthCheck()
		}
	}
}
func (lb *LoadBalancer) performHealthCheck() {
	// DBG: log.Printf("Performing health check")
	lb.Mu.Lock()
	defer lb.Mu.Unlock()

	allHealthy := true
	lb.health.LastCheck = time.Now()
	lb.health.FailedEndpoints = make(map[string]error)
	lb.health.ActiveContainers = make(map[string]bool)

	for path, route := range lb.config.Routes {
		// DBG: log.Printf("#=> Path: %s\n\t%#v\n", path, route)

		// Resolve actual host and port using container resolver
		hostIP, hostPort, err := lb.resolver.ResolveTarget(route.Service, route.Port)
		if err != nil {
			log.Printf("Service unhealthy or misconfigured: %s: %v", route.Service, err)
			allHealthy = false
			lb.health.FailedEndpoints[path] = fmt.Errorf("service resolution failed: %w", err)
			lb.health.ConsecutiveFails++
			lb.health.LastError = err
			lb.health.LastErrorTime = time.Now()
			lb.health.LastErrorStr = err.Error()
			continue
		}

		// Update target with resolved host and port
		target := fmt.Sprintf("%s:%d", hostIP, hostPort)
		// DBG: log.Printf("Checking resolved endpoint %s for service %s", target, route.Service)

		// Perform health check for each protocol
		for _, protocol := range route.Protocols {
			var healthErr error

			switch protocol {
			case "http", "https":
				healthErr = lb.checkHTTPEndpoint(target, protocol)
			case "grpc", "grpcs":
				healthErr = lb.checkGRPCEndpoint(target, protocol == "grpcs")
			case "websocket":
				healthErr = lb.checkWebSocketEndpoint(target)
			default:
				healthErr = lb.checkTCPEndpoint(target)
			}

			if healthErr != nil {
				log.Printf("Endpoint %s (%s) failed health check: %v", target, protocol, healthErr)
				allHealthy = false
				lb.health.FailedEndpoints[fmt.Sprintf("%s-%s", path, protocol)] = healthErr
				lb.health.ConsecutiveFails++
				lb.health.LastError = healthErr
				lb.health.LastErrorTime = time.Now()
				lb.health.LastErrorStr = healthErr.Error()
			} else {
				// Mark container as active if any protocol check succeeds
				lb.health.ActiveContainers[route.Service] = true
			}
		}
	}

	if allHealthy {
		lb.health.ConsecutiveFails = 0
		lb.health.Healthy = true
	} else if lb.health.ConsecutiveFails > 3 {
		lb.health.Healthy = false
	}
}

func (lb *LoadBalancer) checkTCPEndpoint(target string) error {
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return fmt.Errorf("TCP connection failed: %w", err)
	}
	defer conn.Close()
	return nil
}

func (lb *LoadBalancer) checkHTTPEndpoint(target, protocol string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For health checks only
			},
		},
	}

	scheme := "http"
	if protocol == "https" {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s", scheme, target)
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP health check returned status %d", resp.StatusCode)
	}

	return nil
}

func (lb *LoadBalancer) checkGRPCEndpoint(target string, useTLS bool) error {
	var conn net.Conn
	var err error

	// Establish TCP connection first
	conn, err = net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return fmt.Errorf("gRPC TCP connection failed: %w", err)
	}
	defer conn.Close()

	if useTLS {
		// Upgrade to TLS for gRPCs
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true, // For health checks only
			NextProtos:         []string{"h2"},
		})
		defer tlsConn.Close()

		// Perform TLS handshake with timeout
		if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return fmt.Errorf("failed to set TLS deadline: %w", err)
		}
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("TLS handshake failed: %w", err)
		}
	}

	return nil
}

func (lb *LoadBalancer) checkWebSocketEndpoint(target string) error {
	// Create WebSocket connection with timeout
	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For health checks only
		},
	}

	// Try both ws:// and wss:// protocols
	protocols := []string{"ws", "wss"}
	var lastErr error

	for _, proto := range protocols {
		url := fmt.Sprintf("%s://%s/health", proto, target)
		conn, _, err := dialer.Dial(url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		defer conn.Close()
		return nil
	}

	return fmt.Errorf("WebSocket health check failed: %v", lastErr)
}

func (lb *LoadBalancer) checkEndpoint(target string) error {
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func (lb *LoadBalancer) isHealthy() bool {
	lb.Mu.RLock()
	defer lb.Mu.RUnlock()
	return lb.health.Healthy
}

// ServeHTTP implements the http.Handler interface for the LoadBalancer
func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	metrics.ActiveConnections.Inc()
	defer metrics.ActiveConnections.Dec()

	// Circuit breaker pattern
	// if !lb.isHealthy() {
	// 	log.Printf("Service temporarily unavailable ")
	// if lb.shouldAttemptRecovery() {
	// 	if err := lb.attemptRecovery(); err != nil {
	// 		http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
	// 		return
	// 	}
	// } else {
	// 	http.Error(w, "Service temporarily unavailable", http.StatusServiceUnavailable)
	// 	return
	// }
	// }

	// Handle WebSocket upgrade
	if websocket.IsWebSocketUpgrade(r) {
		lb.handleWebSocket(w, r)
		return
	}

	// Handle gRPC requests
	if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
		lb.handleGRPC(w, r)
		return
	}

	// Regular HTTP/HTTP2 routing
	for path, proxy := range lb.proxies {
		if strings.HasPrefix(r.URL.Path, path) {
			proxy.ServeHTTP(w, r)
			metrics.RequestDuration.WithLabelValues(path).Observe(time.Since(start).Seconds())
			metrics.RequestCounter.WithLabelValues(path, strconv.Itoa(http.StatusOK), r.Proto).Inc()
			return
		}
	}

	// No matching route found
	http.Error(w, "Not found", http.StatusNotFound)
	metrics.RequestCounter.WithLabelValues("", strconv.Itoa(http.StatusNotFound), r.Proto).Inc()
}

func (lb *LoadBalancer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not yet implemented", http.StatusNotImplemented)
	return

	route, _, err := lb.findRoute(r.URL.Path, "websocket")
	if err != nil {
		http.Error(w, "WebSocket endpoint not found", http.StatusNotFound)
		return
	}

	// Create backend URL
	backendURL := url.URL{
		Scheme: "ws",
		Host:   fmt.Sprintf("%s:%d", route.Service, route.Port),
		Path:   r.URL.Path,
	}
	if r.TLS != nil {
		backendURL.Scheme = "wss"
	}

	// Connect to backend
	backendConn, _, err := websocket.DefaultDialer.Dial(backendURL.String(), nil)
	if err != nil {
		http.Error(w, "Could not connect to backend", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Upgrade client connection
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade WebSocket connection: %v", err)
		return
	}

	// Create and manage WebSocket connection
	wsConn := NewWebSocketConnection(uuid.New().String(), clientConn)
	lb.wsConns.Store(wsConn.ID, wsConn)
	defer func() {
		lb.wsConns.Delete(wsConn.ID)
		wsConn.Close()
	}()

	// Handle the WebSocket connection
	wsConn.Handle(backendConn)
}

// HandleGRPC manages gRPC connections
func (lb *LoadBalancer) handleGRPC(w http.ResponseWriter, r *http.Request) {

	http.Error(w, "not yet implemented", http.StatusNotImplemented)
	return

	route, _, err := lb.findRoute(r.URL.Path, "grpc")
	if err != nil {
		http.Error(w, "gRPC endpoint not found", http.StatusNotFound)
		return
	}

	// Create connection ID
	connID := uuid.New().String()

	// Setup backend connection
	backendAddr := fmt.Sprintf("%s:%d", route.Service, route.Port)
	backendConn, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
	if err != nil {
		http.Error(w, "Could not connect to backend", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	// Handle TLS if needed
	if r.TLS != nil {
		tlsConn := tls.Client(backendConn, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		if err := tlsConn.Handshake(); err != nil {
			http.Error(w, "TLS handshake failed", http.StatusInternalServerError)
			return
		}
		backendConn = tlsConn
	}

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, bufrw, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Track connection
	lb.grpcConns.Store(connID, struct{}{})
	defer lb.grpcConns.Delete(connID)

	// Create error channel
	errChan := make(chan error, 2)

	// Forward buffered data
	if bufrw.Reader.Buffered() > 0 {
		buffer := make([]byte, bufrw.Reader.Buffered())
		if _, err := bufrw.Reader.Read(buffer); err != nil {
			log.Printf("Error reading buffered data: %v", err)
			return
		}
		if _, err := backendConn.Write(buffer); err != nil {
			log.Printf("Error writing to backend: %v", err)
			return
		}
	}

	// Start bidirectional copying
	go lb.copyConn(backendConn, clientConn, errChan, "client→backend")
	go lb.copyConn(clientConn, backendConn, errChan, "backend→client")

	// Wait for completion or shutdown
	select {
	case err := <-errChan:
		if err != nil {
			log.Printf("gRPC error: %v", err)
		}
	case <-lb.done:
		// Graceful shutdown handled by connection close
	}

	// requestCounter.WithLabelValues(targetPath, "200", "grpc").Inc()
}

// findRoute locates the appropriate route for a given path and protocol
func (lb *LoadBalancer) findRoute(path, protocol string) (Route, string, error) {
	for routePath, route := range lb.config.Routes {
		if strings.HasPrefix(path, routePath) {
			for _, p := range route.Protocols {
				if p == protocol {
					return route, routePath, nil
				}
			}
		}
	}
	return Route{}, "", fmt.Errorf("no matching route found for path: %s, protocol: %s", path, protocol)
}

// CopyConn copies data between connections
func (lb *LoadBalancer) copyConn(dst, src net.Conn, errChan chan error, direction string) {
	_, err := io.Copy(dst, src)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		errChan <- fmt.Errorf("%s copy error: %v", direction, err)
		return
	}
	errChan <- nil
}
