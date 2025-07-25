package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/proxify"
)

// AdvancedListener is an advanced custom net.Listener implementation
type AdvancedListener struct {
	net.Listener
	mu sync.RWMutex

	// Statistics
	totalConnections  int64
	activeConnections int64
	maxConnections    int64
	connectionTimeout time.Duration

	// Connection pool management
	connections map[net.Conn]time.Time
	closed      bool
}

// AdvancedListenerFactory implements the ListenerFactory interface
type AdvancedListenerFactory struct {
	MaxConnections    int64
	ConnectionTimeout time.Duration
	EnableMetrics     bool
}

// CreateListener creates an advanced listener
func (f *AdvancedListenerFactory) CreateListener(network, address string) (net.Listener, error) {
	baseListener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	advancedListener := &AdvancedListener{
		Listener:          baseListener,
		maxConnections:    f.MaxConnections,
		connectionTimeout: f.ConnectionTimeout,
		connections:       make(map[net.Conn]time.Time),
	}

	if f.EnableMetrics {
		// Start monitoring goroutine
		go advancedListener.monitorConnections()
	}

	fmt.Printf("Advanced listener created for %s on %s (max connections: %d, timeout: %v)\n",
		network, address, f.MaxConnections, f.ConnectionTimeout)

	return advancedListener, nil
}

// Accept overrides the Accept method to add connection limiting and statistics
func (l *AdvancedListener) Accept() (net.Conn, error) {
	// Check connection limit
	if atomic.LoadInt64(&l.activeConnections) >= l.maxConnections {
		return nil, fmt.Errorf("connection limit reached (%d/%d)", l.activeConnections, l.maxConnections)
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Update statistics
	atomic.AddInt64(&l.totalConnections, 1)
	atomic.AddInt64(&l.activeConnections, 1)

	// Set connection timeout
	if l.connectionTimeout > 0 {
		conn.SetDeadline(time.Now().Add(l.connectionTimeout))
	}

	// Record connection
	l.mu.Lock()
	l.connections[conn] = time.Now()
	l.mu.Unlock()

	fmt.Printf("Connection accepted from %s (active: %d/%d, total: %d)\n",
		conn.RemoteAddr(), atomic.LoadInt64(&l.activeConnections), l.maxConnections, atomic.LoadInt64(&l.totalConnections))

	// Wrap connection to track closure
	return &TrackedConn{
		Conn:     conn,
		listener: l,
	}, nil
}

// Close overrides the Close method
func (l *AdvancedListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()

	fmt.Printf("Advanced listener closed. Final stats - Total: %d, Active: %d\n",
		atomic.LoadInt64(&l.totalConnections), atomic.LoadInt64(&l.activeConnections))

	return l.Listener.Close()
}

// GetStats gets listener statistics
func (l *AdvancedListener) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":  atomic.LoadInt64(&l.totalConnections),
		"active_connections": atomic.LoadInt64(&l.activeConnections),
		"max_connections":    l.maxConnections,
		"connection_timeout": l.connectionTimeout,
		"is_closed":          l.closed,
	}
}

// monitorConnections monitors connection status
func (l *AdvancedListener) monitorConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		<-ticker.C
		l.mu.RLock()
		if l.closed {
			l.mu.RUnlock()
			return
		}

		// Clean up timed out connections
		now := time.Now()
		for conn, startTime := range l.connections {
			if now.Sub(startTime) > l.connectionTimeout {
				conn.Close()
				delete(l.connections, conn)
				atomic.AddInt64(&l.activeConnections, -1)
			}
		}
		l.mu.RUnlock()

		stats := l.GetStats()
		fmt.Printf("Monitor: Active connections: %d/%d, Total: %d\n",
			stats["active_connections"], stats["max_connections"], stats["total_connections"])
	}
}

// TrackedConn wraps net.Conn to track connection closure
type TrackedConn struct {
	net.Conn
	listener *AdvancedListener
}

// Close overrides the Close method to update statistics
func (tc *TrackedConn) Close() error {
	tc.listener.mu.Lock()
	delete(tc.listener.connections, tc.Conn)
	tc.listener.mu.Unlock()

	atomic.AddInt64(&tc.listener.activeConnections, -1)

	fmt.Printf("Connection from %s closed (active: %d/%d)\n",
		tc.Conn.RemoteAddr(), atomic.LoadInt64(&tc.listener.activeConnections), tc.listener.maxConnections)

	return tc.Conn.Close()
}

func main() {
	// Create advanced listener factory
	listenerFactory := &AdvancedListenerFactory{
		MaxConnections:    10,              // Maximum 10 concurrent connections
		ConnectionTimeout: 5 * time.Minute, // Connection timeout 5 minutes
		EnableMetrics:     true,            // Enable monitoring
	}

	// Create proxy options
	options := &proxify.Options{
		ListenAddrHTTP:  ":8888",
		Verbosity:       1, // Verbose
		ListenerFactory: listenerFactory,
	}

	// Create proxy instance
	proxy, err := proxify.NewProxy(options)
	if err != nil {
		panic(fmt.Sprintf("Failed to create proxy: %v", err))
	}

	fmt.Println("Starting proxy with advanced listener...")
	fmt.Println("Features:")
	fmt.Println("- Connection limiting (max 10 concurrent)")
	fmt.Println("- Connection timeout (5 minutes)")
	fmt.Println("- Connection monitoring and statistics")
	fmt.Println("- Automatic cleanup of stale connections")

	// Run proxy
	if err := proxy.Run(); err != nil {
		panic(fmt.Sprintf("Failed to run proxy: %v", err))
	}
}
