package nes

import (
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket configuration
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// WebSocketConfig represents WebSocket-specific configuration
type WebSocketConfig struct {
	ReadBufferSize  int
	WriteBufferSize int
	WriteWait       time.Duration
	PongWait        time.Duration
	PingPeriod      time.Duration
}

// WebSocketConnection represents a managed WebSocket connection
type WebSocketConnection struct {
	ID       string
	Conn     *websocket.Conn
	Done     chan struct{}
	ErrorCh  chan error
	IsClosed bool
	mu       sync.RWMutex
}

// Default WebSocket configuration values
var defaultWSConfig = WebSocketConfig{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	WriteWait:       10 * time.Second,
	PongWait:        60 * time.Second,
	PingPeriod:      (60 * time.Second * 9) / 10,
}

// NewWebSocketConnection creates a new WebSocket connection handler
func NewWebSocketConnection(id string, conn *websocket.Conn) *WebSocketConnection {
	return &WebSocketConnection{
		ID:      id,
		Conn:    conn,
		Done:    make(chan struct{}),
		ErrorCh: make(chan error, 1),
	}
}

// Close safely closes the WebSocket connection
func (wsc *WebSocketConnection) Close() error {
	wsc.mu.Lock()
	defer wsc.mu.Unlock()

	if wsc.IsClosed {
		return nil
	}

	wsc.IsClosed = true
	close(wsc.Done)

	// Send close message to client
	message := websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutdown")
	deadline := time.Now().Add(defaultWSConfig.WriteWait)
	err := wsc.Conn.WriteControl(websocket.CloseMessage, message, deadline)

	if err := wsc.Conn.Close(); err != nil {
		return err
	}

	return err
}

// IsAlive checks if the connection is still active
func (wsc *WebSocketConnection) IsAlive() bool {
	wsc.mu.RLock()
	defer wsc.mu.RUnlock()
	return !wsc.IsClosed
}

// Handle manages the WebSocket connection lifecycle
func (wsc *WebSocketConnection) Handle(backend *websocket.Conn) {
	// Start ping-pong handler
	go wsc.pingHandler()

	// Start message forwarding
	go wsc.forwardMessages(wsc.Conn, backend, "client→backend")
	go wsc.forwardMessages(backend, wsc.Conn, "backend→client")

	// Wait for completion or error
	select {
	case <-wsc.Done:
		return
	case err := <-wsc.ErrorCh:
		if err != nil {
			// Handle error (logging, metrics, etc.)
			return
		}
	}
}

// pingHandler maintains connection liveness
func (wsc *WebSocketConnection) pingHandler() {
	ticker := time.NewTicker(defaultWSConfig.PingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := wsc.ping(); err != nil {
				return
			}
		case <-wsc.Done:
			return
		}
	}
}

// ping sends a ping message to keep the connection alive
func (wsc *WebSocketConnection) ping() error {
	wsc.mu.RLock()
	defer wsc.mu.RUnlock()

	if wsc.IsClosed {
		return nil
	}

	deadline := time.Now().Add(defaultWSConfig.WriteWait)
	err := wsc.Conn.WriteControl(websocket.PingMessage, []byte{}, deadline)
	if err != nil {
		wsc.ErrorCh <- err
		return err
	}
	return nil
}

// forwardMessages handles message forwarding between connections
func (wsc *WebSocketConnection) forwardMessages(src, dst *websocket.Conn, direction string) {
	for {
		messageType, message, err := src.ReadMessage()
		if err != nil {
			wsc.ErrorCh <- err
			return
		}

		err = dst.WriteMessage(messageType, message)
		if err != nil {
			wsc.ErrorCh <- err
			return
		}
	}
}
