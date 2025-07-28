package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Only allow connections from localhost
		return r.Header.Get("Origin") == "http://localhost" ||
			r.Header.Get("Origin") == "https://localhost" ||
			r.Header.Get("Origin") == ""
	},
}

type WSClient struct {
	conn   *websocket.Conn
	send   chan []byte
	server *WSServer
}

type WSServer struct {
	clients    map[*WSClient]bool
	broadcast  chan []byte
	register   chan *WSClient
	unregister chan *WSClient
	mu         sync.RWMutex
}

type WSMessage struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

func NewWSServer() *WSServer {
	return &WSServer{
		clients:    make(map[*WSClient]bool),
		broadcast:  make(chan []byte),
		register:   make(chan *WSClient),
		unregister: make(chan *WSClient),
	}
}

func (ws *WSServer) Run() {
	for {
		select {
		case client := <-ws.register:
			ws.mu.Lock()
			ws.clients[client] = true
			ws.mu.Unlock()
			logrus.Debug("WebSocket client connected")

		case client := <-ws.unregister:
			ws.mu.Lock()
			if _, ok := ws.clients[client]; ok {
				delete(ws.clients, client)
				close(client.send)
				ws.mu.Unlock()
				logrus.Debug("WebSocket client disconnected")
			} else {
				ws.mu.Unlock()
			}

		case message := <-ws.broadcast:
			ws.mu.RLock()
			for client := range ws.clients {
				select {
				case client.send <- message:
				default:
					// Client's send channel is full, close it
					close(client.send)
					delete(ws.clients, client)
				}
			}
			ws.mu.RUnlock()
		}
	}
}

func (ws *WSServer) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logrus.Errorf("WebSocket upgrade failed: %v", err)
		return
	}

	client := &WSClient{
		conn:   conn,
		send:   make(chan []byte, 256),
		server: ws,
	}

	ws.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *WSClient) readPump() {
	defer func() {
		c.server.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				logrus.Errorf("WebSocket error: %v", err)
			}
			break
		}
	}
}

func (c *WSClient) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.conn.WriteMessage(websocket.TextMessage, message)

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Broadcasting methods

func (ws *WSServer) BroadcastStatus(status Status) {
	msg := WSMessage{
		Type:      "status_update",
		Timestamp: time.Now(),
		Data:      status,
	}
	ws.broadcastMessage(msg)
}

func (ws *WSServer) BroadcastStats(stats Statistics) {
	msg := WSMessage{
		Type:      "stats_update",
		Timestamp: time.Now(),
		Data:      stats,
	}
	ws.broadcastMessage(msg)
}

func (ws *WSServer) BroadcastBlockedDomain(blocked BlockedDomain) {
	msg := WSMessage{
		Type:      "domain_blocked",
		Timestamp: time.Now(),
		Data:      blocked,
	}
	ws.broadcastMessage(msg)
}

func (ws *WSServer) broadcastMessage(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		logrus.Errorf("Failed to marshal WebSocket message: %v", err)
		return
	}

	select {
	case ws.broadcast <- data:
	default:
		// Broadcast channel is full, drop the message
		logrus.Warn("WebSocket broadcast channel full, dropping message")
	}
}
