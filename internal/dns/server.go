// Package dns implements a high-performance DNS server with domain blocking capabilities.
// It provides query handling, caching, and upstream forwarding while checking all queries
// against configured blocklists. The server supports both UDP and TCP protocols and
// integrates with the certificate proxy for transparent HTTPS filtering.
package dns

import (
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// Server is the DNS server
type Server struct {
	handler  *Handler
	servers  []*dns.Server
	mu       sync.Mutex
	started  bool
}

// NewServer creates a new DNS server
func NewServer(handler *Handler) *Server {
	return &Server{
		handler: handler,
	}
}

// Start starts the DNS server on the specified port
func (s *Server) Start(port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.started {
		return fmt.Errorf("server already started")
	}
	
	addr := fmt.Sprintf(":%d", port)
	
	// Create UDP server
	udpServer := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: s.handler,
	}
	
	// Create TCP server
	tcpServer := &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: s.handler,
	}
	
	s.servers = []*dns.Server{udpServer, tcpServer}
	
	// Start servers
	for _, server := range s.servers {
		go func(srv *dns.Server) {
			logrus.WithFields(logrus.Fields{
				"addr": srv.Addr,
				"net":  srv.Net,
			}).Info("Starting DNS server")
			
			if err := srv.ListenAndServe(); err != nil {
				logrus.WithError(err).Error("DNS server error")
			}
		}(server)
	}
	
	s.started = true
	return nil
}

// Stop stops the DNS server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if !s.started {
		return nil
	}
	
	for _, server := range s.servers {
		if err := server.Shutdown(); err != nil {
			logrus.WithError(err).Warn("Error shutting down DNS server")
		}
	}
	
	s.started = false
	return nil
}