package dns

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"dnshield/internal/config"
)

// Handler handles DNS queries
type Handler struct {
	blocker          *Blocker
	upstreams        []string
	blockIP          net.IP
	cache            *Cache
	captiveDetector  *CaptivePortalDetector
	statsCallback    func(query bool, blocked bool, cached bool)
	blockedCallback  func(domain, rule, clientIP string)
}

// NewHandler creates a new DNS handler
func NewHandler(blocker *Blocker, upstreams []string, blockIP string, captivePortalCfg *config.CaptivePortalConfig) *Handler {
	ip := net.ParseIP(blockIP)
	if ip == nil {
		ip = net.ParseIP("127.0.0.1")
	}

	return &Handler{
		blocker:         blocker,
		upstreams:       upstreams,
		blockIP:         ip,
		cache:           NewCache(10000, 1*time.Hour),
		captiveDetector: NewCaptivePortalDetector(captivePortalCfg),
	}
}

// SetStatsCallback sets the callback for statistics updates
func (h *Handler) SetStatsCallback(cb func(query bool, blocked bool, cached bool)) {
	h.statsCallback = cb
}

// SetBlockedCallback sets the callback for blocked domains
func (h *Handler) SetBlockedCallback(cb func(domain, rule, clientIP string)) {
	h.blockedCallback = cb
}

// ServeDNS implements the dns.Handler interface
func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = true

	// Handle only A and AAAA queries
	if len(r.Question) == 0 {
		w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(question.Name, ".")

	logrus.WithFields(logrus.Fields{
		"domain": domain,
		"type":   dns.TypeToString[question.Qtype],
	}).Debug("DNS query received")

	// Record query
	if h.statsCallback != nil {
		defer func() {
			h.statsCallback(true, false, false) // Will be updated based on result
		}()
	}

	// Record request for captive portal detection
	h.captiveDetector.RecordRequest(domain)

	// Check cache first
	if cached := h.cache.Get(domain, question.Qtype); cached != nil {
		m.Answer = append(m.Answer, cached...)
		w.WriteMsg(m)
		if h.statsCallback != nil {
			h.statsCallback(false, false, true) // Cached response
		}
		return
	}

	// Check if domain is blocked (unless in bypass mode)
	if !h.captiveDetector.IsInBypassMode() && h.blocker.IsBlocked(domain) {
		// Get user/group metadata for logging
		userEmail, groupName := h.blocker.GetMetadata()

		logFields := logrus.Fields{
			"domain": domain,
		}

		// Include user/group if they're set
		if userEmail != "" {
			logFields["user"] = userEmail
		}
		if groupName != "" {
			logFields["group"] = groupName
		}

		logrus.WithFields(logFields).Info("Blocked domain")

		// Get client IP
		clientIP := ""
		if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			clientIP = addr.IP.String()
		}

		if h.statsCallback != nil {
			h.statsCallback(false, true, false) // Blocked
		}
		if h.blockedCallback != nil {
			h.blockedCallback(domain, "blocklist", clientIP)
		}

		switch question.Qtype {
		case dns.TypeA:
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    10,
				},
				A: h.blockIP,
			}
			m.Answer = append(m.Answer, rr)
		case dns.TypeAAAA:
			// Return empty response for IPv6
			m.Rcode = dns.RcodeSuccess
		default:
			m.Rcode = dns.RcodeNotImplemented
		}

		w.WriteMsg(m)
		return
	}

	// Forward to upstream
	h.forwardToUpstream(w, r, m, domain, question.Qtype)
}

// forwardToUpstream forwards the query to upstream DNS servers
func (h *Handler) forwardToUpstream(w dns.ResponseWriter, r *dns.Msg, m *dns.Msg, domain string, qtype uint16) {
	c := new(dns.Client)
	c.Timeout = 5 * time.Second

	for _, upstream := range h.upstreams {
		// Add port if not specified
		if !strings.Contains(upstream, ":") {
			upstream += ":53"
		}

		resp, _, err := c.Exchange(r, upstream)
		if err != nil {
			logrus.WithError(err).WithField("upstream", upstream).Warn("Failed to query upstream")
			continue
		}

		// Cache successful responses
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			h.cache.Set(domain, qtype, resp.Answer)
		}

		w.WriteMsg(resp)
		return
	}

	// All upstreams failed
	m.Rcode = dns.RcodeServerFailure
	w.WriteMsg(m)
}

// GetCaptivePortalDetector returns the captive portal detector
func (h *Handler) GetCaptivePortalDetector() *CaptivePortalDetector {
	return h.captiveDetector
}
