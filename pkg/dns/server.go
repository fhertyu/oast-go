// Package dns implements the OAST DNS collector: it answers A/AAAA/TXT/NS/MX/SOA
// queries against the configured OAST zones, resolves the token label from the
// query name and emits an Interaction event for each query.
package dns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/oast/oast/internal/config"
	"github.com/oast/oast/internal/domain"
	"github.com/oast/oast/internal/interaction"
	"github.com/oast/oast/internal/storage"
	"github.com/oast/oast/internal/token"
)

// Server runs the OAST DNS collector on UDP + TCP.
type Server struct {
	addr      string
	protocols []string
	domains   *domain.Manager
	bus       *interaction.Bus
	store     storage.Store
	log       *slog.Logger

	aaaaEnabled bool
	recordNoise bool

	udpSrv *dns.Server
	tcpSrv *dns.Server

	queries atomic.Uint64
}

// New returns a configured but not-yet-started Server.
func New(cfg config.DNSConfig, dm *domain.Manager, bus *interaction.Bus, store storage.Store, log *slog.Logger) *Server {
	protocols := cfg.Protocols
	if len(protocols) == 0 {
		protocols = []string{"udp", "tcp"}
	}
	return &Server{
		addr:        cfg.Listen,
		protocols:   protocols,
		domains:     dm,
		bus:         bus,
		store:       store,
		log:         log,
		aaaaEnabled: cfg.AAAAEnabled,
		recordNoise: cfg.RecordNoise,
	}
}

// Start launches the configured protocols. Listeners are pre-bound so a
// port conflict fails fast (returns an error) instead of being logged from a
// goroutine after startup "succeeded". Call Shutdown to stop.
func (s *Server) Start() error {
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	for _, p := range s.protocols {
		switch strings.ToLower(p) {
		case "udp":
			pc, err := net.ListenPacket("udp", s.addr)
			if err != nil {
				return fmt.Errorf("dns udp listen %s: %w", s.addr, err)
			}
			s.udpSrv = &dns.Server{
				PacketConn: pc, Addr: s.addr, Net: "udp", Handler: mux,
				NotifyStartedFunc: func() { s.log.Info("dns listening", "proto", "udp", "addr", s.addr) },
			}
			go func() {
				if err := s.udpSrv.ActivateAndServe(); err != nil {
					s.log.Error("dns udp serve ended", "err", err)
				}
			}()
		case "tcp":
			ln, err := net.Listen("tcp", s.addr)
			if err != nil {
				if s.udpSrv != nil { // roll back the already-bound UDP socket
					_ = s.udpSrv.Shutdown()
				}
				return fmt.Errorf("dns tcp listen %s: %w", s.addr, err)
			}
			s.tcpSrv = &dns.Server{
				Listener: ln, Addr: s.addr, Net: "tcp", Handler: mux,
				NotifyStartedFunc: func() { s.log.Info("dns listening", "proto", "tcp", "addr", s.addr) },
			}
			go func() {
				if err := s.tcpSrv.ActivateAndServe(); err != nil {
					s.log.Error("dns tcp serve ended", "err", err)
				}
			}()
		default:
			return fmt.Errorf("unsupported dns protocol %q (only udp/tcp)", p)
		}
	}
	return nil
}

// Shutdown stops both servers with a 5s budget.
func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if s.udpSrv != nil {
		_ = s.udpSrv.ShutdownContext(ctx)
	}
	if s.tcpSrv != nil {
		_ = s.tcpSrv.ShutdownContext(ctx)
	}
}

// Queries returns the total number of queries handled.
func (s *Server) Queries() uint64 { return s.queries.Load() }

func (s *Server) handle(w dns.ResponseWriter, msg *dns.Msg) {
	s.queries.Add(1)
	if len(msg.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}
	q := msg.Question[0]
	dom, prefix, ok := s.domains.Resolve(q.Name)
	if !ok {
		// Not one of our zones — REFUSED so upstream resolvers stop retrying.
		s.log.Debug("dns query not in our zones", "qname", q.Name)
		resp := new(dns.Msg)
		resp.SetRcode(msg, dns.RcodeRefused)
		_ = w.WriteMsg(resp)
		return
	}
	tokenValue, data := token.MatchToken(context.Background(), s.store, prefix)
	s.log.Debug("dns query", "qname", q.Name, "qtype", dns.TypeToString[q.Qtype],
		"token", tokenValue, "prefix", strings.Join(prefix, "."), "data", strings.Join(data, "."), "domain_id", dom.ID)
	if s.shouldRecord(q.Qtype) {
		s.record(w, q, dom, tokenValue, prefix)
	}

	resp := s.buildResponse(msg, q, dom)
	if err := w.WriteMsg(resp); err != nil {
		s.log.Error("dns write failed", "qname", q.Name, "err", err)
	}
}

// shouldRecord reports whether a query should be stored as an interaction.
// Resolver-meta noise (NS / SOA, plus AAAA while it is disabled) is skipped
// unless RecordNoise is enabled.
func (s *Server) shouldRecord(qtype uint16) bool {
	if s.recordNoise {
		return true
	}
	switch qtype {
	case dns.TypeNS, dns.TypeSOA:
		return false
	case dns.TypeAAAA:
		return s.aaaaEnabled
	}
	return true
}

// record enqueues a DNS Interaction event onto the bus.
func (s *Server) record(w dns.ResponseWriter, q dns.Question, dom *storage.Domain, tokenValue string, prefix []string) {
	srcIP, srcPort := splitHostPort(w.RemoteAddr().String())
	iv := storage.Interaction{
		Type:       storage.InteractionDNS,
		SubType:    dns.TypeToString[q.Qtype],
		Protocol:   protoOf(w.LocalAddr()),
		SrcIP:      srcIP,
		SrcPort:    srcPort,
		QName:      q.Name,
		QType:      dns.TypeToString[q.Qtype],
		TokenValue: tokenValue,
		Labels:     prefix,
		DomainID:   dom.ID,
	}
	if err := s.bus.Submit(iv); err != nil {
		s.log.Warn("dns bus submit dropped", "qname", q.Name, "err", err)
	}
}

// buildResponse constructs a reply according to the qtype and the domain's
// configured records. Unknown qtypes get NOTIMP.
func (s *Server) buildResponse(msg *dns.Msg, q dns.Question, dom *storage.Domain) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true
	resp.Compress = false

	ttl := uint32(60)

	switch q.Qtype {
	case dns.TypeA:
		if ip := net.ParseIP(dom.ResponseIP); ip != nil && ip.To4() != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip.To4(),
			})
		}
	case dns.TypeAAAA:
		if !s.aaaaEnabled {
			// IPv6 is off by default: NOTIMP makes recursive resolvers stop
			// asking instead of retrying an empty NOERROR answer.
			resp.SetRcode(msg, dns.RcodeNotImplemented)
			resp.Authoritative = false
			return resp
		}
	case dns.TypeTXT:
		if dom.TXTPayload != "" {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
				Txt: []string{dom.TXTPayload},
			})
		}
	case dns.TypeNS:
		zone := dns.Fqdn(dom.Name)
		for _, ns := range dom.NSRecords {
			resp.Ns = append(resp.Ns, &dns.NS{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
				Ns:  dns.Fqdn(ns),
			})
		}
		// glue A record for the queried name
		if ip := net.ParseIP(dom.ResponseIP); ip != nil && ip.To4() != nil {
			resp.Extra = append(resp.Extra, &dns.A{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip.To4(),
			})
		}
	case dns.TypeSOA:
		if dom.SOAPrimaryNS != "" {
			resp.Ns = append(resp.Ns, &dns.SOA{
				Hdr:     dns.RR_Header{Name: dns.Fqdn(dom.Name), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
				Ns:      dns.Fqdn(dom.SOAPrimaryNS),
				Mbox:    dns.Fqdn(dom.SOAEmail),
				Serial:  1,
				Refresh: 3600,
				Retry:   600,
				Expire:  86400,
				Minttl:  60,
			})
		}
	case dns.TypeMX:
		if len(dom.NSRecords) > 0 {
			resp.Answer = append(resp.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
				Preference: 10,
				Mx:         dns.Fqdn(dom.NSRecords[0]),
			})
		}
	case dns.TypeANY:
		// Minimal ANY response: A + TXT. Some clients use ANY to enumerate.
		if ip := net.ParseIP(dom.ResponseIP); ip != nil && ip.To4() != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   ip.To4(),
			})
		}
		if dom.TXTPayload != "" {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
				Txt: []string{dom.TXTPayload},
			})
		}
	default:
		resp.SetRcode(msg, dns.RcodeNotImplemented)
		resp.Authoritative = false
	}
	return resp
}

// splitHostPort returns the host and port part of an "ip:port" string.
// On error returns (addr, 0).
func splitHostPort(addr string) (string, int) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	p, _ := strconv.Atoi(port)
	return host, p
}

// protoOf returns "udp" or "tcp" based on the local address Network().
func protoOf(local net.Addr) string {
	if local == nil {
		return ""
	}
	switch local.Network() {
	case "udp", "udp4", "udp6":
		return "udp"
	case "tcp", "tcp4", "tcp6":
		return "tcp"
	}
	return local.Network()
}
