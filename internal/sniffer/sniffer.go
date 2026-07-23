// Package sniffer captures DNS traffic on the hotspot interface using gopacket/pcap,
// parses queries and responses, and feeds resolved (IP, domain) pairs into the classifier.
package sniffer

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"hotspotd/internal/classify"
)

// dnsEvent represents a parsed DNS event for the consumer goroutine.
type dnsEvent struct {
	// For DNS responses: the resolved IPs and the queried domain.
	ResolvedIPs []string
	Domain      string
	// For DNS queries: the source client IP and queried name.
	SourceIP   string
	QueriedName string
	IsResponse bool
}

// Stats holds sniffer counters for visibility reporting.
type Stats struct {
	DNSQueriesSeen   int64
	DNSResponsesSeen int64
	DoHEventsSeen    int64
}

// DomainRecord tracks a DNS domain seen on the network.
type DomainRecord struct {
	Domain   string
	IPs      []string
	App      string // classified app name, or empty
	LastSeen time.Time
	QueryCnt int
}

// Sniffer captures DNS traffic and feeds it into the classifier.
type Sniffer struct {
	iface      string
	subnet     string
	classifier *classify.Classifier

	// dohResolverSet is a set of known DoH resolver IPs.
	dohResolverSet map[string]bool

	// Atomic counters for stats.
	dnsQueries   atomic.Int64
	dnsResponses atomic.Int64
	dohEvents    atomic.Int64

	// All domains seen, keyed by domain name.
	domainMu  sync.Mutex
	domains   map[string]*DomainRecord
	domainGen atomic.Int64
}

// New creates a new Sniffer bound to the given interface.
func New(iface, subnet string, classifier *classify.Classifier, dohResolverSet map[string]bool) *Sniffer {
	return &Sniffer{
		iface:          iface,
		subnet:         subnet,
		classifier:     classifier,
		dohResolverSet: dohResolverSet,
		domains:        make(map[string]*DomainRecord),
	}
}

// GetStats returns a snapshot of sniffer counters.
func (s *Sniffer) GetStats() Stats {
	return Stats{
		DNSQueriesSeen:   s.dnsQueries.Load(),
		DNSResponsesSeen: s.dnsResponses.Load(),
		DoHEventsSeen:    s.dohEvents.Load(),
	}
}

// trackDomain records a DNS response for domain tracking.
func (s *Sniffer) trackDomain(domain string, ips []string, app string) {
	s.domainMu.Lock()
	defer s.domainMu.Unlock()

	rec, exists := s.domains[domain]
	if !exists {
		rec = &DomainRecord{Domain: domain}
		s.domains[domain] = rec
		s.domainGen.Add(1)
	}
	rec.IPs = ips
	rec.LastSeen = time.Now()
	rec.QueryCnt++
	if app != "" {
		rec.App = app
	}
}

// GetDomains returns a snapshot of all tracked domains.
func (s *Sniffer) GetDomains() []DomainRecord {
	s.domainMu.Lock()
	defer s.domainMu.Unlock()
	out := make([]DomainRecord, 0, len(s.domains))
	for _, rec := range s.domains {
		out = append(out, *rec)
	}
	return out
}

// DomainGeneration returns a counter that increments when new domains are seen.
func (s *Sniffer) DomainGeneration() int64 {
	return s.domainGen.Load()
}

// Start begins capturing DNS traffic. It blocks until ctx is cancelled.
// Runs the capture loop in a child goroutine and processes events in the caller goroutine.
func (s *Sniffer) Start(ctx context.Context) error {
	log.Printf("📡 [SYSTEM] Listening on interface: %s (Subnet: %s)", s.iface, s.subnet)

	// Build BPF filter: capture DNS (UDP port 53) traffic on the subnet,
	// plus TCP 443 to known DoH resolvers for detection.
	bpfFilter := s.buildBPFFilter()

	handle, err := pcap.OpenLive(s.iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap on %s: %w", s.iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return fmt.Errorf("failed to set BPF filter: %w", err)
	}

	// Buffered channel to decouple capture from processing.
	// Never let the capture loop block — if the channel is full, we drop events.
	events := make(chan dnsEvent, 1024)

	// Capture goroutine.
	go func() {
		defer close(events)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.NoCopy = true

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			packet, err := packetSource.NextPacket()
			if err != nil {
				// Check if context was cancelled.
				select {
				case <-ctx.Done():
					return
				default:
				}
				// Transient error — log and continue.
				log.Printf("[WARN] Packet capture error: %v", err)
				continue
			}

			s.processPacket(packet, events)
		}
	}()

	// Consumer loop: process DNS events and feed into classifier.
	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			if evt.IsResponse {
				s.dnsResponses.Add(1)
				var classifiedApp string
				for _, ip := range evt.ResolvedIPs {
					s.classifier.Update(ip, evt.Domain)
					if classifiedApp == "" {
						if app, _, ok := s.classifier.Lookup(ip); ok {
							classifiedApp = app
						}
					}
				}
				s.trackDomain(evt.Domain, evt.ResolvedIPs, classifiedApp)
			} else {
				s.dnsQueries.Add(1)
			}
		}
	}
}

// processPacket decodes a captured packet and sends DNS events to the channel.
func (s *Sniffer) processPacket(packet gopacket.Packet, events chan<- dnsEvent) {
	// Check for DoH traffic (TCP:443 to known resolver IPs).
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.DstPort == 443 || tcp.SrcPort == 443 {
			if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
				ip := ipLayer.(*layers.IPv4)
				dstIP := ip.DstIP.String()
				if s.dohResolverSet[dstIP] {
					s.dohEvents.Add(1)
					// Don't silently drop — this is counted and reported by Module 4.
				}
			}
		}
		return // TCP traffic — no DNS to parse here.
	}

	// Parse DNS layer.
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)

	// Extract the queried domain name from questions.
	var domain string
	if len(dns.Questions) > 0 {
		domain = string(dns.Questions[0].Name)
	}
	if domain == "" {
		return
	}

	// Get source IP for query attribution.
	var srcIP string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		srcIP = ipLayer.(*layers.IPv4).SrcIP.String()
	}

	if dns.QR { // This is a DNS response.
		var resolvedIPs []string
		for _, answer := range dns.Answers {
			switch answer.Type {
			case layers.DNSTypeA:
				if answer.IP != nil {
					resolvedIPs = append(resolvedIPs, answer.IP.String())
				}
			case layers.DNSTypeAAAA:
				if answer.IP != nil {
					resolvedIPs = append(resolvedIPs, answer.IP.String())
				}
			}
		}
		if len(resolvedIPs) > 0 {
			select {
			case events <- dnsEvent{
				ResolvedIPs: resolvedIPs,
				Domain:      domain,
				IsResponse:  true,
			}:
			default:
				// Channel full — drop event rather than blocking capture.
				log.Printf("[WARN] DNS event channel full, dropping response for %s", domain)
			}
		}
	} else { // This is a DNS query.
		select {
		case events <- dnsEvent{
			SourceIP:    srcIP,
			QueriedName: domain,
			IsResponse:  false,
		}:
		default:
			// Channel full — drop event rather than blocking capture.
		}
	}
}

// buildBPFFilter constructs the BPF filter string.
// Captures: UDP port 53 (DNS) on the subnet + TCP port 443 to known DoH resolvers.
func (s *Sniffer) buildBPFFilter() string {
	parts := []string{}

	// DNS traffic on the subnet.
	if s.subnet != "" {
		_, ipNet, err := net.ParseCIDR(s.subnet)
		if err == nil {
			parts = append(parts, fmt.Sprintf("(udp port 53 and net %s)", ipNet.String()))
		} else {
			// Fallback: just capture all DNS.
			parts = append(parts, "(udp port 53)")
		}
	} else {
		parts = append(parts, "(udp port 53)")
	}

	// DoH detection: TCP 443 to known resolver IPs.
	if len(s.dohResolverSet) > 0 {
		dohParts := []string{}
		for ip := range s.dohResolverSet {
			dohParts = append(dohParts, fmt.Sprintf("dst host %s", ip))
		}
		parts = append(parts, fmt.Sprintf("(tcp port 443 and (%s))", strings.Join(dohParts, " or ")))
	}

	return strings.Join(parts, " or ")
}
