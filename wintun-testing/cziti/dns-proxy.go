package cziti

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"time"
	"wintun-testing/cziti/windns"
)

func processDNSquery(packet []byte, p *net.UDPAddr, s *net.UDPConn) {
	q := &dns.Msg{}
	if err := q.Unpack(packet); err != nil {
		fmt.Println("ERROR", err)
		return
	}

	msg := dns.Msg{}
	msg.SetReply(q)
	msg.RecursionAvailable = false
	msg.Authoritative = false
	msg.Rcode = dns.RcodeRefused

	query := q.Question[0]
	var ip net.IP
	// fmt.Printf("query: Type(%d) name(%s)\n", query.Qtype, query.Name)

	ip = DNS.Resolve(query.Name)

	// never proxy hostnames that we know about regardless of type
	if ip != nil {
		fmt.Println("resolved ", query.Name, ip)

		var answer *dns.A
		if query.Qtype == dns.TypeA && len(ip.To4()) == net.IPv4len {
			answer = &dns.A{
				Hdr: dns.RR_Header{Name: query.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			}
		} else if query.Qtype == dns.TypeAAAA {
			answer = &dns.A{
				Hdr: dns.RR_Header{Name: query.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				A:   ip.To16(),
			}
		}

		if answer != nil {
			msg.Authoritative = true
			msg.Rcode = dns.RcodeSuccess

			msg.Answer = append(msg.Answer, answer)
		}

		repB, err := msg.Pack()
		if err == nil {
			_, _, err = s.WriteMsgUDP(repB, nil, p)
		}
		if err != nil {
			fmt.Println("dns error", err)
		}
	} else {
		// fmt.Println("proxying ", dns.Type(query.Qtype), query.Name, q.Id, " for ", p)
		proxyDNS(q, p, s)
	}
}

type dnsreq struct {
	q []byte
	s *net.UDPConn
	p *net.UDPAddr
}

func runDNSserver(dnsBind []net.IP) {
	dnsServers := windns.GetUpstreamDNS()
	go runDNSproxy(dnsServers)

	reqch := make(chan dnsreq)

	for _, bindAddr := range dnsBind {
		go runListener(bindAddr, 53, reqch)
	}

	windns.ReplaceDNS(dnsBind)

	for req := range reqch {
		processDNSquery(req.q, req.p, req.s)
	}
}

func runListener(ip net.IP, port int, reqch chan dnsreq) {
	laddr := &net.UDPAddr{
		IP:   ip,
		Port: 53,
		Zone: "",
	}

	network := "udp6"
	if len(ip.To4()) == net.IPv4len {
		network = "udp4"
	}

	server, err := net.ListenUDP(network, laddr)
	if err != nil {
		panic(err)
	}

	// oob := make([]byte, 1024)
	for {
		b := make([]byte, 1024)
		nb, _, _, peer, err := server.ReadMsgUDP(b, nil)
		if err != nil {
			panic(err)
		}
		reqch <- dnsreq{
			q: b[:nb],
			s: server,
			p: peer,
		}
	}
}

/*******************************************************************/
type proxiedReq struct {
	req  *dns.Msg
	peer *net.UDPAddr
	s    *net.UDPConn
	exp  time.Time
}

var proxiedRequests chan *proxiedReq

func proxyDNS(req *dns.Msg, peer *net.UDPAddr, serv *net.UDPConn) {
	proxiedRequests <- &proxiedReq{
		req:  req,
		peer: peer,
		s:    serv,
		exp:  time.Now().Add(30 * time.Second),
	}
}

func runDNSproxy(dnsServers []string) {
	var dnsUpstreams []*net.UDPConn
	for _, s := range dnsServers {
		sAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:53", s))
		if err != nil {
			fmt.Println("skipping upstream", s, err.Error())
		} else {
			conn, err := net.DialUDP("udp", nil, sAddr)
			if err != nil {
				fmt.Println("skipping upstream", s, err.Error())
			}
			dnsUpstreams = append(dnsUpstreams, conn)
		}
	}

	proxiedRequests = make(chan *proxiedReq, 16)
	respChan := make(chan []byte, 16)

	for _, proxy := range dnsUpstreams {
		go func() {
			for {
				resp := make([]byte, 1024)
				n, err := proxy.Read(resp)
				if err != nil {
					fmt.Println("error receiving from ", proxy.RemoteAddr(), err)
				} else {
					respChan <- resp[:n]
				}
			}
		}()
	}

	reqs := make(map[uint32]*proxiedReq)

	for {
		select {
		case pr := <-proxiedRequests:
			id := (uint32(pr.req.Id) << 16) | uint32(pr.req.Question[0].Qtype)
			reqs[id] = pr
			b, _ := pr.req.Pack()
			// fmt.Println("sending proxy req", id, dns.Type(pr.req.Question[0].Qtype), pr.req.Question[0].Name)
			for _, proxy := range dnsUpstreams {
				// fmt.Println("sending proxy req", dns.Type(pr.req.Question[0].Qtype), pr.req.Question[0].Name, proxy.RemoteAddr())
				if _, err := proxy.Write(b); err != nil {
					fmt.Println("failed to proxy DNS to ", proxy)
				}
			}

		case rep := <-respChan:
			reply := dns.Msg{}
			if err := reply.Unpack(rep); err == nil {
				id := (uint32(reply.Id) << 16) | uint32(reply.Question[0].Qtype)
				req, found := reqs[id]
				if found {
					delete(reqs, id)
					// fmt.Printf("proxy resolved %+v for %v\n\n", reply, req.peer)
					req.s.WriteMsgUDP(rep, nil, req.peer)
				} else {
					fmt.Println("matching request was not found for ",
						dns.Type(reply.Question[0].Qtype), reply.Question[0].Name)
				}
			}
		case <-time.After(time.Minute):
			// cleanup requests we didn't get answers for
			now := time.Now()
			for k, r := range reqs {
				if now.After(r.exp) {
					fmt.Println("req expired", dns.Type(r.req.Question[0].Qtype), r.req.Question[0].Name)
					delete(reqs, k)
				}
			}
		}
	}
}
