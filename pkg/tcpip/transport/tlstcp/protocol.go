// Package tlstcp contains the implementation of the Izumi tlstcp transport
// protocols for use in secure communication.
package tlstcp

import (
	"crypto/tls"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/header/parse"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/raw"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	TLSTCP tcpip.TransportProtocolNumber = 201
)

type protocol struct {
	stack *stack.Stack
}

func (p *protocol) Close() {
	// Implement the Close method
	p.stack.Close()
}

func (*protocol) Number() tcpip.TransportProtocolNumber {
	return TLSTCP
}

func (p *protocol) Option(option tcpip.GettableTransportProtocolOption) tcpip.Error {
	return nil
}

func (*protocol) Parse(pkt *stack.PacketBuffer) bool {
	return parse.TCP(pkt)
}

func (*protocol) ParsePorts(v []byte) (src, dst uint16, err tcpip.Error) {
	h := header.TCP(v)
	return h.SourcePort(), h.DestinationPort(), nil
}

// Wait implements stack.TransportProtocol.Wait.
func (p *protocol) Wait() {
	p.stack.Wait()
}

// Pause implements stack.TransportProtocol.Pause.
func (p *protocol) Pause() {
	p.stack.Pause()
}

// Resume implements stack.TransportProtocol.Resume.
func (p *protocol) Resume() {
	p.stack.Resume()
}

// Restore implements stack.TransportProtocol.Restore.
func (p *protocol) Restore() {
	p.stack.Resume()
}

func (p *protocol) SetOption(option tcpip.SettableTransportProtocolOption) tcpip.Error {
	return nil
}

func (p *protocol) NewEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	log.Infof("IZUMI: new TLSTCP Endpoint created")
	tcpEP, _ := p.stack.NewEndpoint(tcp.ProtocolNumber, netProto, waiterQueue)
	tlstcpEP := &endpoint{
		tcpEP:     tcpEP,
		tlsConfig: &tls.Config{},
	}
	return tlstcpEP, nil

}

func (p *protocol) NewRawEndpoint(netProto tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	return raw.NewEndpoint(p.stack, netProto, header.TCPProtocolNumber, waiterQueue)
}

func (p *protocol) HandleUnknownDestinationPacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) stack.UnknownDestinationPacketDisposition {
	return stack.UnknownDestinationPacketHandled
}

func (*protocol) MinimumPacketSize() int {
	return header.TCPMinimumSize
}

func NewProtocol(s *stack.Stack) stack.TransportProtocol {
	log.Infof("IZUMI: new TLSTCP Protocol stack being initialized")
	return &protocol{stack: s}
}
