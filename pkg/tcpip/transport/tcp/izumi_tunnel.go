package tcp

import (
	"crypto/tls"
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SecureTunnel wraps a TCP endpoint to provide secure container-to-container communication.
type SecureTunnel struct {
	ep     tcpip.Endpoint
	stack  *stack.Stack
	config *tls.Config

	mu         sync.Mutex
	handshaken bool
	verifiedID string // Remote container ID after verification
}

// NewSecureTunnel creates a new secure tunnel around a TCP endpoint.
func NewSecureTunnel(ep tcpip.Endpoint, stack *stack.Stack) (*SecureTunnel, tcpip.Error) {
	// For now using self-signed cert - will be replaced with DICE
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, &tcpip.ErrAborted{}
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// TODO: Replace with proper DICE verification
		InsecureSkipVerify: true,
	}

	return &SecureTunnel{
		ep:     ep,
		stack:  stack,
		config: config,
	}, nil
}

// Helper function to generate a temporary certificate
func generateSelfSignedCert() (tls.Certificate, error) {
	// TODO: Generate a basic self-signed cert
	// This is just for PoC, real implementation would use DICE chain
	return tls.Certificate{}, nil
}

// Write implements tcpip.Endpoint.Write
func (t *SecureTunnel) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	t.mu.Lock()
	needHandshake := !t.handshaken
	t.mu.Unlock()

	if needHandshake {
		if err := t.doHandshake(); err != nil {
			return 0, err
		}
	}

	// Pass through to underlying endpoint for now
	// TODO: Add encryption 
	return t.ep.Write(p, opts)
}

// Read implements tcpip.Endpoint.Read
func (t *SecureTunnel) Read(w io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	t.mu.Lock()
	needHandshake := !t.handshaken
	t.mu.Unlock()

	if needHandshake {
		if err := t.doHandshake(); err != nil {
			return tcpip.ReadResult{}, err
		}
	}

	// Pass through to underlying endpoint for now
	// TODO: Add decryption
	return t.ep.Read(w, opts)
}

func (t *SecureTunnel) doHandshake() tcpip.Error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.handshaken {
		return nil
	}

	// TODO: Implement mutual TLS handshake with DICE attestation
	// For now just marking as handshaken
	log.Infof("IZUMI: TLS handshake assumed to be done")
	t.handshaken = true
	return nil
}

// Following methods delegate to underlying endpoint
func (t *SecureTunnel) Close() {
	t.ep.Close()
}

func (t *SecureTunnel) Abort() {
	t.ep.Abort()
}

func (t *SecureTunnel) Connect(addr tcpip.FullAddress) tcpip.Error {
	return t.ep.Connect(addr)
}

func (t *SecureTunnel) Bind(addr tcpip.FullAddress) tcpip.Error {
	return t.ep.Bind(addr)
}

func (t *SecureTunnel) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	return t.ep.GetLocalAddress()
}

func (t *SecureTunnel) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	return t.ep.GetRemoteAddress()
}

func (t *SecureTunnel) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	return t.ep.Shutdown(flags)
}

func (t *SecureTunnel) Listen(backlog int) tcpip.Error {
	return t.ep.Listen(backlog)
}

func (t *SecureTunnel) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return t.ep.Accept(peerAddr)
}

func (t *SecureTunnel) Readiness(mask waiter.EventMask) waiter.EventMask {
	return t.ep.Readiness(mask)
}

func (t *SecureTunnel) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return t.ep.SetSockOpt(opt)
}

func (t *SecureTunnel) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return t.ep.SetSockOptInt(opt, v)
}

func (t *SecureTunnel) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	return t.ep.GetSockOptInt(opt)
}

func (t *SecureTunnel) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	return t.ep.GetSockOpt(opt)
}

func (t *SecureTunnel) Disconnect() tcpip.Error {
	return t.ep.Disconnect()
}

func (t *SecureTunnel) State() uint32 {
	return t.ep.State()
}

func (t *SecureTunnel) ModerateRecvBuf(copied int) {
	t.ep.ModerateRecvBuf(copied)
}

func (t *SecureTunnel) Info() tcpip.EndpointInfo {
	return t.ep.Info()
}

func (t *SecureTunnel) Stats() tcpip.EndpointStats {
	return t.ep.Stats()
}

func (t *SecureTunnel) LastError() tcpip.Error {
	return t.ep.LastError()
}

func (t *SecureTunnel) SocketOptions() *tcpip.SocketOptions {
	return t.ep.SocketOptions()
}

func (t *SecureTunnel) SetOwner(owner tcpip.PacketOwner) {
	t.ep.SetOwner(owner)
}
