package tcp

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/izumi"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

const caCertPEM = `	
-----BEGIN CERTIFICATE-----
MIIDvTCCAqWgAwIBAgIUOZ3idWpUh9jERDajL+nlGaEjHsUwDQYJKoZIhvcNAQEL
BQAwbjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xDTALBgNVBAsMBFVuaXQxGjAYBgNVBAMM
EUlaVU1JIERldmVsb3BtZW50MB4XDTI0MTIwNDE0MzM0N1oXDTI1MTIwNDE0MzM0
N1owbjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5
MRUwEwYDVQQKDAxPcmdhbml6YXRpb24xDTALBgNVBAsMBFVuaXQxGjAYBgNVBAMM
EUlaVU1JIERldmVsb3BtZW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAp5BUIfBbpeygLAAc8Sb2d4w9hhUF0WeUJu0kIHqWIFMgOMDh/o9vsxYSor8r
QPlHy6wAh/guHJIYWI7wWIHkRA+NgavC+DaC5Gtkb/Fi+7uTl4deykJRplbPQmv3
Q3Gca+0u1ODI/3x3HBLDuseS7HW8PcyReIUR6Bst0Svbun7mQ33wiuwK6nD4BNJc
5QNb37cv0IpE3AWNGRNJIOThlDbng9bbMAy8VzW5ynCpuqqVwIsI7+xrlR9sbJFO
X/tmReo7OlXYaxPJ1cxy/gtivS+d/FVW7BTjUmZjmYD8wPySEtetmnpfS5nbO0mu
Ghz9p9E5wKGZAgw+a3Cd9HUKwQIDAQABo1MwUTAdBgNVHQ4EFgQUuJmvotNSgy0N
+9oSKB+8oO3oNAswHwYDVR0jBBgwFoAUuJmvotNSgy0N+9oSKB+8oO3oNAswDwYD
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAL+fKayEI/w8qty3zGF8Q
7IJtW5RKwh4y7YWiDk9JPnwzGOmT2fCmrVcAXT+WEZ+ecA2/uW7BZw/QneCDamXK
KXEqzqWgms0pVBWMmlwTmpNi4IAx45bT2RKH+JLQ+YWhKRM0PVYnfhauHFbUyJ3k
Xq2i1FuPLP93GZmMKRgb8GF2CIqnywG5xSRsb2NWedeR91WSjNF3bW6ppNPuGsRZ
KxB6P1nanYCDZhkBbyfLfGWXWnbBJKCJdnHAD+ZZX4AIg5/BP5kgGSKfU1Ybvmgx
R8dDYrpzOZBUxsVRqjDCs1BqbvlrvLYzakpGJ0OKG4GKBqb2RM16dzViYfOG98mK
LQ==
-----END CERTIFICATE-----`

const caKeyPEM = `
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnkFQh8Ful7KAs
ABzxJvZ3jD2GFQXRZ5Qm7SQgepYgUyA4wOH+j2+zFhKivytA+UfLrACH+C4ckhhY
jvBYgeRED42Bq8L4NoLka2Rv8WL7u5OXh17KQlGmVs9Ca/dDcZxr7S7U4Mj/fHcc
EsO6x5Lsdbw9zJF4hRHoGy3RK9u6fuZDffCK7ArqcPgE0lzlA1vfty/QikTcBY0Z
E0kg5OGUNueD1tswDLxXNbnKcKm6qpXAiwjv7GuVH2xskU5f+2ZF6js6VdhrE8nV
zHL+C2K9L538VVbsFONSZmOZgPzA/JIS162ael9Lmds7Sa4aHP2n0TnAoZkCDD5r
cJ30dQrBAgMBAAECggEAAlXjU4/WB+5AKDVYIe0HTaC7sjtff+b1Y1iSCLorLsog
UXSwKLMcM0Abnls/LKMl1twR28NN9ZrUYDJ9tXLZ5xhDNnRd382zE9DesP4NnVcE
s1mXGM8xXA3e6qLiguEP3Ufsg5HqkMet4YM2IVexDbrVTtxjtx0GFCLR9+XITLtc
kYagSlFSkjkKtsxIlc6nzkQIEoDmcRaDX/xPh1W50ZbDBj2Pi1aQK+O5DLBWD9vI
AideoKV1xFF5kdlfwJluxvTonN0Ka0s5MZl7/2zNVgShKPhuxSwyslMxk/NHk/ge
o6R8t11jSWFnHf83Xxmn1FEwSF5U9IvdlrAOeHIEgQKBgQDZjV5vMSi+kWpB+Bkl
b1KhgKFmOIaM6wnfUkz0ZL4GWRaQxsbGyLh7hk8oR4FrDKbyRvxwx0qzkQpxEa54
0Mh67+COhEAPcJmGhofHk9C1gHGOAXMiaA+d83itHRn0v4Vnw6qfOK/K2qo1ivkD
IBFPjszjTdAIdPZDI58QInpmgQKBgQDFLVom6xv5Jb0NZyDdb/TcE6DSaplYqqoy
Pb5ck4xtgGxSaVSKMRQQNHpRwrmBdRDMuKBwUHA+OVdt6jVl2r7yHFhYeaoj8zm3
O0185WaJtnhuLdZ5+NJL+yPquNHjXff/7i5YAOzbBDxoO0Enq/KSu3jsEj9SIdMZ
Nqfy3EcEQQKBgCEs57u5GWeGMVgCB4On6Efsn7BA6nPO2+CMYmPagQfiyggl5+Yk
cc2Ue7m+vcOfWE4V+SURnxinA5qegaa23/uvXOUe0c4I88CJ/2a16dvjzG1FV1Nl
3wvNNxffGjgyhJuAQSKquFQM6Gvl13dciodBVYlMMm83tt4iLn19ZIEBAoGARr02
kq/WoVQAt0ZAbDE2T55bHCJSUZUo6k1sdhoZT0+7jPVs9wcUg5vQJnUNyHwPQuMZ
7DFvk2NPEofsEFaiGopAx70eZTdlhW8pJZ3HY7CrFBwtziSOjePTxun3ovKbfp4c
0kXCs/CZG2vmvCzcIfhQMaF6RiUMbwdEycRtVgECgYBSIXzJQiviOl3DcmHthupZ
TCbtlQ6GNtThDhsn3dHk1mQs0U/j4tiHWF3MOL6fOFJOx/Wka415CWtkkxc1eYlS
YjGqTsHtXHltfZLFMeac7QI+21N6cC0ac0qlLB+ApP51gLq+HDKWqZVqfZa/dSav
gxYEMGY7dv7fC9jQhDwZXQ==
-----END PRIVATE KEY-----`

// SecureTunnel wraps a TCP endpoint to provide secure container-to-container communication.
type SecureTunnel struct {
	ep     tcpip.Endpoint
	stack  *stack.Stack
	config *tls.Config

	isServer   bool
	tlsConn    *tls.Conn
	remoteAddr tcpip.FullAddress
	localAddr  tcpip.FullAddress
	mu         sync.Mutex
	handshaken bool
	verifiedID string // Remote container ID after verification
	role       string
}

// NewSecureTunnel creates a new secure tunnel around a TCP endpoint.
func NewSecureTunnel(ep tcpip.Endpoint, stack *stack.Stack) (*SecureTunnel, tcpip.Error) {
	// For now using self-signed cert
	caCert, caKey, err := izumi.LoadCACertAndKey([]byte(caCertPEM), []byte(caKeyPEM))
	if err != nil {
		log.Infof("IZUMI: Error loading CA Cert files")
	}

	// Generate the containerID
	containerID := izumi.GenerateRandomContainerID(8)
	log.Infof("IZUMI: ContainerID - %s", containerID)
	cert, err := izumi.GenerateSelfSignedCert(caCert, caKey, containerID)
	if err != nil {
		return nil, &tcpip.ErrAborted{}
	}

	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM([]byte(caCertPEM)); !ok {
		log.Infof("IZUMI: failed to parse CA cert.")
		return nil, &tcpip.ErrAborted{}
	}

	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ClientAuth:         tls.RequireAndVerifyClientCert,
		RootCAs:            certPool, // Pool containing trusted CA certs
		ClientCAs:          certPool, // Same pool for client cert verification
		InsecureSkipVerify: false,
		ServerName:         containerID,
	}

	return &SecureTunnel{
		ep:     ep,
		stack:  stack,
		config: config,
		role:   "unknown",
	}, nil
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
	// return t.ep.Read(w, opts)
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

type netConnWrapper struct {
	ep tcpip.Endpoint
	wq waiter.Queue

	remoteAddr tcpip.FullAddress
	localAddr  tcpip.FullAddress
	role       string
}

func (w *netConnWrapper) Read(b []byte) (n int, err error) {
	log.Infof("IZUMI: Starting Read operation")
	writer := &SliceWriter{slice: b}

	res, readerr := w.ep.Read(writer, tcpip.ReadOptions{})
	if readerr != nil {
		if _, ok := readerr.(*tcpip.ErrWouldBlock); ok {
			log.Infof("IZUMI: Read would block, waiting for data...")
			// Setup wait for data
			entry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
			w.wq.EventRegister(&entry)
			defer w.wq.EventUnregister(&entry)

			<-notifyCh // Wait for data
			log.Infof("IZUMI: Received notification, retrying read...")

			// Try reading again
			res, readerr = w.ep.Read(writer, tcpip.ReadOptions{})
			if readerr != nil {
				log.Infof("IZUMI: Read error after wait: %v", readerr)
				return 0, fmt.Errorf("read error after wait: %v", readerr)
			}
		} else {
			log.Infof("IZUMI: Initial read error: %v", readerr)
			return 0, fmt.Errorf("read error: %v", readerr)
		}
	}

	log.Infof("IZUMI: Read successful - bytes read: %d, content: %x", res.Count, b[:res.Count])
	return res.Count, nil
}

func (w *netConnWrapper) Write(b []byte) (n int, err error) {
	log.Infof("IZUMI: Starting Write operation - length: %d, content: %s", len(b), string(b))
	r := bytes.NewReader(b)

	n64, writeerr := w.ep.Write(r, tcpip.WriteOptions{})
	if writeerr != nil {
		if _, ok := writeerr.(*tcpip.ErrWouldBlock); ok {
			log.Infof("IZUMI: Write would block, waiting...")
			// Setup wait for write
			entry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
			w.wq.EventRegister(&entry)
			defer w.wq.EventUnregister(&entry)

			<-notifyCh // Wait until writable
			log.Infof("IZUMI: Received write notification, retrying write...")

			// Try writing again
			n64, writeerr = w.ep.Write(r, tcpip.WriteOptions{})
			if writeerr != nil {
				log.Infof("IZUMI: Write error after wait: %v", writeerr)
				return 0, fmt.Errorf("write error after wait: %v", writeerr)
			}
		} else {
			log.Infof("IZUMI: Initial write error: %v", writeerr)
			return 0, fmt.Errorf("write error: %v", writeerr)
		}
	}

	log.Infof("IZUMI: Write successful - bytes written: %d", n64)
	return int(n64), nil
}

// SliceWriter implements io.Writer to write directly into a byte slice
type SliceWriter struct {
	slice []byte
}

func (s *SliceWriter) Write(b []byte) (n int, err error) {
	n = copy(s.slice, b)
	s.slice = s.slice[n:]
	return n, nil
}

func (w *netConnWrapper) Close() error {
	// Use ep.Close()
	w.ep.Close()
	return nil
}

func (w *netConnWrapper) SetDeadline(t time.Time) error {
	// Need to set both read and write deadlines
	return nil
}

func (w *netConnWrapper) SetReadDeadline(t time.Time) error {
	// Convert time.Time to tcpip.Time
	return nil
}

func (w *netConnWrapper) SetWriteDeadline(t time.Time) error {
	// Similar to SetReadDeadline
	return nil
}

func (w *netConnWrapper) LocalAddr() net.Addr {
	// Convert tcpip.FullAddress to net.Addr
	return nil
}

func (w *netConnWrapper) RemoteAddr() net.Addr {
	// Similar to LocalAddr
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
	// Set client role before connecting
	t.mu.Lock()
	t.isServer = false
	t.role = "client"
	t.mu.Unlock()
	log.Infof("IZUMI: Endpoint configured as client")
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
	// Set server role before delegating to underlying endpoint
	t.mu.Lock()
	t.isServer = true
	t.role = "server"
	t.mu.Unlock()
	log.Infof("IZUMI: Endpoint configured as server")
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
