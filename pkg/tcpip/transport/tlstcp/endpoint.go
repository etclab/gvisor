package tlstcp

import (
	"crypto/tls"
	"io"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/waiter"
)

type endpoint struct {
	tcpEP         tcpip.Endpoint
	tlsConfig     *tls.Config
	tlsState      tls.ConnectionState
	tlsConn       *tls.Conn
	isHandshaking bool
	handshakeErr  error
	isServer      bool
}

func (e *endpoint) Abort() {
	localaddr, _ := e.tcpEP.GetLocalAddress()
	log.Infof("IZUMI: Abort() of tlstcp triggered in %+v", localaddr.Addr)
	e.tcpEP.Abort()
}

func (e *endpoint) Bind(addr tcpip.FullAddress) (err tcpip.Error) {
	return e.tcpEP.Bind(addr)
}

func (e *endpoint) Close() {
	localaddr, _ := e.tcpEP.GetLocalAddress()
	log.Infof("IZUMI: Close() of tlstcp triggered in %+v", localaddr.Addr)
	e.tcpEP.Close()
}

func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	e.isServer = false
	e.isHandshaking = true
	log.Infof("IZUMI: TLSTCP - Client starting Handshake")
	if err := e.tcpEP.Connect(addr); err != nil {
		return err
	}

	var wq *waiter.Queue
	return e.startHandshake(wq)
}

func (e *endpoint) Disconnect() tcpip.Error {
	localaddr, _ := e.tcpEP.GetLocalAddress()
	log.Infof("IZUMI: Disconnect() of tlstcp triggered in %+v", localaddr.Addr)
	return e.tcpEP.Disconnect()
}

func (e *endpoint) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	return e.tcpEP.GetLocalAddress()
}

func (e *endpoint) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	return e.tcpEP.GetRemoteAddress()
}

func (e *endpoint) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	return e.tcpEP.GetSockOpt(opt)
}

func (e *endpoint) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	return e.tcpEP.GetSockOptInt(opt)
}

func (e *endpoint) Info() tcpip.EndpointInfo {
	return e.tcpEP.Info()
}

func (e *endpoint) LastError() tcpip.Error {
	return e.tcpEP.LastError()
}

func (e *endpoint) Listen(backlog int) tcpip.Error {
	e.isServer = true
	log.Infof("IZUMI: TLSTCP - Server listening")
	return e.tcpEP.Listen(backlog)
}

func (e *endpoint) ModerateRecvBuf(copied int) {
	e.tcpEP.ModerateRecvBuf(copied)
}

func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	return e.tcpEP.Readiness(mask)
}

func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.tcpEP.SetOwner(owner)
}

func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	log.Infof("IZUMI: TLSTCP - Entered SetSockOpt()")
	return e.tcpEP.SetSockOpt(opt)
}

func (e *endpoint) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return e.tcpEP.SetSockOptInt(opt, v)
}

func (e *endpoint) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	return e.tcpEP.Shutdown(flags)
}

func (e *endpoint) SocketOptions() *tcpip.SocketOptions {
	return e.tcpEP.SocketOptions()
}

func (e *endpoint) State() uint32 {
	return e.tcpEP.State()
}

func (e *endpoint) Stats() tcpip.EndpointStats {
	return e.tcpEP.Stats()
}

func (e *endpoint) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	log.Infof("IZUMI: Write START")
	return e.tcpEP.Write(p, opts)
}

func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	log.Infof("IZUMI: Read START")
	return e.tcpEP.Read(dst, opts)
}

// Accept implements tcpip.Endpoint.Accept
func (e *endpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	log.Infof("IZUMI: Accept() of tlstcp triggered")

	newTCPEP, wq, err := e.tcpEP.Accept(peerAddr)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("IZUMI: Accept() - newTCPEP instatiated.")

	e.tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	newEP := &endpoint{
		tcpEP:     newTCPEP,
		tlsConfig: e.tlsConfig,
		isServer:  true,
	}

	log.Infof("IZUMI: new Endpoint created by Accept()")
	err = newEP.startHandshake(wq)
	log.Infof("IZUMI: new Endpoint handshake done in Accept()")
	return newEP, wq, err
}

func (e *endpoint) startHandshake(wq *waiter.Queue) tcpip.Error {
	log.Infof("IZUMI: TLSTCP: startHandshake() triggered")

	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Wrap the Endpoint using gonet.NewTCPConn.
	tcpConn := gonet.NewTCPConn(wq, e.tcpEP)
	tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	var conn *tls.Conn
	if e.isServer {
		log.Infof("IZUMI: TLSTCP: Ready to create tls.Server")
		conn = tls.Server(tcpConn, config)
	} else {
		log.Infof("IZUMI: TLSTCP: Ready to create tls.Client")
		conn = tls.Client(tcpConn, config)
	}

	if err := conn.Handshake(); err != nil {
		log.Infof("IZUMI: TLSTCP: Handshake Failed: %+v", err)
		return &tcpip.ErrConnectionRefused{}
	}

	e.tlsConn = conn
	e.isHandshaking = false
	log.Infof("IZUMI: TLSTCP: Handshake Completed")
	return nil
}
