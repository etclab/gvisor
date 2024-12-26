package tlstcp

import (
	"crypto/tls"
	"io"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

type endpoint struct {
	tcpEP     tcpip.Endpoint
	tlsConfig *tls.Config
}

func (e *endpoint) Abort() {
	e.tcpEP.Abort()
}

func (e *endpoint) Bind(addr tcpip.FullAddress) (err tcpip.Error) {
	return e.tcpEP.Bind(addr)
}

func (e *endpoint) Close() {
	e.tcpEP.Close()
}

func (e *endpoint) Connect(addr tcpip.FullAddress) tcpip.Error {
	if err := e.tcpEP.Connect(addr); err != nil {
		return err
	}

	log.Infof("IZUMI: TCP connection succesful. TLS to be implemented")
	return nil
}

func (e *endpoint) Disconnect() tcpip.Error {
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
	return e.tcpEP.Listen(backlog)
}

func (e *endpoint) ModerateRecvBuf(copied int) {
	e.tcpEP.ModerateRecvBuf(copied)
}

func (e *endpoint) Read(dst io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	return e.tcpEP.Read(dst, opts)
}

func (e *endpoint) Readiness(mask waiter.EventMask) waiter.EventMask {
	return e.tcpEP.Readiness(mask)
}

func (e *endpoint) SetOwner(owner tcpip.PacketOwner) {
	e.tcpEP.SetOwner(owner)
}

func (e *endpoint) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
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
	return e.tcpEP.Write(p, opts)
}

// Accept implements tcpip.Endpoint.Accept
func (e *endpoint) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	newTCPEP, wq, err := e.tcpEP.Accept(peerAddr)
	if err != nil {
		return nil, nil, err
	}

	log.Infof("IZUMI: tlstcp Accept() triggered")

	return &endpoint{
		tcpEP:     newTCPEP,
		tlsConfig: e.tlsConfig,
	}, wq, nil

}
