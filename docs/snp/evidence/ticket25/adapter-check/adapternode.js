// The Node workload of ticket 25's adapter check. Node resolves through glibc's
// getaddrinfo, so it exercises /etc/nsswitch.conf and libnss_dns rather than
// Go's own resolver — a second, independent witness that the sentry's responder
// answers what a stock resolver asks.
'use strict';
const https = require('https');
const net = require('net');
const dns = require('dns');

function allowedName() {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const req = https.get({host: 'www.rfc-editor.org', port: 443, path: '/', timeout: 60000, agent: false}, (res) => {
      let n = 0;
      res.on('data', (d) => { n += d.length; });
      res.on('end', () => {
        const tls = res.socket && res.socket.getProtocol ? res.socket.getProtocol() : 'none';
        console.log(`ALLOWED-NAME status=${res.statusCode} tls=${tls} bytes=${n} ms=${Date.now() - t0}`);
        resolve();
      });
    });
    req.on('timeout', () => { console.log('ALLOWED-NAME timeout'); req.destroy(); });
    req.on('error', (e) => { console.log(`ALLOWED-NAME error=${e.message} code=${e.code}`); resolve(); });
  });
}

function unknownName() {
  return new Promise((resolve) => {
    dns.lookup('example.com', (err, address) => {
      console.log(`UNKNOWN-NAME address=${address} error=${err ? err.code : 'none'}`);
      resolve();
    });
  });
}

function rawAddress() {
  return new Promise((resolve) => {
    const s = net.connect({host: '8.8.8.8', port: 443});
    s.setTimeout(20000, () => { console.log('RAW-ADDRESS timeout'); s.destroy(); resolve(); });
    s.on('connect', () => { console.log('RAW-ADDRESS connected, which it should not have'); s.destroy(); resolve(); });
    s.on('error', (e) => { console.log(`RAW-ADDRESS error=${e.message} code=${e.code} errno=${e.errno}`); resolve(); });
  });
}

(async () => {
  await allowedName();
  await unknownName();
  await rawAddress();
})();
