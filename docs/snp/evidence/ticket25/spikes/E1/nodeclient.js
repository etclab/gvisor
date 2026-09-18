// E1a Node client (libuv): an UNMODIFIED-style Node program exercising the two
// code paths the sentry's FD-backed endpoint has to satisfy.
//
//   phase 1 (plain TCP): net.connect(port, host), write a line, read the reply,
//                        print localAddress/remoteAddress, then end().
//   phase 2 (TLS/HTTPS): https.get of an https URL (default agent).
//
// argv: node nodeclient.js <host> <port> <https url>
'use strict';
const net = require('net');
const https = require('https');

const [host, port, url] = process.argv.slice(2);
if (!host || !port || !url) {
  console.error('usage: node nodeclient.js <host> <port> <https url>');
  process.exit(2);
}

function phase1() {
  return new Promise((resolve) => {
    console.log('=== PHASE 1: plain TCP ===');
    const s = net.connect(Number(port), host);
    s.setTimeout(5000);
    s.on('connect', () => {
      console.log('PHASE1 connect: local=%s:%s remote=%s:%s family=%s',
        s.localAddress, s.localPort, s.remoteAddress, s.remotePort, s.remoteFamily);
      s.write('hello-from-node\n');
    });
    s.on('data', (d) => {
      console.log('PHASE1 read=%j', d.toString());
      s.end();
    });
    s.on('timeout', () => { console.log('PHASE1 timeout'); s.destroy(); });
    s.on('error', (e) => { console.log('PHASE1 error:', e.message); });
    s.on('close', (hadErr) => { console.log('PHASE1 close hadError=%s', hadErr); resolve(); });
  });
}

function phase2() {
  return new Promise((resolve) => {
    console.log('=== PHASE 2: https.get + TLS ===');
    // E1_DIAL_IP pins the phase-2 destination to an already-resolved address so
    // that fault-injection runs are not confounded by the resolver's own
    // sockets (DNS is out of scope for E1). Only the lookup step is replaced;
    // libuv still performs the identical socket()/connect()/poll sequence.
    const opts = {};
    if (process.env.E1_DIAL_IP) {
      const ip = process.env.E1_DIAL_IP;
      opts.lookup = (hostname, o, cb) => cb(null, ip, 4);
      console.log('PHASE2 dial pinned to %s', ip);
    }
    const req = https.get(url, opts, (res) => {
      console.log('PHASE2 status=%s', res.statusCode);
      let n = 0;
      res.on('data', (d) => { if (n === 0) console.log('PHASE2 bodyprefix=%j', d.slice(0, 64).toString()); n += d.length; });
      res.on('end', () => { console.log('PHASE2 OK bytes=%d', n); resolve(); });
    });
    req.on('error', (e) => { console.log('PHASE2 error:', e.message); resolve(); });
    req.setTimeout(15000, () => { console.log('PHASE2 timeout'); req.destroy(); });
  });
}

(async () => { await phase1(); await phase2(); })();
