// Ticket 25, spike E1b. An UNMODIFIED-shaped Node client (node v18.19.1, libuv).
// Same two steps as the Go client: a plain TCP round trip against the helper's
// echo server, then a real HTTPS GET. Both names come from /etc/hosts and point
// at the synthetic 100.64.0.0/10 addresses the sentry intercepts.
'use strict';
const net = require('net');
const https = require('https');

function step1() {
  return new Promise((resolve) => {
    console.log('\n== net.connect tcp echo.spike.test:7777');
    const t0 = Date.now();
    const s = net.connect({host: 'echo.spike.test', port: 7777});
    let got = Buffer.alloc(0);
    let bulkTarget = 0;
    const big = Buffer.alloc(256 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    let phase = 'hello';
    s.setTimeout(20000, () => { console.log('   TIMEOUT'); s.destroy(); resolve(); });
    s.on('connect', () => {
      console.log(`   connect:     ok (${Date.now() - t0} ms)`);
      console.log(`   localAddress:  ${s.localAddress}:${s.localPort}`);
      console.log(`   remoteAddress: ${s.remoteAddress}:${s.remotePort}`);
      s.write('hello from node\n');
    });
    s.on('data', (d) => {
      got = Buffer.concat([got, d]);
      if (phase === 'hello' && got.length >= 16) {
        console.log(`   echo:        ${JSON.stringify(got.toString())} (${Date.now() - t0} ms)`);
        phase = 'bulk';
        got = Buffer.alloc(0);
        bulkTarget = big.length;
        const t1 = Date.now();
        s.once('bulkdone', () => {
          console.log(`   bulk:        wrote ${big.length}, echoed ${bulkTarget} back in ${Date.now() - t1} ms`);
          console.log('   end():       half-closing (shutdown SHUT_WR)');
          s.end();
        });
        s.write(big);
      } else if (phase === 'bulk' && got.length >= bulkTarget) {
        phase = 'done';
        s.emit('bulkdone');
      }
    });
    s.on('end', () => { console.log('   end event:   peer sent FIN (EOF seen)'); });
    s.on('error', (e) => { console.log(`   ERROR:       ${e.message} (${e.code}, errno ${e.errno})`); resolve(); });
    s.on('close', (hadErr) => { console.log(`   close:       hadError=${hadErr}`); resolve(); });
  });
}

function step2() {
  return new Promise((resolve) => {
    console.log('\n== https.get https://www.rfc-editor.org/');
    const t0 = Date.now();
    const req = https.get({host: 'www.rfc-editor.org', port: 443, path: '/', timeout: 30000, agent: false}, (res) => {
      console.log(`   status:      ${res.statusCode} ${res.statusMessage} in ${Date.now() - t0} ms`);
      console.log(`   httpVersion: ${res.httpVersion}`);
      const cert = res.socket.getPeerCertificate ? res.socket.getPeerCertificate() : null;
      if (cert && cert.subject) console.log(`   cert CN:     ${JSON.stringify(cert.subject.CN)}`);
      if (res.socket.getProtocol) console.log(`   tls:         ${res.socket.getProtocol()}`);
      let n = 0, first = null;
      res.on('data', (d) => { if (first === null) first = d.slice(0, 120).toString(); n += d.length; });
      res.on('end', () => {
        console.log(`   body:        ${n} bytes, first 120: ${JSON.stringify(first)}`);
        resolve();
      });
    });
    req.on('timeout', () => { console.log('   TIMEOUT'); req.destroy(); resolve(); });
    req.on('error', (e) => { console.log(`   ERROR:       ${e.message} (${e.code}, errno ${e.errno})`); resolve(); });
  });
}

(async () => {
  console.log(`nodeclient: node ${process.version} pid ${process.pid}`);
  await step1();
  await step2();
  console.log('\nnodeclient: done');
  process.exit(0);
})();
