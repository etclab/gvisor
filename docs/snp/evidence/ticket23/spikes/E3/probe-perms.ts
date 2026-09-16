// E3 probe: what Deno itself says the permission state of each of E1's rows is,
// under whatever flags this process was started with. Querying needs no
// permission of its own, so the answers are the flag parser's, not a side
// effect of trying the resource.
const q = (d: Deno.PermissionDescriptor) => {
  try {
    return Deno.permissions.querySync(d).state;
  } catch (e) {
    return "QUERY THREW: " + (e instanceof Error ? `${e.name}: ${e.message}` : String(e));
  }
};
const rows: [string, Deno.PermissionDescriptor][] = [
  ["net api.anthropic.com:443", { name: "net", host: "api.anthropic.com:443" }],
  ["net api.anthropic.com (any port)", { name: "net", host: "api.anthropic.com" }],
  ["net www.rfc-editor.org:443", { name: "net", host: "www.rfc-editor.org:443" }],
  ["net 160.79.104.10:443 (api's A record)", { name: "net", host: "160.79.104.10:443" }],
  ["net 104.18.20.81:443 (rfc-editor A record)", { name: "net", host: "104.18.20.81:443" }],
  ["net 127.0.0.53:53 (the resolver)", { name: "net", host: "127.0.0.53:53" }],
  ["read /etc/ssl/certs (the trust store)", { name: "read", path: "/etc/ssl/certs" }],
  ["read /etc/ssl/certs/ca-certificates.crt", { name: "read", path: "/etc/ssl/certs/ca-certificates.crt" }],
  ["read /etc/resolv.conf", { name: "read", path: "/etc/resolv.conf" }],
  ["read /etc/nsswitch.conf", { name: "read", path: "/etc/nsswitch.conf" }],
  ["write ./summary.txt", { name: "write", path: "./summary.txt" }],
  ["env ANTHROPIC_API_KEY", { name: "env", variable: "ANTHROPIC_API_KEY" }],
  ["env PATH", { name: "env", variable: "PATH" }],
  ["run /bin/true", { name: "run", command: "/bin/true" }],
  ["sys (uname, hostname, cpus…)", { name: "sys" }],
  ["ffi", { name: "ffi" }],
  ["import", { name: "import" }],
];
for (const [label, d] of rows) console.log(`${label} = ${q(d)}`);
