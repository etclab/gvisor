// E3 probe: one fetch of Deno.args[0], with the exact error text if it is
// refused. The refusal is caught, as the agent's fetch_url tool catches it.
// The cause is printed too: a TypeError from fetch says nothing on its own,
// and the whole of this probe is which sentence arrives.
const url = Deno.args[0];
try {
  const r = await fetch(url);
  console.log(`OK status=${r.status} bytes=${(await r.arrayBuffer()).byteLength}`);
} catch (e) {
  console.log("ERROR " + (e instanceof Error ? `${e.name}: ${e.message}` : String(e)));
  let c = (e as Error)?.cause;
  for (let depth = 1; c && depth < 6; depth++) {
    console.log(`  cause ${depth}: ` + (c instanceof Error ? `${c.name}: ${c.message}` : String(c)));
    c = (c as Error)?.cause;
  }
}
