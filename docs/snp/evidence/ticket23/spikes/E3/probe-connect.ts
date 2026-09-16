// E3 probe: a raw TCP connect to Deno.args[0]:Deno.args[1], which is the one
// call whose permission check is against an address and not a name.
try {
  const c = await Deno.connect({ hostname: Deno.args[0], port: Number(Deno.args[1]) });
  console.log(`OK connected to ${Deno.args[0]}:${Deno.args[1]}`);
  c.close();
} catch (e) {
  console.log("ERROR " + (e instanceof Error ? `${e.name}: ${e.message}` : String(e)));
}
