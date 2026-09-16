// E3 probe: one write to Deno.args[0], which may or may not exist yet.
const path = Deno.args[0];
try {
  await Deno.writeTextFile(path, "e3\n");
  console.log(`OK wrote ${path}`);
} catch (e) {
  console.log("ERROR " + (e instanceof Error ? `${e.name}: ${e.message}` : String(e)));
}
