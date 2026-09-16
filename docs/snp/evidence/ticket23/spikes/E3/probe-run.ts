// E3 probe: the two-line --allow-run test. Deno.args[0] is the command as it
// is spelled to Deno.Command; the rest are its arguments.
const cmd = Deno.args[0];
try {
  const { code, stdout, stderr } = await new Deno.Command(cmd, { args: Deno.args.slice(1) }).output();
  console.log(`OK code=${code} stdout=${JSON.stringify(new TextDecoder().decode(stdout))} stderr=${JSON.stringify(new TextDecoder().decode(stderr))}`);
} catch (e) {
  console.log("ERROR " + (e instanceof Error ? `${e.name}: ${e.message}` : String(e)));
}
