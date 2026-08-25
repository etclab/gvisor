/*
 * tunneld-placeholder: the binary the measured image embeds until tunneld
 * exists (ticket 14 rebuilds the image with TUNNELD=<real binary>).
 *
 * It does exactly what a boot test needs and nothing a tunnel needs: it
 * reports to the serial console what the image gave it — the reference value
 * author's public key inside the measurement, and the config device outside
 * it — and it refuses, rather than loads, a reference value set that arrives
 * without its detached signature (ADR-0006). It verifies nothing; that is the
 * loader's job, and the loader is Go code in attest/refvalsfile.go.
 *
 * The paths below are the config-device layout ticket 06 defines and the
 * in-image path of the author key. Ticket 14's tunneld reads the same paths.
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define AUTHOR_KEY  "/etc/attested-tunnel/author.pub"
#define CONFIG_ROOT "/config"
#define REFVALS     CONFIG_ROOT "/reference-values.json"
#define REFVALS_SIG CONFIG_ROOT "/reference-values.json.sig"
#define PEERS       CONFIG_ROOT "/peers.json"
#define CHAIN_PEM   CONFIG_ROOT "/chain/chain.pem"
#define CHAIN_JSON  CONFIG_ROOT "/chain/chain.json"

static int present(const char *p) {
	struct stat st;
	return stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

static void report(const char *label, const char *p) {
	printf("tunneld-placeholder: %-24s %s %s\n", label, p, present(p) ? "present" : "ABSENT");
}

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("tunneld-placeholder: standing in for tunneld; rebuild with TUNNELD=<binary> (ticket 14)\n");

	char key[80] = {0};
	FILE *f = fopen(AUTHOR_KEY, "r");
	if (f) {
		if (fgets(key, sizeof key, f))
			key[strcspn(key, "\n")] = 0;
		fclose(f);
	}
	printf("tunneld-placeholder: author key (measured)   %s %s\n", AUTHOR_KEY,
	       key[0] ? key : "ABSENT");

	struct stat st;
	if (stat(CONFIG_ROOT, &st) != 0) {
		printf("tunneld-placeholder: REFUSED: no config device mounted at %s\n", CONFIG_ROOT);
		return 3;
	}
	report("reference value set", REFVALS);
	report("detached signature", REFVALS_SIG);
	report("peer table", PEERS);
	report("certificate chain", CHAIN_PEM);
	report("chain identity+tcb", CHAIN_JSON);

	int doc = present(REFVALS), sig = present(REFVALS_SIG);
	if (doc && sig) {
		printf("tunneld-placeholder: reference value set and its detached signature are both on the device; "
		       "the real loader would verify then parse (ADR-0006)\n");
		return 0;
	}
	/* One sentinel for "absent" and "unsigned", as ADR-0006 requires. */
	printf("tunneld-placeholder: REFUSED: reference value set not loadable (document %s, signature %s) — ADR-0006\n",
	       doc ? "present" : "absent", sig ? "present" : "absent");
	return 4;
}
