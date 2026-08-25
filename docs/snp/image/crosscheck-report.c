/*
 * crosscheck-report: the binary embedded as /usr/bin/tunneld in the ONE image
 * built for ticket 07's cross-check, and in nothing else.
 *
 * It pulls an attestation report through the report interface exactly as
 * ticket 01's by-hand procedure does (configfs-tsm: a 64-byte single write to
 * inblob, then read outblob) and prints the report as hex on the console
 * between two marker lines, so the host can recover it from the serial log
 * and decode it with docs/snp/parse-snp-report.py.
 *
 * The measurement it prints is used for exactly one thing: checking that the
 * offline prediction for THIS image is right. It is never a reference value.
 * See docs/snp-measurement-prediction.md.
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DIR "/sys/kernel/config/tsm/report/ticket07"

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	if (mkdir(DIR, 0755) != 0 && access(DIR, F_OK) != 0) {
		printf("crosscheck-report: FAILED: cannot create " DIR "\n");
		return 2;
	}
	/* 64 recognisable bytes, as in ticket 01, written in one write. */
	unsigned char in[64];
	for (int i = 0; i < 64; i++) in[i] = (unsigned char)i;
	int fd = open(DIR "/inblob", O_WRONLY);
	if (fd < 0 || write(fd, in, sizeof in) != (ssize_t)sizeof in) {
		printf("crosscheck-report: FAILED: inblob write\n");
		return 2;
	}
	close(fd);

	unsigned char report[4096];
	fd = open(DIR "/outblob", O_RDONLY);
	if (fd < 0) { printf("crosscheck-report: FAILED: outblob open\n"); return 2; }
	size_t n = 0; ssize_t r;
	while ((r = read(fd, report + n, sizeof report - n)) > 0) n += (size_t)r;
	close(fd);
	printf("crosscheck-report: outblob %zu bytes\n", n);

	printf("crosscheck-report: BEGIN REPORT HEX\n");
	for (size_t i = 0; i < n; i++) {
		printf("%02x", report[i]);
		if (i % 64 == 63) printf("\n");
	}
	if (n % 64) printf("\n");
	printf("crosscheck-report: END REPORT HEX\n");
	/* Byte offset 0x90, 48 bytes: MEASUREMENT (SEV-SNP ABI, ATTESTATION_REPORT). */
	if (n >= 0x90 + 48) {
		printf("crosscheck-report: launch measurement as reported by the platform: ");
		for (int i = 0; i < 48; i++) printf("%02x", report[0x90 + i]);
		printf("\n");
	}
	return 0;
}
