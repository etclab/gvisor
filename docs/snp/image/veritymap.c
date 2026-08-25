/*
 * veritymap: create a read-only dm-verity mapping with raw device-mapper
 * ioctls, so the measured initrd needs no dmsetup, no libdevmapper and no
 * udev. Every parameter of the mapping arrives on the kernel command line,
 * which the launch measurement covers, so a mismatch is loud rather than
 * silent: the mapping is created with panic_on_corruption.
 *
 * usage: veritymap NAME DATADEV HASHDEV DATABLOCKS HASHSTART ROOTHASH SALT
 *
 *   NAME        device-mapper name; the device appears as /dev/dm-N
 *   DATADEV     block device holding the root filesystem image
 *   HASHDEV     block device holding the hash tree (may equal DATADEV)
 *   DATABLOCKS  number of 4096-byte data blocks
 *   HASHSTART   first hash block, in 4096-byte units, on HASHDEV
 *   ROOTHASH    sha256 root of the hash tree, hex
 *   SALT        salt, hex, or "-" for none
 *
 * Prints the dm-N minor on success. Exits non-zero on any failure.
 * Linux kernel dm-verity table format:
 * Documentation/admin-guide/device-mapper/verity.rst
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <linux/dm-ioctl.h>

#define CONTROL "/dev/mapper/control"
#define DATA_BLOCK 4096ULL
#define BUFSZ 16384

static void die(const char *what) {
	perror(what);
	exit(1);
}

static void prep(struct dm_ioctl *io, const char *name, unsigned flags) {
	memset(io, 0, sizeof(*io));
	io->version[0] = DM_VERSION_MAJOR;
	io->version[1] = DM_VERSION_MINOR;
	io->version[2] = DM_VERSION_PATCHLEVEL;
	io->data_size = BUFSZ;
	io->data_start = sizeof(*io);
	io->flags = flags;
	snprintf(io->name, sizeof(io->name), "%s", name);
}

int main(int argc, char **argv) {
	if (argc != 8) {
		fprintf(stderr, "usage: veritymap NAME DATADEV HASHDEV DATABLOCKS HASHSTART ROOTHASH SALT\n");
		return 2;
	}
	const char *name = argv[1], *datadev = argv[2], *hashdev = argv[3];
	unsigned long long datablocks = strtoull(argv[4], NULL, 10);
	unsigned long long hashstart = strtoull(argv[5], NULL, 10);
	const char *roothash = argv[6], *salt = argv[7];
	if (datablocks == 0 || strlen(roothash) != 64) {
		fprintf(stderr, "veritymap: bad DATABLOCKS or ROOTHASH\n");
		return 2;
	}

	int fd = open(CONTROL, O_RDWR);
	if (fd < 0)
		die(CONTROL);

	static char buf[BUFSZ] __attribute__((aligned(8)));
	struct dm_ioctl *io = (struct dm_ioctl *)buf;

	prep(io, name, 0);
	if (ioctl(fd, DM_DEV_CREATE, io) < 0)
		die("DM_DEV_CREATE");
	unsigned long long dev = io->dev;

	prep(io, name, DM_READONLY_FLAG);
	io->target_count = 1;
	struct dm_target_spec *spec = (struct dm_target_spec *)(buf + sizeof(*io));
	memset(spec, 0, sizeof(*spec));
	spec->sector_start = 0;
	spec->length = datablocks * (DATA_BLOCK / 512);
	strcpy(spec->target_type, "verity");
	char *params = (char *)(spec + 1);
	int n = snprintf(params, BUFSZ - sizeof(*io) - sizeof(*spec),
			 "1 %s %s %llu %llu %llu %llu sha256 %s %s 1 panic_on_corruption",
			 datadev, hashdev, DATA_BLOCK, DATA_BLOCK, datablocks, hashstart,
			 roothash, salt);
	if (n < 0)
		die("snprintf");
	spec->next = sizeof(*spec) + ((n + 1 + 7) & ~7);
	if (ioctl(fd, DM_TABLE_LOAD, io) < 0)
		die("DM_TABLE_LOAD");

	prep(io, name, 0); /* no DM_SUSPEND_FLAG: this resumes, activating the table */
	if (ioctl(fd, DM_DEV_SUSPEND, io) < 0)
		die("DM_DEV_SUSPEND (resume)");

	/* dm_ioctl.dev is a huge-encoded dev_t: minor in bits 0-7 and 20-31. */
	unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
	printf("%u\n", minor);
	return 0;
}
