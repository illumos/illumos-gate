/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Oxide Computer Company
 */

/*
 * Read and write to the AMD SMN.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <usmn.h>

static boolean_t
usmn_read(int fd, const char *addr)
{
	unsigned long long l;
	char *eptr;
	usmn_reg_t usr;

	errno = 0;
	l = strtoull(addr, &eptr, 16);
	if (errno != 0 || *eptr != '\0' || l > UINT32_MAX) {
		warnx("failed to parse %s: invalid string or address", addr);
		return (B_FALSE);
	}

	usr.usr_addr = (uint32_t)l;
	usr.usr_data = 0;

	if (ioctl(fd, USMN_READ, &usr) != 0) {
		warn("failed to read SMN at 0x%x", usr.usr_addr);
		return (B_FALSE);
	}

	(void) printf("0x%x: 0x%x\n", usr.usr_addr, usr.usr_data);
	return (B_TRUE);
}

int
main(int argc, char *argv[])
{
	int i, c, fd, ret;
	const char *device = NULL;

	while ((c = getopt(argc, argv, "d:")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		default:
			(void) fprintf(stderr, "Usage: usmn -d device addr "
			    "[addr]...\n"
			    "Note: All addresses are interpreted as hex\n");
			return (2);
		}
	}

	if (device == NULL) {
		errx(EXIT_FAILURE, "missing required device");
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		errx(EXIT_FAILURE, "missing registers to read");
	}

	if ((fd = open(device, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", device);
	}

	ret = EXIT_SUCCESS;
	for (i = 0; i < argc; i++) {
		if (!usmn_read(fd, argv[i])) {
			ret = EXIT_FAILURE;
		}
	}

	(void) close(fd);

	return (ret);
}
