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
 * Copyright 2022 Oxide Computer Company
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
usmn_parse_uint32(const char *str, uint32_t *valp)
{
	long long l;
	char *eptr;

	errno = 0;
	l = strtoll(str, &eptr, 16);
	if (errno != 0 || *eptr != '\0') {
		warnx("failed to parse string '%s'", str);
		return (B_FALSE);
	}

	if (l < 0 || l > UINT32_MAX) {
		warnx("value %s is outside the valid range [0, UINT32_MAX]",
		    str);
		return (B_FALSE);
	}

	*valp = (uint32_t)l;
	return (B_TRUE);
}

static boolean_t
usmn_op(boolean_t do_write, int fd, const char *addr, uint32_t length,
    uint32_t value)
{
	usmn_reg_t usr;

	usr.usr_data = value;
	usr.usr_size = length;
	if (!usmn_parse_uint32(addr, &usr.usr_addr)) {
		return (B_FALSE);
	}

	if (ioctl(fd, do_write ? USMN_WRITE : USMN_READ, &usr) != 0) {
		warn("SMN ioctl failed at 0x%x", usr.usr_addr);
		return (B_FALSE);
	}

	if (!do_write) {
		(void) printf("0x%x: 0x%x\n", usr.usr_addr, usr.usr_data);
	}
	return (B_TRUE);
}

int
main(int argc, char *argv[])
{
	int i, c, fd, ret;
	const char *device = NULL;
	boolean_t do_write = B_FALSE;
	uint32_t wval = 0;
	uint32_t length = 4;

	while ((c = getopt(argc, argv, "d:L:w:")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'L':
			if (!usmn_parse_uint32(optarg, &length)) {
				return (EXIT_FAILURE);
			}
			if (length != 1 && length != 2 && length != 4) {
				warnx("length %u is out of range {1,2,4}",
				    length);
				return (EXIT_FAILURE);
			}
			break;
		case 'w':
			do_write = B_TRUE;
			if (!usmn_parse_uint32(optarg, &wval)) {
				return (EXIT_FAILURE);
			}
			break;
		default:
			(void) fprintf(stderr, "Usage: usmn -d device "
			    "[-L length] [-w value] addr [addr]...\n"
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
		errx(EXIT_FAILURE, "at least one register must be specified");
	}

	if (do_write && argc != 1) {
		errx(EXIT_FAILURE, "can only write to a single register");
	}

	if ((fd = open(device, do_write ? O_RDWR : O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", device);
	}

	ret = EXIT_SUCCESS;
	for (i = 0; i < argc; i++) {
		if (!usmn_op(do_write, fd, argv[i], length, wval)) {
			ret = EXIT_FAILURE;
		}
	}

	(void) close(fd);
	return (ret);
}
