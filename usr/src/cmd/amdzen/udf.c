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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Facilitate access to the AMD Zen data fabric
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <zen_udf.h>

static void
udf_readone(int fd, uint8_t inst, uint8_t func, uint16_t reg,
    zen_udf_flags_t flags)
{
	int ret;
	zen_udf_io_t zui;

	bzero(&zui, sizeof (zui));
	zui.zui_flags = flags;
	zui.zui_inst = inst;
	zui.zui_func = func;
	zui.zui_reg = reg;

	ret = ioctl(fd, ZEN_UDF_READ, &zui);
	if (ret != 0) {
		err(EXIT_FAILURE, "failed to issue read ioctl");
	}

	if ((flags & ZEN_UDF_F_BCAST) == 0) {
		(void) printf("ifr %x/%x/%x: 0x%" PRIx64 "\n",
		    inst, func, reg, zui.zui_data);
	} else {
		(void) printf("ifr bcast/%x/%x: 0x%" PRIx64 "\n",
		    func, reg, zui.zui_data);
	}
}

int
main(int argc, char *argv[])
{
	int c, fd;
	const char *device = NULL;
	const char *funcstr = NULL;
	const char *inststr = NULL;
	const char *regstr = NULL;
	zen_udf_flags_t flags = 0;
	uint8_t func, inst = UINT8_MAX;
	uint16_t reg;
	unsigned long lval;
	char *eptr;

	while ((c = getopt(argc, argv, "d:f:bi:r:l")) != -1) {
		switch (c) {
		case 'd':
			device = optarg;
			break;
		case 'f':
			funcstr = optarg;
			break;
		case 'b':
			flags |= ZEN_UDF_F_BCAST;
			break;
		case 'i':
			inststr = optarg;
			break;
		case 'l':
			flags |= ZEN_UDF_F_64;
			break;
		case 'r':
			regstr = optarg;
			break;
		}
	}

	if (device == NULL || funcstr == NULL || regstr == NULL ||
	    (inststr == NULL && (flags & ZEN_UDF_F_BCAST) == 0)) {
		warnx("missing required arguments");
		(void) fprintf(stderr, "Usage: "
		    "\tudf \t[-l] -d device -f func -b -r reg\n"
		    "\t\t[-l] -d device -f func -i inst -r reg\n");
		exit(2);
	}

	errno = 0;
	lval = strtoul(funcstr, &eptr, 0);
	if (errno != 0 || lval > UINT8_MAX || *eptr != '\0') {
		errx(EXIT_FAILURE, "failed to parse -f: %s", funcstr);
	}
	func = (uint8_t)lval;

	if ((flags & ZEN_UDF_F_BCAST) == 0) {
		lval = strtoul(inststr, &eptr, 0);
		if (errno != 0 || lval > UINT8_MAX || *eptr != '\0') {
			errx(EXIT_FAILURE, "failed to parse -i: %s", inststr);
		}
		inst = (uint8_t)lval;
	} else if (inststr != NULL) {
		errx(EXIT_FAILURE, "pass just one of -b or -i inst");
	}

	lval = strtoul(regstr, &eptr, 0);
	if (errno != 0 || lval > UINT16_MAX || *eptr != '\0') {
		errx(EXIT_FAILURE, "failed to parse -r: %s", regstr);
	}
	reg = (uint16_t)lval;

	if ((fd = open(device, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open %s", device);
	}

	udf_readone(fd, inst, func, reg, flags);
	(void) close(fd);
	return (0);
}
