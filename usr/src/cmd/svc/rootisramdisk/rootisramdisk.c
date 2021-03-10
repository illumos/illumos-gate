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
 * Copyright 2021 Oxide Computer Company
 */

/*
 * rootisramdisk: a helper program for smf_root_is_ramdisk() in
 * "/lib/svc/share/smf_include.sh".  Exits zero if the root file system is
 * mounted from a ramdisk, or non-zero if not, or if we hit an error condition.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <fcntl.h>
#include <err.h>
#include <limits.h>
#include <string.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>

#define	EXIT_USAGE			2
#define	EXIT_NOT_RAMDISK		3

bool g_verbose = false;

static bool
root_is_ramdisk(void)
{
	struct stat st;
	major_t maj;
	char driver[PATH_MAX + 1];

	if (stat("/", &st) != 0) {
		err(EXIT_FAILURE, "stat");
	}

	maj = major(st.st_dev);
	if (g_verbose) {
		fprintf(stderr, "major = %lu\n", (long unsigned)maj);
	}

	if (modctl(MODGETNAME, driver, sizeof (driver), &maj) != 0) {
		err(EXIT_FAILURE, "modctl");
	}

	if (g_verbose) {
		fprintf(stderr, "driver = %s\n", driver);
	}

	return (strcmp(driver, "ramdisk") == 0);
}

int
main(int argc, char *argv[])
{
	int c;

	while ((c = getopt(argc, argv, ":v")) != -1) {
		switch (c) {
		case 'v':
			g_verbose = true;
			break;
		case ':':
			errx(EXIT_USAGE, "-%c requires an operand", optopt);
			break;
		case '?':
			errx(EXIT_USAGE, "-%c unknown", optopt);
			break;
		}
	}

	return (root_is_ramdisk() ? EXIT_SUCCESS : EXIT_NOT_RAMDISK);
}
