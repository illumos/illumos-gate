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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Check certain aspects of files for the overwrite test that are a bit harder
 * to do in the shell.
 */

#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/stat.h>

typedef enum {
	CT_UNSET,
	CT_NOPERMS,
	CT_DOOR
} check_type_t;

int
main(int argc, char *argv[])
{
	int c;
	struct stat st;
	check_type_t type = CT_UNSET;

	if (argc == 1) {
		errx(EXIT_FAILURE, "missing required arguments");
	}

	while ((c = getopt(argc, argv, ":dn")) != -1) {
		switch (c) {
		case 'd':
			type = CT_DOOR;
			break;
		case 'n':
			type = CT_NOPERMS;
			break;
		case ':':
			errx(EXIT_FAILURE, "option -%c requires an operand", c);
		case '?':
			errx(EXIT_FAILURE, "unknown option -%c", c);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1) {
		errx(EXIT_FAILURE, "expected a file to look at but have %d "
		    "args", argc);
	}

	if (stat(argv[0], &st) != 0) {
		err(EXIT_FAILURE, "failed to stat %s", argv[0]);
	}

	switch (type) {
	case CT_UNSET:
		errx(EXIT_FAILURE, "missing a check type option");
	case CT_NOPERMS:
		if (S_ISREG(st.st_mode) == 0) {
			errx(EXIT_FAILURE, "%s is not a regular file: 0x%x",
			    argv[0], st.st_mode);
		} else if ((st.st_mode & S_IAMB) != 0) {
			errx(EXIT_FAILURE, "%s ended up with perms somehow: "
			    "found 0o%o", argv[0], st.st_mode & S_IAMB);
		}
		break;
	case CT_DOOR:
		if (S_ISDOOR(st.st_mode) == 0) {
			errx(EXIT_FAILURE, "%s is not a door: 0x%x",
			    argv[0], st.st_mode);
		}
		break;
	}

	return (EXIT_SUCCESS);
}
