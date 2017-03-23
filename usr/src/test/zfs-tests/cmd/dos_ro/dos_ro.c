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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <attr.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libnvpair.h>

extern const char *__progname;

int vflag = 0;

static int
dosattr_set_ro(int fildes, const char *fname)
{
	nvlist_t	*nvl = NULL;
	int		err;

	err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (err != 0)
		return (err);

	(void) nvlist_add_boolean_value(nvl, A_READONLY, 1);

	if (fname == NULL) {
		err = fsetattr(fildes, XATTR_VIEW_READWRITE, nvl);
	} else {
		err = setattrat(fildes, XATTR_VIEW_READWRITE, fname, nvl);
	}
	if (err < 0) {
		err = errno;
		if (vflag > 1) {
			(void) fprintf(stderr,
			    "dosattr_set: setattrat (%s), err %d\n",
			    fname, err);
		}
	}

	nvlist_free(nvl);

	return (err);
}

void
usage(void)
{
	(void) fprintf(stderr, "usage: %s [-v] file\n",
	    __progname);
	exit(1);
}

int
main(int argc, char **argv)
{
	char *fname;
	int c, fd, n;

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			vflag++;
			break;
		case '?':
		default:
			usage();
			break;
		}
	}

	if (optind + 1 != argc)
		usage();
	fname = argv[optind];

	fd = open(fname, O_CREAT | O_RDWR, 0644);
	if (fd < 0) {
		perror(fname);
		exit(1);
	}

	if (vflag)
		(void) fprintf(stderr, "Write 1 (mode 644)\n");
	n = write(fd, "mode 644 OK\n", 12);
	if (n != 12) {
		(void) fprintf(stderr, "write mode 644, err=%d\n", errno);
		exit(1);
	}

	if (vflag)
		(void) fprintf(stderr, "Chmod 444\n");
	n = fchmod(fd, 0444);
	if (n < 0) {
		(void) fprintf(stderr, "chmod 444, err=%d\n", errno);
		exit(1);
	}

	if (vflag)
		(void) fprintf(stderr, "Write 2 (mode 444)\n");
	n = write(fd, "mode 444 OK\n", 12);
	if (n != 12) {
		(void) fprintf(stderr, "write mode 444, err=%d\n", errno);
		exit(1);
	}

	if (vflag)
		(void) fprintf(stderr, "Set DOS R/O\n");
	n = dosattr_set_ro(fd, NULL /* fname? */);
	if (n != 0) {
		(void) fprintf(stderr, "Set R/O, err=%d\n", n);
		exit(1);
	}

	/*
	 * This fails, but write on an already open handle should succeed
	 * the same as when we've set the mode to 444 after open.
	 */
	if (vflag)
		(void) fprintf(stderr, "Write 3 (DOS R/O)\n");
	n = write(fd, "Write DOS RO?\n", 14);
	if (n != 14) {
		(void) fprintf(stderr, "write (DOS R/O), err=%d\n", errno);
		exit(1);
	}

	return (0);
}
