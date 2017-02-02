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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * open(2) should return EISDIR when asking for write access on a dir.
 * This test should return the same results in both GZ and NGZ contexts.
 */
#include <stdio.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/debug.h>
#include <sys/statvfs.h>

#define	SD_TEST_DIR	"/dev/zvol"

int
main(int argc, char *argv[])
{
	struct stat st;
	struct statvfs vfs;
	int ret;

	if (stat(SD_TEST_DIR, &st) != 0) {
		fprintf(stderr, "test failed: failed to stat %s\n",
		    SD_TEST_DIR);
		return (1);
	}

	if ((st.st_mode & S_IFMT) != S_IFDIR) {
		fprintf(stderr, "test failed: %s is not a dir\n", SD_TEST_DIR);
		return (1);
	}

	if (statvfs(SD_TEST_DIR, &vfs) != 0) {
		fprintf(stderr, "test failed: failed to stat vfs for %s: %s\n",
		    SD_TEST_DIR, strerror(errno));
		return (1);
	}

	if (strncmp("dev", vfs.f_basetype, FSTYPSZ) != 0) {
		fprintf(stderr, "test failed: asked to run on non-dev\n");
		return (1);
	}

	ret = open(SD_TEST_DIR, O_RDWR, 0);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EISDIR);

	/*
	 * It's important to test both O_RDWR and O_RDWR | O_CREAT
	 * because of the different code paths taken in sdev.
	 */
	ret = open(SD_TEST_DIR, O_RDWR | O_CREAT, 0);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, EISDIR);

	return (0);
}
