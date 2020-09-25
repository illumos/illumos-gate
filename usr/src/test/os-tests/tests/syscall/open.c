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
 * Copyright 2020 Joyent, Inc.
 */

/*
 * Test the open(2) syscall.
 *
 * Currently only tests O_DIRECT pass/fail based on the known support in the
 * underlying file system.
 *
 * Note: there is a test for the O_DIRECTORY flag in the directory above this
 * which could be consolidated into this code at some point.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/param.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static void
o_direct_test(const char *dir)
{
	int fd;
	struct statvfs64 buf;
	char tmpname[MAXPATHLEN];
	char *path;

	boolean_t pass;

	(void) snprintf(tmpname, sizeof (tmpname), "%s/otstXXXXXX", dir);
	if ((path = mktemp(tmpname)) == NULL) {
		(void) printf("FAILED: unable to create temp file name\n");
		exit(1);
	}

	if (statvfs64(dir, &buf) == -1) {
		perror("statvfs failed");
		exit(1);
	}

	if (strcmp(buf.f_basetype, "zfs") == 0) {
		pass = B_TRUE;
	} else if (strcmp(buf.f_basetype, "tmpfs") == 0) {
		pass = B_FALSE;
	} else {
		(void) printf("SKIP: expected 'zfs' or 'tmpfs'\n");
		return;
	}

	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_DIRECT, 0644);
	if (fd >= 0) {
		(void) close(fd);
		(void) unlink(path);
		if (!pass) {
			(void) printf("FAILED: O_DIRECT on %s/tst_open is "
			    "expected to fail\n", dir);
			exit(1);
		}
	} else {
		if (pass) {
			(void) printf("FAILED: O_DIRECT on %s/tst_open is "
			    "expected to succeed\n", dir);
			exit(1);
		}

		if (errno != EINVAL) {
			(void) printf("FAILED: expected EINVAL, got %d\n",
			    errno);
			exit(1);
		}
	}
}

int
main(void)
{
	/* On typical illumos distros, /tmp is tmpfs, O_DIRECT should fail */
	o_direct_test("/tmp");

	/* On typical illumos distros, /var is zfs, O_DIRECT should pass */
	o_direct_test("/var/tmp");

	(void) printf("PASS\n");
	return (0);
}
