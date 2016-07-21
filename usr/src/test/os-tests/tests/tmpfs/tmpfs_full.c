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
 * Given a path to a tmpfs that has already been marked as full, attempt to
 * perform certain activities on it, all of which should fail with ENOSPC.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <sys/debug.h>
#include <unistd.h>

int
main(int argc, const char *argv[])
{
	int fd, ret;
	struct statvfs vfs;

	if (argc != 3) {
		fprintf(stderr, "test failed: missing path or file\n");
		return (1);
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		fprintf(stderr, "test failed: failed to open root %s: %s\n",
		    argv[1], strerror(errno));
		return (1);
	}

	if (fstatvfs(fd, &vfs) != 0) {
		fprintf(stderr, "test failed: failed to stat vfs for %s: %s\n",
		    argv[1], strerror(errno));
		return (1);
	}

	if (strncmp("tmpfs", vfs.f_basetype, FSTYPSZ) != 0) {
		fprintf(stderr, "test failed: asked to run on non-tmpfs\n");
		return (1);
	}

	/*
	 * Once a few additional bugs in tmpfs are fixed, we should double check
	 * and make sure that the free space here is actually zero before
	 * continuing.
	 */

	/*
	 * Go through operations that would create nodes and make sure that they
	 * all fail.
	 */

	ret = openat(fd, "Mnemosyne", O_RDWR | O_CREAT, 0755);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, ENOSPC);

	ret = mkdirat(fd, "Euterpe", 0775);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, ENOSPC);

	ret = symlinkat("/dev/null", fd, "Melpomene");
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, ENOSPC);

	ret = linkat(fd, argv[2], fd, "Urania", 0);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, ENOSPC);

	/*
	 * Make sure we can't create open extended attributes.
	 */
	ret = openat(fd, "Lethe", O_RDWR | O_CREAT | O_XATTR);
	VERIFY3S(ret, ==, -1);
	VERIFY3S(errno, ==, ENOSPC);

	return (0);
}
