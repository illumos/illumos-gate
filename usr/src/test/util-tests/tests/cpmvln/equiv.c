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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Given two files, see if they are the same without following symlinks. We
 * declare something is the same if the stat information has the same st_ino and
 * st_dev fields.
 */

#include <err.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>

int
main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;
	struct stat base;

	if (argc <= 2) {
		errx(EXIT_FAILURE, "need at least two operands to "
		    "compare");
	}

	if (lstat(argv[1], &base) != 0) {
		err(EXIT_FAILURE, "failed to lstat %s", argv[1]);
	}

	for (int i = 2; i < argc; i++) {
		struct stat st;

		if (lstat(argv[i], &st) != 0) {
			warn("failed to stat %s", argv[i]);
			ret = EXIT_FAILURE;
			continue;
		}

		if (base.st_dev != st.st_dev ||
		    base.st_ino != st.st_ino) {
			warnx("%s does not match %s: expected dev/ino "
			    "0x%lx/0x%lx, found 0x%lx/0x%lx", argv[1], argv[i],
			    base.st_dev, base.st_ino, st.st_dev, st.st_ino);
			ret = EXIT_FAILURE;
		}
	}

	return (ret);
}
