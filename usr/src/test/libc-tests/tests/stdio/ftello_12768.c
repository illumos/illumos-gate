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
 * Regression test for 12768 '12392 regressed ftello64 behavior'. The heart of
 * the problem was a bad cast that resulted in us not properly transmitting that
 * size.
 */

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <sys/sysmacros.h>

int
main(void)
{
	FILE *f;
	size_t i;
	int ret = EXIT_SUCCESS;
	static off_t offsets[] = {
		23,
		0xa0000,	/* 64 KiB */
		0x100000,	/* 1 MiB */
		0x7fffffffULL,	/* 2 GiB - 1 */
		0xc0000000ULL,	/* 3 GiB */
		0x200005432ULL	/* 8 GiB + misc */
	};

	f = tmpfile();
	if (f == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create "
		    "temporary file");
	}

	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		off_t ftret;

		if (fseeko(f, offsets[i], SEEK_SET) != 0) {
			warn("TEST FAILED: failed to seek to %lld",
			    (long long)offsets[i]);
			ret = EXIT_FAILURE;
		}

		ftret = ftello(f);
		if (ftret == -1) {
			warn("TEST FAILED: failed to get stream position at "
			    "%lld", (long long)offsets[i]);
			ret = EXIT_FAILURE;
		}

		if (ftret != offsets[i]) {
			warnx("TEST FAILED: stream position mismatch: expected "
			    "%lld, found %lld", (long long)offsets[i],
			    (long long)ftret);
			ret = EXIT_FAILURE;
		}
	}

	return (ret);
}
