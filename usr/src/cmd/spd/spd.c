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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * A private utility to dump the raw spd information nvlist.
 */

#include <err.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libjedec.h>

int
main(int argc, const char *argv[])
{
	int fd;
	struct stat st;
	uint8_t buf[4096];
	ssize_t ret;
	spd_error_t serr;

	if (argc != 2) {
		errx(EXIT_FAILURE, "spd: file");
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open %s", argv[1]);
	}

	if (fstat(fd, &st) != 0) {
		err(EXIT_FAILURE, "failed to get stat info for %s", argv[1]);
	}

	if (st.st_size > sizeof (buf)) {
		errx(EXIT_FAILURE, "spd data exceeds internal 0x%zx internal "
		    "buffer: 0x%lx", sizeof (buf), st.st_size);
	}

	ret = read(fd, buf, st.st_size);
	if (ret < 0) {
		err(EXIT_FAILURE, "failed to read %s", argv[1]);
	} else if (ret != st.st_size) {
		errx(EXIT_FAILURE, "failed to read %s in one go: got %ld "
		    "bytes, expected %ld", argv[1], ret, st.st_size);
	}

	nvlist_t *nvl = libjedec_spd(buf, st.st_size, &serr);
	if (nvl == NULL) {
		errx(EXIT_FAILURE, "failed to parse spd info: 0x%x\n", serr);
	}

	nvlist_print(stdout, nvl);
	return (EXIT_SUCCESS);
}
