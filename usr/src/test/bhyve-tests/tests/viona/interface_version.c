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
 * Copyright 2022 Oxide Computer Company
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libgen.h>

#include <sys/viona_io.h>

#include "viona_suite.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);

	int ctl_fd = open(VIONA_DEV, O_EXCL | O_RDWR);
	if (ctl_fd < 0) {
		perror("could not open viona device");
		return (EXIT_FAILURE);
	}

	int version = ioctl(ctl_fd, VNA_IOC_VERSION, 0);
	if (version < 0) {
		perror("VNA_IOC_VERSION ioctl failed");
		return (EXIT_FAILURE);
	}
	if (version != VIONA_CURRENT_INTERFACE_VERSION) {
		(void) fprintf(stderr, "kernel version %d != expected %d\n",
		    version, VIONA_CURRENT_INTERFACE_VERSION);
		return (EXIT_FAILURE);
	}

	(void) close(ctl_fd);
	(void) printf("%s\tPASS\n", suite_name);
	return (0);
}
