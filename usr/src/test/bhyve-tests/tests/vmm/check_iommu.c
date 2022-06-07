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

#include <sys/vmm.h>
#include <sys/vmm_dev.h>

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);

	int ctl_fd = open(VMM_CTL_DEV, O_EXCL | O_RDWR);
	if (ctl_fd < 0) {
		perror("could not open vmmctl device");
		return (EXIT_FAILURE);
	}

	int res = ioctl(ctl_fd, VMM_CHECK_IOMMU, 0);
	if (res < 0) {
		perror("VMM_CHECK_IOMMU ioctl failed");
		return (EXIT_FAILURE);
	}

	(void) close(ctl_fd);
	(void) printf("%s\tPASS\n", suite_name);
	return (0);
}
