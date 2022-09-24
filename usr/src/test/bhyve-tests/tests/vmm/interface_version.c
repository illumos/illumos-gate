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
#include <err.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);

	int ctl_fd = open(VMM_CTL_DEV, O_EXCL | O_RDWR);
	if (ctl_fd < 0) {
		perror("could not open vmmctl device");
	}

	int version = ioctl(ctl_fd, VMM_INTERFACE_VERSION, 0);
	if (version < 0) {
		perror("VMM_INTERFACE_VERSION ioctl failed");
	}
	if (version != VMM_CURRENT_INTERFACE_VERSION) {
		(void) fprintf(stderr, "kernel version %d != expected %d\n",
		    version, VMM_CURRENT_INTERFACE_VERSION);
		return (EXIT_FAILURE);
	}
	(void) close(ctl_fd);

	/* Query the version via an instance fd as well */
	struct vmctx *ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		err(EXIT_FAILURE, "could not open test VM");
	}
	version = ioctl(vm_get_device_fd(ctx), VMM_INTERFACE_VERSION, 0);
	if (version < 0) {
		err(EXIT_FAILURE,
		    "VMM_INTERFACE_VERSION ioctl failed on vmm fd");
	}
	if (version != VMM_CURRENT_INTERFACE_VERSION) {
		errx(EXIT_FAILURE, "kernel version %d != expected %d",
		    version, VMM_CURRENT_INTERFACE_VERSION);
	}
	vm_destroy(ctx);

	(void) printf("%s\tPASS\n", suite_name);
	return (0);
}
