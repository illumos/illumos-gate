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
#include <sys/vmm_drv_test.h>
#include <vmmapi.h>

#include "common.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		perror("could open test VM");
		return (EXIT_FAILURE);
	}

	int vdtfd = open_drv_test();
	if (vdtfd < 0) {
		perror("could open drv_test device");
		vm_destroy(ctx);
		return (EXIT_FAILURE);
	}

	int err;
	err = ioctl(vdtfd, VDT_IOC_HOLD, vm_get_device_fd(ctx));
	if (err != 0) {
		perror("could not establish drv hold on VM");
		vm_destroy(ctx);
		return (EXIT_FAILURE);
	}

	err = ioctl(vdtfd, VDT_IOC_RELE, 0);
	if (err != 0) {
		perror("could not release drv hold on VM");
		vm_destroy(ctx);
		return (EXIT_FAILURE);
	}

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
