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
#include <sys/stat.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <sys/sysmacros.h>
#include <stdbool.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <sys/vmm_data.h>
#include <vmmapi.h>

#include "common.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could not open test VM");
	}

	if (vm_activate_cpu(ctx, 0) != 0) {
		err(EXIT_FAILURE, "could not activate vcpu0");
	}

	const int vmfd = vm_get_device_fd(ctx);
	int error;

	if (ioctl(vmfd, VM_PAUSE, 0) != 0) {
		err(EXIT_FAILURE, "VM_PAUSE failed");
	}

	/* Pausing an already-paused instanced should result in EALREADY */
	if (ioctl(vmfd, VM_PAUSE, 0) == 0) {
		errx(EXIT_FAILURE, "VM_PAUSE should have failed");
	}
	error = errno;
	if (error != EALREADY) {
		errx(EXIT_FAILURE, "VM_PAUSE unexpected errno: %d != %d",
		    EALREADY, error);
	}

	if (ioctl(vmfd, VM_RESUME, 0) != 0) {
		err(EXIT_FAILURE, "VM_RESUME failed");
	}

	/* Resuming an already-running instanced should result in EALREADY */
	if (ioctl(vmfd, VM_RESUME, 0) == 0) {
		errx(EXIT_FAILURE, "VM_RESUME should have failed");
	}
	error = errno;
	if (error != EALREADY) {
		errx(EXIT_FAILURE, "VM_RESUME unexpected errno: %d != %d",
		    EALREADY, error);
	}

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
