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
#include <errno.h>
#include <err.h>
#include <assert.h>

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
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
		errx(EXIT_FAILURE, "could open test VM");
	}

	/*
	 * It would be odd if we had the freshly created VM instance, but it did
	 * not appear to exist.
	 */
	assert(check_instance_usable(suite_name));

	/* Make sure that auto-destruct is off */
	if (ioctl(vm_get_device_fd(ctx), VM_SET_AUTODESTRUCT, 0) != 0) {
		errx(EXIT_FAILURE, "could not disable auto-destruct");
	}

	vm_close(ctx);
	if (!check_instance_usable(suite_name)) {
		err(EXIT_FAILURE, "instance missing after close");
	}
	ctx = NULL;

	if (destroy_instance(suite_name) != 0) {
		errx(EXIT_FAILURE, "could not clean up instance");
	}

	/* Now repeat that process, but enable auto-destruct */
	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could open test VM");
	}
	if (ioctl(vm_get_device_fd(ctx), VM_SET_AUTODESTRUCT, 1) != 0) {
		errx(EXIT_FAILURE, "could not enable auto-destruct");
	}
	vm_close(ctx);
	ctx = NULL;
	/* At this point, the instance should be gone */
	if (check_instance_usable(suite_name)) {
		err(EXIT_FAILURE,
		    "instance did not auto-destruct as expected");
	}

	/*
	 * Repeat the test again, but establish a vmm_drv hold first.
	 * The instance should auto-destruct when the hold is released.
	 */
	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could open test VM");
	}
	if (ioctl(vm_get_device_fd(ctx), VM_SET_AUTODESTRUCT, 1) != 0) {
		errx(EXIT_FAILURE, "could not enable auto-destruct");
	}
	int vdtfd = open_drv_test();
	if (vdtfd < 0) {
		errx(EXIT_FAILURE, "could open drv_test device");
	}
	if (ioctl(vdtfd, VDT_IOC_HOLD, vm_get_device_fd(ctx)) != 0) {
		errx(EXIT_FAILURE, "could not hold VM from vmm_drv device");
	}
	vm_close(ctx);
	ctx = NULL;

	/*
	 * With the vmm_drv hold remaining on the instance, we expect it to
	 * exist, but not be usable (due to in-progress destroy).
	 */
	if (!check_instance_exists(suite_name)) {
		err(EXIT_FAILURE, "instance completed auto-destruct despite "
		    "existing vmm_drv hold");
	}
	if (check_instance_usable(suite_name)) {
		err(EXIT_FAILURE, "instance still usable despite close() after "
		    "auto-destroy configured");
	}

	if (ioctl(vdtfd, VDT_IOC_RELE, 0) != 0) {
		errx(EXIT_FAILURE, "could not release VM from vmm_drv device");
	}
	if (check_instance_usable(suite_name)) {
		err(EXIT_FAILURE, "instance did not complete destruction "
		    "after vmm_drv release");
	}

	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
