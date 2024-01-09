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

#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "common.h"

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	struct vcpu *vcpu;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could open test VM");
	}

	/*
	 * It would be odd if we had the freshly created VM instance, but it did
	 * not appear to exist.
	 */
	assert(check_instance_usable(suite_name));

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		err(EXIT_FAILURE, "Could not open vcpu0");
	}

	/* Ensure sure that auto-destruct is off */
	if (ioctl(vm_get_device_fd(ctx), VM_SET_AUTODESTRUCT, 0) != 0) {
		errx(EXIT_FAILURE, "could not disable auto-destruct");
	}

	if (ioctl(vm_get_device_fd(ctx), VM_DESTROY_SELF, 0) != 0) {
		errx(EXIT_FAILURE, "ioctl(VM_DESTROY_SELF) failed");
	}

	/*
	 * Since we still hold the instance open, we expect it to still exist in
	 * /dev/vmm, but be useless for further operations
	 */
	if (!check_instance_exists(suite_name)) {
		err(EXIT_FAILURE,
		    "instance missing after unfinished destroy");
	}

	/* Attempt an operation on our still-open handle */
	uint64_t reg = 0;
	if (vm_get_register(vcpu, VM_REG_GUEST_RAX, &reg) == 0) {
		err(EXIT_FAILURE,
		    "VM_GET_REGISTER succeeded despite instance destruction");
	}
	/* Check usability via the dedicated ioctl */
	if (check_instance_usable(suite_name)) {
		err(EXIT_FAILURE,
		    "instance not reporting in-progress destruction");
	}


	vm_vcpu_close(vcpu);
	vm_close(ctx);
	ctx = NULL;

	/* Make doubly-sure the VM is gone after close */
	if (check_instance_exists(suite_name)) {
		err(EXIT_FAILURE, "instance still accessible after destroy");
	}

	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
