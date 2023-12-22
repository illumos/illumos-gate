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

bool
check_paused(struct vmctx *ctx)
{
	struct vdi_field_entry_v1 entry = {
		.vfe_ident = VAI_VM_IS_PAUSED,
	};
	struct vm_data_xfer xfer = {
		.vdx_vcpuid = -1,
		.vdx_class = VDC_VMM_ARCH,
		.vdx_version = 1,
		.vdx_len = sizeof (entry),
		.vdx_data = &entry,
		.vdx_flags = VDX_FLAG_READ_COPYIN,
	};

	const int vmfd = vm_get_device_fd(ctx);
	if (ioctl(vmfd, VM_DATA_READ, &xfer) != 0) {
		err(EXIT_FAILURE, "error reading pause state");
	}

	return (entry.vfe_value != 0);
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;
	struct vcpu *vcpu;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could not open test VM");
	}

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		err(EXIT_FAILURE, "Could not open vcpu0");
	}

	if (vm_activate_cpu(vcpu) != 0) {
		err(EXIT_FAILURE, "could not activate vcpu0");
	}

	const int vmfd = vm_get_device_fd(ctx);
	int error;

	/* Instance should not be paused after initial creation */
	if (check_paused(ctx)) {
		errx(EXIT_FAILURE, "VM unexpectedly in paused state");
	}

	if (ioctl(vmfd, VM_PAUSE, 0) != 0) {
		err(EXIT_FAILURE, "VM_PAUSE failed");
	}

	/* Now we should observe the instance as paused */
	if (!check_paused(ctx)) {
		errx(EXIT_FAILURE, "VM no in expected paused state");
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

	/* A VM_RUN attempted now should fail with EBUSY */
	struct vm_entry ventry = { .cmd = 0, };
	struct vm_exit vexit = { 0 };
	if (vm_run(vcpu, &ventry, &vexit) == 0) {
		errx(EXIT_FAILURE, "VM_RUN should have failed");
	}
	error = errno;
	if (error != EBUSY) {
		errx(EXIT_FAILURE, "VM_RUN unexpected errno: %d != %d",
		    EBUSY, error);
	}

	if (ioctl(vmfd, VM_RESUME, 0) != 0) {
		err(EXIT_FAILURE, "VM_RESUME failed");
	}

	/* Now we should observe the instance as no longer paused */
	if (check_paused(ctx)) {
		errx(EXIT_FAILURE, "VM unexpectedly in paused state");
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

	vm_vcpu_close(vcpu);
	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
