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

static void
should_eq_u32(const char *field_name, uint32_t a, uint32_t b)
{
	if (a != b) {
		errx(EXIT_FAILURE, "unexpected %s %u != %u",
		    field_name, a, b);
	}
}

int
main(int argc, char *argv[])
{
	const char *suite_name = basename(argv[0]);
	struct vmctx *ctx;

	ctx = create_test_vm(suite_name);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "could not open test VM");
	}

	/*
	 * Check that vmm_data import/export facility is robust in the face of
	 * potentially invalid inputs
	 */
	const int vmfd = vm_get_device_fd(ctx);

	uint8_t buf[sizeof (struct vdi_atpic_v1) + sizeof (int)];
	struct vm_data_xfer vdx = {
		.vdx_class = VDC_ATPIC,
		.vdx_version = 1,
		.vdx_len = sizeof (struct vdi_atpic_v1),
		.vdx_data = buf,
	};

	/* Attempt a valid-sized read first */
	if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
		err(EXIT_FAILURE, "valid vmm_dat_read failed");
	}
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));

	/* ... then too-small ... */
	vdx.vdx_len = sizeof (struct vdi_atpic_v1) - sizeof (int);
	vdx.vdx_result_len = 0;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) == 0) {
		errx(EXIT_FAILURE, "invalid vmm_dat_read should have failed");
	}
	int error = errno;
	if (error != ENOSPC) {
		errx(EXIT_FAILURE, "expected ENOSPC errno, got %d", error);
	}
	/* the "correct" vdx_result_len should still be communicated out */
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));

	/*
	 * ... and too-big to round it out.
	 *
	 * This should pass, but still set vdx_result_len to the actual length
	 */
	vdx.vdx_len = sizeof (struct vdi_atpic_v1) + sizeof (int);
	vdx.vdx_result_len = 0;
	if (ioctl(vmfd, VM_DATA_READ, &vdx) != 0) {
		err(EXIT_FAILURE, "too-large (but valid) vmm_dat_read failed");
	}
	should_eq_u32("vdx_result_len", vdx.vdx_result_len,
	    sizeof (struct vdi_atpic_v1));

	/*
	 * The vmm_data_write paths should also be tested, but not until they
	 * are exposed to the general public without requring mdb -kw settings.
	 */

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
