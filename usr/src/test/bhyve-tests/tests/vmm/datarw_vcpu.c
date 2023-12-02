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

static void
should_eq_u64(const char *field_name, uint64_t a, uint64_t b)
{
	if (a != b) {
		errx(EXIT_FAILURE, "unexpected %s %" PRIu64 " != %" PRIu64,
		    field_name, a, b);
	}
}

static void
check_inval_field(int vmfd, uint32_t ident, uint64_t val)
{
	struct vdi_field_entry_v1 field = {
		.vfe_ident = ident,
		.vfe_value = val,
	};
	struct vm_data_xfer vdx = {
		.vdx_class = VDC_VMM_ARCH,
		.vdx_version = 1,
		.vdx_len = sizeof (field),
		.vdx_data = &field,
	};

	if (ioctl(vmfd, VM_DATA_WRITE, &vdx) == 0) {
		err(EXIT_FAILURE, "vmm_data_write should have failed");
	}
	int err = errno;
	if (err != EINVAL) {
		errx(EXIT_FAILURE, "expected EINVAL errno, got %d", err);
	}
}

static void
do_data_write(int vmfd, struct vm_data_xfer *vdx)
{
	if (ioctl(vmfd, VM_DATA_WRITE, vdx) != 0) {
		err(EXIT_FAILURE, "valid vmm_data_write failed");
	}
	if (vdx->vdx_result_len != vdx->vdx_len) {
		errx(EXIT_FAILURE, "unexpected vdx_result_len %u != %u",
		    vdx->vdx_len, vdx->vdx_result_len);
	}
}

static void
do_data_read(int vmfd, struct vm_data_xfer *vdx)
{
	if (ioctl(vmfd, VM_DATA_READ, vdx) != 0) {
		err(EXIT_FAILURE, "valid vmm_data_read failed");
	}
	if (vdx->vdx_result_len != vdx->vdx_len) {
		errx(EXIT_FAILURE, "unexpected vdx_result_len %u != %u",
		    vdx->vdx_len, vdx->vdx_result_len);
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

	if (vm_activate_cpu(ctx, 0) != 0) {
		err(EXIT_FAILURE, "could not activate vcpu0");
	}

	const int vmfd = vm_get_device_fd(ctx);

	/* Pause the instance before attempting to manipulate vcpu data */
	if (ioctl(vmfd, VM_PAUSE, 0) != 0) {
		err(EXIT_FAILURE, "VM_PAUSE failed");
	}

	struct vdi_field_entry_v1 fields[4] = {
		{ .vfe_ident = VAI_PEND_NMI },
		{ .vfe_ident = VAI_PEND_EXTINT },
		{ .vfe_ident = VAI_PEND_EXCP },
		{ .vfe_ident = VAI_PEND_INTINFO },
	};

	struct vm_data_xfer vdx = {
		.vdx_class = VDC_VMM_ARCH,
		.vdx_version = 1,
		.vdx_flags = VDX_FLAG_READ_COPYIN,
		.vdx_len = sizeof (fields),
		.vdx_data = &fields,
	};

	/* Fetch arch state first */
	do_data_read(vmfd, &vdx);

	/* All of these should be zeroed on a fresh vcpu */
	should_eq_u64("VAI_PEND_NMI", fields[0].vfe_value, 0);
	should_eq_u64("VAI_PEND_EXTINT", fields[1].vfe_value, 0);
	should_eq_u64("VAI_PEND_EXCP", fields[2].vfe_value, 0);
	should_eq_u64("VAI_PEND_INTINFO", fields[3].vfe_value, 0);

	/* Light up those fields */
	fields[0].vfe_value = 1;
	fields[1].vfe_value = 1;
	fields[2].vfe_value = VM_INTINFO_VALID | VM_INTINFO_HWEXCP | IDT_GP;
	fields[3].vfe_value = VM_INTINFO_VALID | VM_INTINFO_SWINTR | 0x80;
	do_data_write(vmfd, &vdx);

	/*
	 * Flip the order (just for funsies) and re-query to check that we still
	 * get the expected state.
	 */
	fields[0].vfe_ident = VAI_PEND_INTINFO;
	fields[1].vfe_ident = VAI_PEND_EXCP;
	fields[2].vfe_ident = VAI_PEND_EXTINT;
	fields[3].vfe_ident = VAI_PEND_NMI;
	do_data_read(vmfd, &vdx);

	should_eq_u64("VAI_PEND_INTINFO", fields[0].vfe_value,
	    VM_INTINFO_VALID | VM_INTINFO_SWINTR | 0x80);
	should_eq_u64("VAI_PEND_EXCP", fields[1].vfe_value,
	    VM_INTINFO_VALID | VM_INTINFO_HWEXCP | IDT_GP);
	should_eq_u64("VAI_PEND_EXTINT", fields[2].vfe_value, 1);
	should_eq_u64("VAI_PEND_NMI", fields[3].vfe_value, 1);


	/* NMI-typed exception with the wrong vector */
	check_inval_field(vmfd, VAI_PEND_INTINFO,
	    VM_INTINFO_VALID | VM_INTINFO_NMI | 0xd);

	/* Hardware exception with a bad vector (>= 32) */
	check_inval_field(vmfd, VAI_PEND_INTINFO,
	    VM_INTINFO_VALID | VM_INTINFO_HWEXCP | 0x40);

	/* Non-HW event injected into HW exception field */
	check_inval_field(vmfd, VAI_PEND_EXCP,
	    VM_INTINFO_VALID | VM_INTINFO_SWINTR | 0xd);

	/* Zero out the values again */
	fields[0].vfe_value = 0;
	fields[1].vfe_value = 0;
	fields[2].vfe_value = 0;
	fields[3].vfe_value = 0;
	do_data_write(vmfd, &vdx);

	/* And confirm that it took */
	do_data_read(vmfd, &vdx);
	should_eq_u64("VAI_PEND_INTINFO", fields[0].vfe_value, 0);
	should_eq_u64("VAI_PEND_EXCP", fields[1].vfe_value, 0);
	should_eq_u64("VAI_PEND_EXTINT", fields[2].vfe_value, 0);
	should_eq_u64("VAI_PEND_NMI", fields[3].vfe_value, 0);

	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
