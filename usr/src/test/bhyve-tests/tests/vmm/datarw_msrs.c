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
#include <sys/x86_archext.h>
#include <sys/controlregs.h>

#include "common.h"

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

static uint32_t
query_data_size(int vmfd, struct vm_data_xfer *vdx)
{
	vdx->vdx_len = 0;
	vdx->vdx_data = NULL;
	vdx->vdx_flags = 0;

	if (ioctl(vmfd, VM_DATA_READ, vdx) == 0) {
		errx(EXIT_FAILURE,
		    "expected VM_DATA_READ to fail for size query");
	}
	if (errno != ENOSPC) {
		err(EXIT_FAILURE,
		    "expected ENOSPC error for VM_DATA_READ size query");
	}
	return (vdx->vdx_result_len);
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

	struct vm_data_xfer vdx = {
		.vdx_class = VDC_MSR,
		.vdx_version = 1,
		.vdx_vcpuid = 0,
	};

	const uint32_t msr_sz = query_data_size(vmfd, &vdx);
	const uint32_t msr_count = msr_sz / sizeof (struct vdi_field_entry_v1);

	struct vdi_field_entry_v1 *entries =
	    calloc(msr_count, sizeof (struct vdi_field_entry_v1));
	if (entries == NULL) {
		err(EXIT_FAILURE, "could not allocate space for MSR data");
	}

	/* Attempt to read all the (default) entries */
	vdx.vdx_data = entries;
	vdx.vdx_len = msr_sz;
	do_data_read(vmfd, &vdx);

	/* Spot check a few MSRs which we expect to be present */
	struct expected_msr {
		const char *name;
		uint32_t msr;
		bool present;
	} spot_check[] = {
		{ .msr = MSR_AMD_EFER, .name = "EFER" },
		{ .msr = REG_TSC, .name = "TSC" },
		{ .msr = MSR_AMD_CSTAR, .name = "CSTAR" },
		{ .msr = MSR_AMD_KGSBASE, .name = "KGSBASE" },
	};
	for (uint_t i = 0; i < msr_count; i++) {
		for (uint_t j = 0; j < ARRAY_SIZE(spot_check); j++) {
			if (spot_check[j].msr == entries[i].vfe_ident) {
				spot_check[j].present = true;
			}
		}
	}
	for (uint_t j = 0; j < ARRAY_SIZE(spot_check); j++) {
		if (!spot_check[j].present) {
			errx(EXIT_FAILURE,
			    "did not find %s(%x) MSR in VM_DATA_READ results",
			    spot_check[j].name, spot_check[j].msr);
		}
	}

	/* Attempt to write those same values back to the instance */
	do_data_write(vmfd, &vdx);
	free(entries);
	entries = NULL;

	/* Do a targeted read of a few values */
	struct vdi_field_entry_v1 small_list[] = {
		{ .vfe_ident = REG_TSC },
		{ .vfe_ident = MSR_INTC_SEP_EIP },
		{ .vfe_ident = REG_PAT },
	};
	vdx.vdx_data = small_list;
	vdx.vdx_len = sizeof (small_list);
	vdx.vdx_flags = VDX_FLAG_READ_COPYIN;
	do_data_read(vmfd, &vdx);

	/*
	 * Test access to DEBUGCTL and LBR-related MSRs on AMD.
	 *
	 * Because support for these varies between CPUs, they are (currently)
	 * not included in the default set of MSRs emitted by a blanket read of
	 * MSRs via the vmm-data interface.
	 */
	if (cpu_vendor_amd()) {
		struct vdi_field_entry_v1 dbg_entries[] = {
			{ .vfe_ident = MSR_DEBUGCTL },
			{ .vfe_ident = MSR_LBR_FROM },
			{ .vfe_ident = MSR_LBR_TO },
			{ .vfe_ident = MSR_LEX_FROM },
			{ .vfe_ident = MSR_LEX_TO },
		};

		vdx.vdx_data = &dbg_entries;
		vdx.vdx_len = sizeof (dbg_entries);
		vdx.vdx_flags = VDX_FLAG_READ_COPYIN;

		do_data_read(vmfd, &vdx);

		vdx.vdx_flags = 0;
		do_data_write(vmfd, &vdx);
	}


	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
