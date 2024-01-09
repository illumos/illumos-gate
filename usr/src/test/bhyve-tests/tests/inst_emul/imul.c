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
#include <strings.h>
#include <libgen.h>
#include <assert.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/vmm.h>
#include <sys/vmm_dev.h>
#include <vmmapi.h>

#include "in_guest.h"

#define	MMIO_TEST_BASE	0x10001000
#define	MMIO_TEST_END	0x10002000

static bool
handle_test_mmio(const struct vm_exit *vexit, struct vm_entry *ventry)
{
	/* expecting only reads */
	if (vexit->u.mmio.read == 0) {
		return (false);
	}

	/* expecting only in the [0x10001000 - 0x10002000) range */
	if (vexit->u.mmio.gpa < MMIO_TEST_BASE ||
	    vexit->u.mmio.gpa >= MMIO_TEST_END) {
		return (false);
	}

	/*
	 * Emit a pattern of the lowest 16 bits of the address, ascending by the
	 * 2-byte stride for every 2 additional bytes, as the result.
	 *
	 * For example, an 8-byte read of 0x00001234 would result in:
	 * 0x123a123812361234 being returned
	 */
	const uint16_t addr = vexit->u.mmio.gpa;
	uint64_t val = 0;
	switch (vexit->u.mmio.bytes) {
	case 8:
		val |= (uint64_t)(addr + 6) << 48;
		val |= (uint64_t)(addr + 4) << 32;
		/* FALLTHROUGH */
	case 4:
		val |= (uint32_t)(addr + 2) << 16;
		/* FALLTHROUGH */
	case 2:
		val |= addr;
		break;
	default:
		/* expect only 2/4/8-byte reads */
		return (false);
	}

	ventry_fulfill_mmio(vexit, ventry, val);
	return (true);
}

int
main(int argc, char *argv[])
{
	const char *test_suite_name = basename(argv[0]);
	struct vmctx *ctx = NULL;
	struct vcpu *vcpu;
	int err;

	ctx = test_initialize(test_suite_name);

	if ((vcpu = vm_vcpu_open(ctx, 0)) == NULL) {
		test_fail_errno(errno, "Could not open vcpu0");
	}

	err = test_setup_vcpu(vcpu, MEM_LOC_PAYLOAD, MEM_LOC_STACK);
	if (err != 0) {
		test_fail_errno(err, "Could not initialize vcpu0");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_UNHANDLED:
			if (!handle_test_mmio(&vexit, &ventry)) {
				test_fail_vmexit(&vexit);
			}
			break;
		case VEK_TEST_PASS:
			test_pass();
			break;
		case VEK_TEST_FAIL:
		default:
			test_fail_vmexit(&vexit);
			break;
		}
	} while (true);
}
