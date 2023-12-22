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
#include "test_defs.h"

const char *strict_name = "STRICT_APICV";

static bool
strict_apicv(void)
{
	const char *strict_val;

	if ((strict_val = getenv(strict_name)) != NULL) {
		if (strlen(strict_val) != 0 &&
		    strcmp(strict_val, "0") != 0) {
			return (true);
		}
	}
	return (false);
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

	/*
	 * Although x2APIC should be off by default, make doubly sure by
	 * explicitly setting it so.
	 */
	err = vm_set_x2apic_state(vcpu, X2APIC_DISABLED);
	if (err != 0) {
		test_fail_errno(err, "Could not disable x2apic on vcpu0");
	}

	struct vm_entry ventry = { 0 };
	struct vm_exit vexit = { 0 };

	do {
		const enum vm_exit_kind kind =
		    test_run_vcpu(vcpu, &ventry, &vexit);
		switch (kind) {
		case VEK_REENTR:
			break;
		case VEK_TEST_PASS:
			test_pass();
			break;
		case VEK_TEST_FAIL:
			test_fail_msg("payload signaled failure");
			break;
		case VEK_UNHANDLED:
			/*
			 * Not all APICv-accelerated accesses are properly
			 * handled by the in-kernel emulation today.
			 * (See: illumos #13847).
			 *
			 * To allow this test to be useful on systems without
			 * APICv, we suppress such failures unless explicitly
			 * strict handling is requested.
			 */
			if (vexit.exitcode == VM_EXITCODE_VMX &&
			    (vexit.u.vmx.exit_reason == 44 ||
			    vexit.u.vmx.exit_reason == 56)) {
				if (strict_apicv()) {
					test_fail_vmexit(&vexit);
				}
				(void) fprintf(stderr,
				    "Ignoring APICv access issue\n"
				    "If strictness is desired, "
				    "run with %s=1 in env\n", strict_name);
				test_pass();
			}
			test_fail_vmexit(&vexit);
			break;
		default:
			test_fail_vmexit(&vexit);
			break;
		}
	} while (true);
}
