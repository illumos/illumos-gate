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
#include <vmmapi.h>

#include "common.h"


static void
check_caps(struct vcpu *vcpu)
{
	struct capcheck {
		enum vm_cap_type cap;
		bool enabled;
	} checks[] = {
		{ .cap = VM_CAP_HALT_EXIT, .enabled = true, },
		{ .cap = VM_CAP_PAUSE_EXIT, .enabled = false, }
	};

	for (uint_t i = 0; i < ARRAY_SIZE(checks); i++) {
		const char *capname = vm_capability_type2name(checks[i].cap);

		int val;
		if (vm_get_capability(vcpu, checks[i].cap, &val) != 0) {
			err(EXIT_FAILURE, "could not query %s", capname);
		}
		const bool actual = (val != 0);
		if (actual != checks[i].enabled) {
			errx(EXIT_FAILURE, "cap %s unexpected state %d != %d",
			    capname, actual, checks[i].enabled);
		}
	}
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

	/* Check the capabs on a freshly created instance */
	check_caps(vcpu);

	/* Force the instance through a reinit before checking them again */
	if (vm_reinit(ctx, 0) != 0) {
		err(EXIT_FAILURE, "vm_reinit failed");
	}
	check_caps(vcpu);

	vm_vcpu_close(vcpu);
	vm_destroy(ctx);
	(void) printf("%s\tPASS\n", suite_name);
	return (EXIT_SUCCESS);
}
