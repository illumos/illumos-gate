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

/*
 * This test goes through and verifies that the FPU contents are properly
 * restored with a setcontext call.
 */

#include <err.h>
#include <stdlib.h>
#include <ucontext.h>
#include <limits.h>

#include "xsave_util.h"

xsu_fpu_t init_set, override, found;
volatile int exit_status = EXIT_SUCCESS;

static void
setcontext_restore_check(uint32_t hwsup)
{
	xsu_getfpu(&found, hwsup);
	if (xsu_same(&init_set, &found, hwsup)) {
		(void) printf("TEST PASSED: setcontext() correctly restored "
		    "clobbered FPU contents\n");
		exit(exit_status);
	} else {
		errx(EXIT_FAILURE, "TEST_FAILED: setcontext() did not properly "
		    "restore clobbered FPU contents");
	}
}

int
main(void)
{
	ucontext_t *ctx;
	uint32_t start = arc4random();
	uint32_t hwsup = xsu_hwsupport();

	ctx = ucontext_alloc(0);
	if (ctx == NULL) {
		err(EXIT_FAILURE, "failed to get allocate ucontext_t");
	}
	(void) printf("filling starting at 0x%x\n", start);
	xsu_fill(&init_set, hwsup, start);
	xsu_fill(&override, hwsup, start + INT_MAX);
	xsu_setfpu(&init_set, hwsup);

	if (getcontext_extd(ctx, 0) != 0) {
		err(EXIT_FAILURE, "failed to get extended context");
	}

	xsu_ustack_alloc(ctx);
	makecontext(ctx, setcontext_restore_check, 1, hwsup);
	xsu_setfpu(&override, hwsup);
	xsu_getfpu(&found, hwsup);
	if (!xsu_same(&override, &found, hwsup)) {
		warnx("TEST FAILED: override FPU data not found!");
		exit_status = EXIT_FAILURE;
	}
	(void) setcontext(ctx);

	err(EXIT_FAILURE, "TEST FAILED: set context did not work!");
}
