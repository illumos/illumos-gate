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
 * The purpose of this program is to go through and replace all the FPU
 * registers in the floating point state in a ucontext_t and verify that we see
 * what we expected here.
 */

#include <err.h>
#include <stdlib.h>
#include <ucontext.h>

#include "xsave_util.h"

xsu_fpu_t to_set, found;

static void
setcontext_replace_check(uint32_t hwsup)
{
	xsu_getfpu(&found, hwsup);
	if (xsu_same(&to_set, &found, hwsup)) {
		(void) printf("TEST PASSED: setcontext() correctly wrote FPU "
		    "contents\n");
		exit(EXIT_SUCCESS);
	} else {
		errx(EXIT_FAILURE, "TEST_FAILED: setcontext() did not write "
		    "full FPU state");
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
	xsu_fill(&to_set, hwsup, start);
	if (getcontext_extd(ctx, 0) != 0) {
		err(EXIT_FAILURE, "failed to get extended context");
	}

	xsu_overwrite_uctx(ctx, &to_set, hwsup);
	xsu_ustack_alloc(ctx);
	makecontext(ctx, setcontext_replace_check, 1, hwsup);
	(void) setcontext(ctx);

	err(EXIT_FAILURE, "TEST FAILED: set context did not work!");
}
