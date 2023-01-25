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
 * This test exercises the swapcontext_extd(2) functionality and verifies that
 * we can swap contexts that have both extended and non-extended ucontext_t's
 * and that we can get at that state in both cases. This test relies on extended
 * states as we try to validate and ensure that they exist.
 */

#include <err.h>
#include <stdlib.h>
#include <ucontext.h>
#include <limits.h>
#include <errno.h>

#include "xsave_util.h"

static xsu_fpu_t mk_fpu, orig_fpu, found;
static ucontext_t *mk_ctx, *orig_ctx;
static volatile int estatus = EXIT_SUCCESS;

static void
mkctx_target(uint32_t hwsup, uint32_t *testp)
{
	xsu_getfpu(&found, hwsup);
	if (!xsu_same(&mk_fpu, &found, hwsup)) {
		estatus = EXIT_FAILURE;
		warnx("TEST FAILED: initial swap had bad FPU");
	} else {
		(void) printf("TEST PASSED: initial swap had correct FPU\n");
	}

	(void) swapcontext_extd(mk_ctx, 0, orig_ctx);
	err(EXIT_FAILURE, "swapcontext_extd() back failed");
}

static void
mkctx_failure(void)
{
	errx(EXIT_FAILURE, "swapcontext_extd() called failure func");
}

int
main(void)
{
	uint32_t hwsup = xsu_hwsupport();
	uint32_t start = arc4random();

	xsu_fill(&mk_fpu, hwsup, start);
	xsu_fill(&orig_fpu, hwsup, start + INT_MAX);

	mk_ctx = ucontext_alloc(0);
	if (mk_ctx == NULL)
		err(EXIT_FAILURE, "failed to allocate extended ucontext_t");
	orig_ctx = ucontext_alloc(0);
	if (orig_ctx == NULL)
		err(EXIT_FAILURE, "failed to allocate extended ucontext_t");

	/*
	 * Set the FPU and snag our initial context. We'll use makecontext to
	 * call this and then change our FPU, swap and start checking and then
	 * swap back.
	 */
	xsu_setfpu(&mk_fpu, hwsup);
	if (getcontext_extd(mk_ctx, 0) != 0) {
		errx(EXIT_FAILURE, "failed to get initial extended context for "
		    "makecontext");
	}

	xsu_ustack_alloc(mk_ctx);
	makecontext(mk_ctx, mkctx_target, 2, hwsup, &hwsup);
	xsu_setfpu(&orig_fpu, hwsup);
	if (swapcontext_extd(orig_ctx, 0, mk_ctx) != 0) {
		err(EXIT_FAILURE, "failed to swap contexts");
	}
	xsu_getfpu(&found, hwsup);
	if (!xsu_same(&orig_fpu, &found, hwsup)) {
		estatus = EXIT_FAILURE;
		warnx("TEST FAILED: swap back did not have the right FPU");
	} else {
		(void) printf("TEST PASSED: swap back had the correct FPU\n");
	}

	xsu_ustack_alloc(mk_ctx);
	makecontext(mk_ctx, mkctx_failure, 0);
	if (swapcontext_extd(orig_ctx, 23, mk_ctx) != -1) {
		errx(EXIT_FAILURE, "somehow got back from error test "
		    "swapcontext_extd() with bad func");
	}
	if (errno != EINVAL) {
		estatus = EXIT_FAILURE;
		warnx("TEST FAILED: swapcontext_extd() with bad flags had "
		    "errno %d expected EINVAL", errno);
	} else {
		(void) printf("TEST PASSED: swapcontext_extd() with bad flags "
		    "has correct errno (EINVAL)\n");
	}

	return (estatus);
}
