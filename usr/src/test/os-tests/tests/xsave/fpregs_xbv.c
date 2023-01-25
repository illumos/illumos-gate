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
 * In illumos#15367 we noted that on some CPUs it was possible to get the xsave
 * state into a place where it has not set components that are used for the x87
 * and XMM state in the xsave component bit-vector (what we call the
 * xsh_xstate_bv or xbv for short). This test attempts to create those
 * situations and then get a ucontext_t to see that we actually have cleared it
 * out. Because this behavior varies from CPU to CPU (e.g. in the original case
 * we only saw this on AMD and not Intel), it can be tricky to guarantee we've
 * recreated this.
 */

#include <err.h>
#include <stdio.h>
#include <sys/types.h>
#include <ucontext.h>
#include <stdlib.h>

int
main(void)
{
	ucontext_t ctx;
	upad128_t u, *up;

	u._l[0] = 0x1;
	u._l[1] = 0x2;
	u._l[2] = 0x3;
	u._l[3] = 0x4;

	/*
	 * Load %xmm0 and then lock in the data into the pcb with a call to
	 * getcontext(2) which will force an FPU save.
	 */
	/* BEGIN CSTYLED */
	__asm__ __volatile__ ("movdqu %0, %%xmm0" : : "m" (u));
	__asm__ __volatile__ ("fldl %0" : : "m" (u));
	/* END CSTYLED */
	if (getcontext(&ctx) != 0) {
		errx(EXIT_FAILURE, "TEST_FAILED: failed to get initial "
		    "ucontext");
	}

	/*
	 * Attempt to reset the FPU at this point and then call getcontext. The
	 * fninit is for the x87 part. The vzeroall covers all the higher
	 * registers and this combined should reset the x87 and xmm regions back
	 * to 0. It appears that on some Intel processors, the vzeroall is
	 * required to get the XMM set to not be written out as opposed to just
	 * doing a pxor or similar.
	 */
	/* BEGIN CSTYLED */
        __asm__ __volatile__ ("fninit" : : :);
        __asm__ __volatile__ ("vzeroall" : : :);
	/* END CSTYLED */
	if (getcontext(&ctx) != 0) {
		errx(EXIT_FAILURE, "TEST_FAILED: failed to get second "
		    "ucontext");
	}
	up = &ctx.uc_mcontext.fpregs.fp_reg_set.fpchip_state.xmm[0];
	if (up->_l[0] != 0 || up->_l[1] != 0 || up->_l[2] != 0 ||
	    up->_l[3] != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: %%xmm0 was not zero, found: "
		    "0x%x 0x%x 0x%x 0x%x", up->_l[3], up->_l[2],
		    up->_l[1], up->_l[0]);
	}

	(void) printf("TEST PASSED: successfully got zeored %%xmm0\n");
	return (EXIT_SUCCESS);
}
