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
 * This test verifies the following:
 *
 *   o xregs and fpregs report the same content for the xmm registers at least.
 *   o A write to xregs is reflected in reads of fpregs.
 *   o A write to the fpregs is reflected in reads of xregs and doesn't
 *     clobber additional state in xregs.
 *   o A thread in our victim process sees the final state here and can print
 *     that out.
 *   o As a side effect it makes sure that libproc isn't incorrectly caching
 *     register info on handles.
 *
 * We use the xsu_dump process of the same bitness as us.
 */

#include <err.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "xsave_util.h"

static xsu_fpu_t fpu;

int
main(int argc, char *argv[])
{
	uint32_t seed, hwsup;
	unsigned long ul;
	char *eptr;
	prxregset_t *prx, *cmp_prx;
	size_t prx_len, cmp_prx_len;
	xsu_proc_t xp;
	fpregset_t fpr;

	if (argc != 5) {
		errx(EXIT_FAILURE, "missing args: <prog> <output file> "
		    "<seed> <func>");
	}

	errno = 0;
	ul = strtoul(argv[3], &eptr, 0);
	if (errno != 0 || *eptr != '\0') {
		errx(EXIT_FAILURE, "seed value is bad: %s", argv[3]);
	}

#if defined(_LP64)
	if (ul > UINT32_MAX) {
		errx(EXIT_FAILURE, "seed %s outside of [0, UINT32_MAX]",
		    argv[3]);
	}
#endif

	seed = (uint32_t)ul;
	hwsup = xsu_hwsupport();
	xsu_fill(&fpu, hwsup, seed);
	xsu_fpu_to_xregs(&fpu, hwsup, &prx, &prx_len);

	(void) memset(&xp, 0, sizeof (xsu_proc_t));
	xp.xp_prog = argv[1];
	xp.xp_arg = argv[2];
	xp.xp_object = "a.out";
	xp.xp_symname = argv[4];
	xsu_proc_bkpt(&xp);

	/*
	 * First get the xregs into a reasonable place.
	 */
	if (Plwp_setxregs(xp.xp_proc, 1, prx, prx_len) != 0) {
		err(EXIT_FAILURE, "failed to set target's xregs");
	}

	/*
	 * Now that we have that, let's go and get the fpregs. Because of
	 * differences between the 32-bit representation and the xsave state in
	 * the xregs, we stick to different checking in an ILP32 vs. LP64 pieces
	 * of this.
	 */
	if (Plwp_getfpregs(xp.xp_proc, 1, &fpr) != 0) {
		err(EXIT_FAILURE, "failed to get the fp registers");
	}

	if (!xsu_fpregs_cmp(&fpr, prx)) {
		errx(EXIT_FAILURE, "fpregs do not reflect xsave changes!");
	}
	(void) printf("TEST PASSED: fpregs read respects xregs write\n");

	/*
	 * Override the xmm registers with the known variant of the seed and set
	 * that. Update the xregs data so we can later compare them usefully.
	 */
	xsu_fpregset_xmm_set(&fpr, seed + INT32_MAX);
	xsu_xregs_xmm_set(prx, seed + INT32_MAX);
	if (Plwp_setfpregs(xp.xp_proc, 1, &fpr) != 0) {
		err(EXIT_FAILURE, "failed to set fpregs");
	}

	if (Plwp_getxregs(xp.xp_proc, 1, &cmp_prx, &cmp_prx_len) != 0) {
		err(EXIT_FAILURE, "failed to get comparison xregs");
	}

	if (!xsu_fpregs_cmp(&fpr, cmp_prx)) {
		errx(EXIT_FAILURE, "fpregs do not reflect xsave changes!");
	}
	(void) printf("TEST PASSED: xregs read respects fpregs write\n");

	if (!xsu_xregs_comp_equal(prx, cmp_prx, PRX_INFO_YMM)) {
		errx(EXIT_FAILURE, "%%ymm state changed across fpregs write");
	}
	(void) printf("TEST PASSED: fpregs did not change other xregs "
	    "components\n");

	xsu_proc_finish(&xp);

	return (EXIT_SUCCESS);
}
