/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Floating point configuration.
 */

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/x86_archext.h>
#include <sys/archsystm.h>
#include <sys/fp.h>
#include <sys/cmn_err.h>

#define	XMM_ALIGN	16

/*
 * If fpu_exists is non-zero, fpu_probe will attempt to use any
 * hardware FPU (subject to other constraints, see below).  If
 * fpu_exists is zero, fpu_probe will report that there is no
 * FPU even if there is one.
 */
int fpu_exists = 1;

int fp_kind = FP_387;

/*
 * Mechanism to save FPU state.
 */
#if defined(__amd64)
int fp_save_mech = FP_FXSAVE;
#elif defined(__i386)
int fp_save_mech = FP_FNSAVE;
#endif

/*
 * The variable fpu_ignored is provided to allow other code to
 * determine whether emulation is being done because there is
 * no FPU or because of an override requested via /etc/system.
 */
int fpu_ignored = 0;

/*
 * Used by ppcopy and ppzero to determine whether or not to use the
 * SSE-based pagecopy and pagezero routines
 */
int use_sse_pagecopy = 0;
int use_sse_pagezero = 0;
int use_sse_copy = 0;

#if defined(__i386)

/*
 * The variable fpu_pentium_fdivbug is provided to allow other code to
 * determine whether the system contains a Pentium with the FDIV problem.
 */
int fpu_pentium_fdivbug = 0;

#endif

#if defined(__xpv)

/*
 * Use of SSE or otherwise is forcibly configured for us by the hypervisor.
 */

#define	ENABLE_SSE()
#define	DISABLE_SSE()

#else	/* __xpv */

#define	ENABLE_SSE()	setcr4(CR4_ENABLE_SSE_FLAGS(getcr4()))
#define	DISABLE_SSE()	setcr4(CR4_DISABLE_SSE_FLAGS(getcr4()))

#endif	/* __xpv */

/*
 * Try and figure out what kind of FP capabilities we have, and
 * set up the control registers accordingly.
 */
void
fpu_probe(void)
{
	do {
		if (fpu_initial_probe() != 0)
			continue;

		if (fpu_exists == 0) {
			fpu_ignored = 1;
			continue;
		}

#if defined(__i386)
		fpu_pentium_fdivbug = fpu_probe_pentium_fdivbug();
		/*
		 * The test does some real floating point operations.
		 * Reset it back to previous state.
		 */
		(void) fpu_initial_probe();

		if (fpu_pentium_fdivbug != 0) {
			fpu_ignored = 1;
			continue;
		}
#endif

#ifndef __xpv
		/*
		 * Check and see if the fpu is present by looking
		 * at the "extension type" bit.  (While this used to
		 * indicate a 387DX coprocessor in days gone by,
		 * it's forced on by modern implementations for
		 * compatibility.)
		 */
		if ((getcr0() & CR0_ET) == 0)
			continue;
#endif

#if defined(__amd64)
		/*
		 * SSE and SSE2 are required for the 64-bit ABI.
		 *
		 * If they're not present, we can in principal run
		 * 32-bit userland, though 64-bit processes will be hosed.
		 *
		 * (Perhaps we should complain more about this case!)
		 */
		if (is_x86_feature(x86_featureset, X86FSET_SSE) &&
		    is_x86_feature(x86_featureset, X86FSET_SSE2)) {
			fp_kind |= __FP_SSE;
			ENABLE_SSE();

			if (is_x86_feature(x86_featureset, X86FSET_AVX)) {
				ASSERT(is_x86_feature(x86_featureset,
				    X86FSET_XSAVE));
				fp_kind |= __FP_AVX;
			}

			if (is_x86_feature(x86_featureset, X86FSET_XSAVE)) {
				fp_save_mech = FP_XSAVE;
				fpsave_ctxt = xsave_ctxt;
				patch_xsave();
			}
		}
#elif defined(__i386)
		/*
		 * SSE and SSE2 are both optional, and we patch kernel
		 * code to exploit it when present.
		 */
		if (is_x86_feature(x86_featureset, X86FSET_SSE)) {
			fp_kind |= __FP_SSE;
			ENABLE_SSE();
			fp_save_mech = FP_FXSAVE;
			fpsave_ctxt = fpxsave_ctxt;

			if (is_x86_feature(x86_featureset, X86FSET_SSE2)) {
				patch_sse2();
			}

			if (is_x86_feature(x86_featureset, X86FSET_AVX)) {
				ASSERT(is_x86_feature(x86_featureset,
				    X86FSET_XSAVE));
				fp_kind |= __FP_AVX;
			}

			if (is_x86_feature(x86_featureset, X86FSET_XSAVE)) {
				fp_save_mech = FP_XSAVE;
				fpsave_ctxt = xsave_ctxt;
				patch_xsave();
			} else {
				patch_sse();	/* use fxrstor */
			}
		} else {
			remove_x86_feature(x86_featureset, X86FSET_SSE2);
			/*
			 * We will not likely to have a chip with AVX but not
			 * SSE. But to be safe we disable AVX if SSE is not
			 * enabled.
			 */
			remove_x86_feature(x86_featureset, X86FSET_AVX);
			/*
			 * (Just in case the BIOS decided we wanted SSE
			 * enabled when we didn't. See 4965674.)
			 */
			DISABLE_SSE();
		}
#endif
		if (is_x86_feature(x86_featureset, X86FSET_SSE2)) {
			use_sse_pagecopy = use_sse_pagezero = use_sse_copy = 1;
		}

		if (fp_kind & __FP_SSE) {
			struct fxsave_state *fx;
			uint8_t fxsave_state[sizeof (struct fxsave_state) +
			    XMM_ALIGN];

			/*
			 * Extract the mxcsr mask from our first fxsave
			 */
			fx = (void *)(((uintptr_t)(&fxsave_state[0]) +
			    XMM_ALIGN) & ~(XMM_ALIGN - 1ul));

			fx->fx_mxcsr_mask = 0;
			fxsave_insn(fx);
			if (fx->fx_mxcsr_mask != 0) {
				/*
				 * Override default mask initialized in fpu.c
				 */
				sse_mxcsr_mask = fx->fx_mxcsr_mask;
			}
		}

		setcr0(CR0_ENABLE_FPU_FLAGS(getcr0()));
		return;
		/*CONSTANTCONDITION*/
	} while (0);

	/*
	 * No FPU hardware present
	 */
	setcr0(CR0_DISABLE_FPU_FLAGS(getcr0()));
	DISABLE_SSE();
	fp_kind = FP_NO;
	fpu_exists = 0;
}
