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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include <sys/types.h>
#include "base_conversion.h"
#include <sys/isa_defs.h>

/*
 * Miscellaneous support routines used in base conversion
 */

static const union {
	unsigned int	u[2];
	double		d;
} C[] = {
#ifdef _LITTLE_ENDIAN
	{ 0x00000000u, 0x00100000u },
	{ 0x00000001u, 0x7ff00000u }
#else
	{ 0x00100000u, 0x00000000u },
	{ 0x7ff00000u, 0x00000001u }
#endif
};

#define	minnormal	C[0].d
#define	signalingnan	C[1].d

/* raise the floating point exceptions indicated by ef */
void
__base_conversion_set_exception(fp_exception_field_type ef)
{
	double	t;
	volatile double tstored __unused;

	if (ef == (1 << fp_inexact)) {
		t = 9.999999962747097015E-1;
		/*
		 * 28 sig bits so product isn't inexact in extended
		 * accumulator, causing two inexact traps.
		 */
	} else if ((ef & (1 << fp_invalid)) != 0) {
		t = signalingnan;
	} else if ((ef & (1 << fp_overflow)) != 0) {
		t = 4.149515553422842866E+180;
		/*
		 * 28 sig bits so product isn't inexact in extended
		 * accumulator, causing inexact trap prior to overflow trap
		 * on store.
		 */
	} else if ((ef & (1 << fp_underflow)) != 0) {
		t = minnormal;
	} else
		return;

	/* Storage forces exception */
	tstored = t * t;
#if defined(__lint)
	tstored = tstored;
#endif
}

/*
 * The following routine is no longer used in libc, but we have
 * to leave it for now because it's still used by Sun's old Fortran
 * runtime libraries.  Today this is a bug; in the days of SunOS 4.x,
 * when the relevant design decisions were made, it was a feature.
 */
enum fp_class_type
__class_quadruple(quadruple *x)
{
	quadruple_equivalence kluge;

	kluge.x = *x;
	if (kluge.f.msw.exponent == 0) {	/* 0 or sub */
		if ((kluge.f.msw.significand == 0) &&
		    (kluge.f.significand2 == 0) &&
		    (kluge.f.significand3 == 0) &&
		    (kluge.f.significand4 == 0))
			return (fp_zero);
		else
			return (fp_subnormal);
	} else if (kluge.f.msw.exponent == 0x7fff) {	/* inf or nan */
		if ((kluge.f.msw.significand == 0) &&
		    (kluge.f.significand2 == 0) &&
		    (kluge.f.significand3 == 0) &&
		    (kluge.f.significand4 == 0))
			return (fp_infinity);
		else if ((kluge.f.msw.significand & 0xffff) >=
		    (unsigned int)0x8000)
			return (fp_quiet);
		else
			return (fp_signaling);
	} else
		return (fp_normal);
}
