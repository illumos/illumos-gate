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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak feclearexcept = __feclearexcept
#pragma weak feraiseexcept = __feraiseexcept
#pragma weak fetestexcept = __fetestexcept
#pragma weak fegetexceptflag = __fegetexceptflag
#pragma weak fesetexceptflag = __fesetexceptflag

#pragma weak feclearexcept96 = __feclearexcept
#pragma weak feraiseexcept96 = __feraiseexcept
#pragma weak fetestexcept96 = __fetestexcept
#pragma weak fegetexceptflag96 = __fegetexceptflag
#pragma weak fesetexceptflag96 = __fesetexceptflag

#include "fenv_synonyms.h"
#include <fenv.h>
#include <sys/ieeefp.h>
#include <ucontext.h>
#include <thread.h>
#include "fex_handler.h"
#include "fenv_inlines.h"


int feclearexcept(int e)
{
	unsigned long	fsr;

	__fenv_getfsr(&fsr);
	__fenv_set_ex(fsr, __fenv_get_ex(fsr) & ~e);
	__fenv_setfsr(&fsr);
	if (fex_get_log())
		__fex_update_te();
	return 0;
}

/*
*  note - __fex_hdlr depends on fetestexcept following feraiseexcept
*/
int feraiseexcept(int e)
{
	volatile double	t;
	unsigned long	fsr;

	if (e & FE_INVALID) {
		t = 0.0;
		t /= 0.0;
	}
	if (e & FE_DIVBYZERO) {
		t = 1.0e300;
		t /= 0.0;
	}
	if (e & FE_OVERFLOW) {
		/* if overflow is not trapped, avoid raising inexact */
		__fenv_getfsr(&fsr);
		if (!(__fenv_get_te(fsr) & (1 << fp_trap_overflow))) {
			__fenv_set_ex(fsr, __fenv_get_ex(fsr) | FE_OVERFLOW);
			__fenv_setfsr(&fsr);
		}
		else {
			t = 1.0e300;
			t *= 1.0e300;
		}
	}
	if (e & FE_UNDERFLOW) {
		/* if underflow is not trapped, avoid raising inexact */
		__fenv_getfsr(&fsr);
		if (!(__fenv_get_te(fsr) & (1 << fp_trap_underflow))) {
			__fenv_set_ex(fsr, __fenv_get_ex(fsr) | FE_UNDERFLOW);
			__fenv_setfsr(&fsr);
		}
		else {
			t = 1.0e-307;
			t -= 1.001e-307;
		}
	}
	if (e & FE_INEXACT) {
		t = 1.0e300;
		t += 1.0e-307;
	}
	return 0;
}

int fetestexcept(int e)
{
	unsigned long	fsr;

	__fenv_getfsr(&fsr);
	return (int)__fenv_get_ex(fsr) & e;
}

int fegetexceptflag(fexcept_t *p, int e)
{
	unsigned long	fsr;

	__fenv_getfsr(&fsr);
	*p = (int)__fenv_get_ex(fsr) & e;
	return 0;
}

int fesetexceptflag(const fexcept_t *p, int e)
{
	unsigned long	fsr;

	__fenv_getfsr(&fsr);
	__fenv_set_ex(fsr, (((int)__fenv_get_ex(fsr) & ~e) | (*p & e)) &
		FE_ALL_EXCEPT);
	__fenv_setfsr(&fsr);
	if (fex_get_log())
		__fex_update_te();
	return 0;
}
