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

#pragma weak fegetround = __fegetround
#pragma weak fesetround = __fesetround

#pragma weak fegetround96 = __fegetround
#pragma weak fesetround96 = __fesetround96

#include "fenv_synonyms.h"
#include <fenv.h>
#include <ucontext.h>
#include <thread.h>
#include "fex_handler.h"
#include "fenv_inlines.h"

#if defined(__i386) && !defined(__amd64)
#include <float.h>
#endif

int fegetround(void)
{
	unsigned long	fsr;

	__fenv_getfsr(&fsr);
	return (int)__fenv_get_rd(fsr);
}

int fesetround(int r)
{
	unsigned long	fsr;

	if (r & ~3)
		return -1;
	__fenv_getfsr(&fsr);
	__fenv_set_rd(fsr, r);
	__fenv_setfsr(&fsr);
#if defined(__i386) && !defined(__amd64)
	FLT_ROUNDS = (0x2D >> (r << 1)) & 3;	/* 0->1, 1->3, 2->2, 3->0 */
#endif
	return 0;
}

int fesetround96(int r)
{
	unsigned long	fsr;

	if (r & ~3)
		return 0;
	__fenv_getfsr(&fsr);
	__fenv_set_rd(fsr, r);
	__fenv_setfsr(&fsr);
#if defined(__i386) && !defined(__amd64)
	FLT_ROUNDS = (0x2D >> (r << 1)) & 3;	/* 0->1, 1->3, 2->2, 3->0 */
#endif
	return 1;
}
