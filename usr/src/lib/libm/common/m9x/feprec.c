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

#pragma weak __fegetprec = fegetprec
#pragma weak __fesetprec = fesetprec

#include <fenv.h>
#include <ucontext.h>
#include <thread.h>
#include "fex_handler.h"

int fegetprec(void)
{
	unsigned long	fsr;

	__fenv_getfsr(&fsr);
	return __fenv_get_rp(fsr);
}

int fesetprec(int r)
{
	unsigned long	fsr;

	if (r != FE_FLTPREC && r != FE_DBLPREC && r != FE_LDBLPREC)
		return 0;
	__fenv_getfsr(&fsr);
	__fenv_set_rp(fsr, r);
	__fenv_setfsr(&fsr);
	return 1;
}
