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

#pragma weak atan2pil = __atan2pil

#include "libm.h"
#include "libm_synonyms.h"

#define GENERIC	long double
#define ATAN2PI	atan2pil
#define ATAN2	atan2l

/* ATAN2PI(y,x)
 *
 *	ATAN2PI(y,x) = ATAN2(y,x)/pi
 */

extern GENERIC 	ATAN2();

static GENERIC
invpi = (GENERIC) 3.183098861837906715377675267450287240689e-0001L;

GENERIC ATAN2PI(y,x)
GENERIC y,x;
{
	return ATAN2(y,x)*invpi;
}
