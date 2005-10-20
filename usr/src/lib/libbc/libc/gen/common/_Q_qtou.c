/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1995 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "_Qquad.h"
#include "_Qglobals.h"

unsigned
_Q_qtou(QUAD x)
{
	unpacked	px;
	QUAD		c;
	unsigned	u,*pc = (unsigned*)&c,r;
	enum fp_direction_type saved_fp_direction = fp_direction;

	pc[0] = 0x401e0000; pc[1]=pc[2]=pc[3]=0;	/* c = 2^31 */
	r = 0;
	u = *(int*)&x;	/* high part of x */
	if(u>=0x401e0000&&u<0x401f0000) {
		r = 0x80000000;
		x = _Q_sub(x,c);
	}

	_fp_current_exceptions = 0;
	fp_direction = fp_tozero;
	_fp_unpack(&px, (int *)&x,fp_op_extended);
	_fp_pack(&px, (int *)&u,fp_op_integer);
	_Q_set_exception(_fp_current_exceptions);
	fp_direction = saved_fp_direction;
	return (u|r);
}
