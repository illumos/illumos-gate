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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

#include "_Qquad.h"
#include "_Qglobals.h"

static double zero = 0.0, tiny = 1.0e-300, huge = 1.0e300;
static dummy();
extern _Q_get_rp_rd(), _Q_set_exception();

QUAD 
_Q_add(x,y)
	QUAD x,y;
{
	unpacked	px,py,pz;
	QUAD		z;
	_fp_current_exceptions = 0;
	_Q_get_rp_rd();		/* get fp_precision, fp_direction */
	_fp_unpack(&px,&x,fp_op_extended);
	_fp_unpack(&py,&y,fp_op_extended);
	_fp_add(&px,&py,&pz);
	_fp_pack(&pz,&z,fp_op_extended);
	_Q_set_exception(_fp_current_exceptions);
	return z;
}

/* don't use ieee_flags(), use machine dependent routine 
_Q_get_rp_rd()
{
	char		*out;
	fp_precision = ieee_flags("get","precision","",&out);
	fp_direction = ieee_flags("get","direction","",&out);
	return 0;
}
*/

_Q_set_exception(ex)
	unsigned ex;
{
    /* simulate exceptions using double arithmetic */
	double t;
	if((ex&(1<<fp_invalid))!=0)	t = (zero/zero);
	if((ex&(1<<fp_overflow))!=0)	t = (huge*huge);
	if((ex&(1<<fp_underflow))!=0)	t = (tiny*tiny);
	if((ex&(1<<fp_division))!=0)	t = (tiny/zero);
	if((ex&(1<<fp_inexact))!=0)	t = (huge+tiny);
	dummy(t);  /* prevent optimizer eliminating previous expression */
	return 0;
}
	
static 
dummy(x)
	double x;
{
	return 0;
}
