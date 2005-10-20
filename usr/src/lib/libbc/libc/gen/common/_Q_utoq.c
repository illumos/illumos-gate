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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "_Qquad.h"
#include "_Qglobals.h"

QUAD
_Q_utoq(unsigned x)
{
	unpacked	px;
	QUAD		q,c;
	int 		*pc =(int*)&c;
	pc[0] = 0x401e0000; pc[1]=pc[2]=pc[3]=0;	/* pc = 2^31 */
	if((x&0x80000000)!=0) {
		x ^= 0x80000000;
		_fp_unpack(&px, (int *)&x,fp_op_integer);
		_fp_pack(&px, (int *)&q,fp_op_extended);
		q = _Q_add(q,c);
	} else {
		_fp_unpack(&px, (int *)&x,fp_op_integer);
		_fp_pack(&px, (int *)&q,fp_op_extended);
	}
	return (q);
}
