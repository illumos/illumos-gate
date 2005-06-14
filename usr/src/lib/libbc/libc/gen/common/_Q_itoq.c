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

#define	FUNC	itoq

QUAD
_Q_itoq(x)
	int x;
{
	unpacked	px;
	QUAD		q;
	_fp_unpack(&px,&x,fp_op_integer);
	_fp_pack(&px,&q,fp_op_extended);
	return q;
}
