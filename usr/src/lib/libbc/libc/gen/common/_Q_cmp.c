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

enum fcc_type
_Q_cmp(QUAD x, QUAD y)
{
	unpacked	px,py,pz;
	enum fcc_type	fcc;
	_fp_current_exceptions = 0;
	_fp_unpack(&px, (int *)&x,fp_op_extended);
	_fp_unpack(&py, (int *)&y,fp_op_extended);
	fcc = _fp_compare(&px,&py,0);	/* quiet NaN unexceptional */
	_Q_set_exception(_fp_current_exceptions);
	return (fcc);
}
