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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* integer function _Q_feq, _Q_fne, _Q_fgt, _Q_fge, _Q_flt, _Q_fle */

#include "_Qquad.h"

int
_Q_feq(QUAD x, QUAD y)
{
	enum fcc_type	fcc;
	fcc = _Q_cmp(x,y);
	return (fcc_equal==fcc);
}

int
_Q_fne(QUAD x, QUAD y)
{
	enum fcc_type	fcc;
	fcc = _Q_cmp(x,y);
	return (fcc_equal!=fcc);
}

int
_Q_fgt(QUAD x, QUAD y)
{
	enum fcc_type	fcc;
	fcc = _Q_cmpe(x,y);
	return (fcc_greater==fcc);
}

int
_Q_fge(QUAD x, QUAD y)
{
	enum fcc_type	fcc;
	fcc = _Q_cmpe(x,y);
	return (fcc_greater==fcc||fcc_equal==fcc);
}

int
_Q_flt(QUAD x, QUAD y)
{
	enum fcc_type	fcc;
	fcc = _Q_cmpe(x,y);
	return (fcc_less==fcc);
}

int
_Q_fle(QUAD x, QUAD y)
{
	enum fcc_type	fcc;
	fcc = _Q_cmpe(x,y);
	return (fcc_less==fcc||fcc_equal==fcc);
}
