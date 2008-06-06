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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This set of routines used to be implemented mostly in assembler.
 *
 * Since the purpose they have is now rather vestigial, and 64-bit
 * machines can do operations on 64-bit quantities pretty efficiently,
 * a C implementation seems quite adequate and much more maintainable.
 */

#include "lint.h"
#include <sys/types.h>
#include <sys/dl.h>

typedef union {
	long	xword;
	dl_t	dl;
} dlx_t;

dl_t
ladd(dl_t lop, dl_t rop)
{
	dlx_t r;
	/* LINTED pointer cast may result in improper alignment */
	r.xword = *(long *)&lop + *(long *)&rop;
	return (r.dl);
}

dl_t
lshiftl(dl_t op, int cnt)
{
	dlx_t r;
	if (cnt < 0)
		/* LINTED pointer cast may result in improper alignment */
		r.xword = (long)(*(ulong_t *)&op >> (-cnt));
	else
		/* LINTED pointer cast may result in improper alignment */
		r.xword = *(long *)&op << cnt;
	return (r.dl);
}

int
lsign(dl_t op)
{
	/* LINTED pointer cast may result in improper alignment */
	return ((*(long *)&op) >> 63);
}

dl_t
lsub(dl_t lop, dl_t rop)
{
	dlx_t r;
	/* LINTED pointer cast may result in improper alignment */
	r.xword = *(long *)&lop - *(long *)&rop;
	return (r.dl);
}

dl_t
lmul(dl_t lop, dl_t rop)
{
	dlx_t r;
	/* LINTED pointer cast may result in improper alignment */
	r.xword = *(long *)&lop * *(long *)&rop;
	return (r.dl);
}
