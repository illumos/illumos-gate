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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "utility.h"

#define	first(f)	(0)
#define	last(f)		(f->maxpage - 1)

/* next - return next page after current page(cyclic) */
static int
next(FORM *f)
{
	int p = P(f);

	if (++p > last(f))
		p = first(f);
	return (p);
}

/* prev - return previous page before current page(cyclic) */
static int
prev(FORM *f)
{
	int p = P(f);

	if (--p < first(f))
		p = last(f);
	return (p);
}

int
_next_page(FORM *f)
{
	return (_set_form_page(f, next(f), (FIELD *) 0));
}

int
_prev_page(FORM *f)
{
	return (_set_form_page(f, prev(f), (FIELD *) 0));
}

int
_first_page(FORM *f)
{
	return (_set_form_page(f, first(f), (FIELD *) 0));
}

int
_last_page(FORM *f)
{
	return (_set_form_page(f, last(f), (FIELD *) 0));
}
