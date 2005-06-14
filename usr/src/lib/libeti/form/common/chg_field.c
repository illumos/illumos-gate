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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include "utility.h"

#define	first(f)	(f->field [Pmin(f, P(f))])
#define	last(f)		(f->field [Pmax(f, P(f))])
#define	sfirst(f)	(f->field [Smin(f, P(f))])
#define	slast(f)	(f->field [Smax(f, P(f))])

#define	Active(f)	(Opt(f, O_ACTIVE) && Opt(f, O_VISIBLE))

/* next - return next active field on page after f(user defined order) */
static FIELD *
next(FIELD *f)
{
	FORM	*t	= f->form;
	FIELD	**p	= t->field + f->index;
	FIELD	**pmin	= t->field + Pmin(t, P(t));
	FIELD	**pmax	= t->field + Pmax(t, P(t));

	do
		p = p == pmax ? pmin : p+1;

	while ((!Active(*p)) && (*p != f));

	return (*p);
}

/* prev - return previous active field on page before f */
static FIELD *
prev(FIELD *f)
{
	FORM  *t	= f->form;
	FIELD **p	= t->field + f->index;
	FIELD **pmin	= t->field + Pmin(t, P(t));
	FIELD **pmax	= t->field + Pmax(t, P(t));

	do
		p = p == pmin ? pmax : p-1;

	while ((!Active(*p)) && (*p != f));

	return (*p);
}

/* snext - return next active field on page after f(sorted order) */
static FIELD *
snext(FIELD *f)
{
	FIELD *x = f;

	do
		f = f->snext;

	while ((!Active(f)) && (f != x));

	return (f);
}

/* sprev - return previous active field on page before f(sorted order) */
static FIELD *
sprev(FIELD *f)
{
	FIELD *x = f;

	do
		f = f->sprev;

	while ((!Active(f)) && (f != x));

	return (f);
}

/* left - return active field on page left of f */
static FIELD *
left(FIELD *f)
{
	int row = f->frow;

	do
		f = sprev(f);

	while (f->frow != row);

	return (f);
}

/* right - return active field on page right of f */
static FIELD *
right(FIELD *f)
{
	int row = f->frow;

	do
		f = snext(f);

	while (f->frow != row);

	return (f);
}

/* up - return active field on page above f */
static FIELD *
up(FIELD *f)
{
	int row = f->frow;
	int col = f->fcol;

	do
		f = sprev(f);

	while (f->frow == row && f->fcol != col);

	if (f->frow != row) {
		row = f->frow;

		while (f->frow == row && f->fcol > col)
			f = sprev(f);

		if (f->frow != row)
			f = snext(f);
	}
	return (f);
}

/* down - return active field on page below f */
static FIELD *
down(FIELD *f)
{
	int row = f->frow;
	int col = f->fcol;

	do
		f = snext(f);

	while (f->frow == row && f->fcol != col);

	if (f->frow != row) {
		row = f->frow;

		while (f->frow == row && f->fcol < col)
			f = snext(f);

		if (f ->frow != row)
			f = sprev(f);
	}
	return (f);
}

	/*
	 *  _next_field
	 */

int
_next_field(FORM *f)
{
	return (_set_current_field(f, next(C(f))));
}

int
_prev_field(FORM *f)
{
	return (_set_current_field(f, prev(C(f))));
}

int
_first_field(FORM *f)
{
	return (_set_current_field(f, next(last(f))));
}

int
_last_field(FORM *f)
{
	return (_set_current_field(f, prev(first(f))));
}

int
_snext_field(FORM *f)
{
	return (_set_current_field(f, snext(C(f))));
}

int
_sprev_field(FORM *f)
{
	return (_set_current_field(f, sprev(C(f))));
}

int
_sfirst_field(FORM *f)
{
	return (_set_current_field(f, snext(slast(f))));
}

int
_slast_field(FORM *f)
{
	return (_set_current_field(f, sprev(sfirst(f))));
}

int
_left_field(FORM *f)
{
	return (_set_current_field(f, left(C(f))));
}

int
_right_field(FORM *f)
{
	return (_set_current_field(f, right(C(f))));
}

int
_up_field(FORM *f)
{
	return (_set_current_field(f, up(C(f))));
}

int
_down_field(FORM *f)
{
	return (_set_current_field(f, down(C(f))));
}

FIELD *
_first_active(FORM *f)
{
	return (next(last(f)));
}
