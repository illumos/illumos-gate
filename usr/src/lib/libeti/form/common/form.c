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

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SVr4.0 1.8 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

#define	MAX_BUF		81

/* default form */

static FORM default_form =
{
			0,			/* status	*/
			0,			/* rows		*/
			0,			/* cols		*/
			0,			/* currow	*/
			0,			/* curcol	*/
			0,			/* toprow	*/
			0,			/* begincol */
			-1,			/* maxfield	*/
			-1,			/* maxpage	*/
			-1,			/* curpage	*/
			O_NL_OVERLOAD	|
			O_BS_OVERLOAD,		/* opts		*/
			(WINDOW *) 0,		/* win		*/
			(WINDOW *) 0,		/* sub		*/
			(WINDOW *) 0,		/* w		*/
			(FIELD **) 0,		/* field	*/
			(FIELD *) 0,		/* current	*/
			(_PAGE *) 0,		/* page		*/
			(char *) 0,		/* usrptr	*/
			(PTF_void) 0,		/* forminit	*/
			(PTF_void) 0,		/* formterm	*/
			(PTF_void) 0,		/* fieldinit	*/
			(PTF_void) 0,		/* fieldterm	*/
};

FORM * _DEFAULT_FORM = &default_form;

/*
 * insert - insert field f into sorted list pointed
 * to by head. return (possibly new) head of list.
 */
static FIELD *
insert(FIELD *f, FIELD *head)
{
	FIELD *p;
	FIELD *newhead;
	int frow, fcol;

	if (head) {
		p = newhead = head;

		frow = f->frow;
		fcol = f->fcol;

		while ((p->frow < frow) ||
		    (p->frow == frow && p->fcol < fcol)) {
			p = p->snext;

			if (p == head) {
				head = (FIELD *) 0;
				break;
			}
		}
		f->snext	= p;
		f->sprev	= p->sprev;
		f->snext->sprev	= f;
		f->sprev->snext	= f;

		if (p == head)
			newhead = f;	/* insert at head of list */
	} else
		newhead = f->sprev = f->snext = f; /* initialize new list */

	return (newhead);
}

/* sort_form - sort fields on form(per page) */
static void
sort_form(FORM *f)
{
	FIELD **field;
	FIELD *p;
	int i, page, pmin, pmax;

	field = f->field;

	for (page = 0; page < f->maxpage; ++page) {	/* for each page */
		p = (FIELD *) 0;

		pmin = Pmin(f, page);
		pmax = Pmax(f, page);

		for (i = pmin; i <= pmax; ++i) {	/* for each field */
			field[i]->index = i;
			field[i]->page = page;

			p = insert(field[i], p);
		}
		Smin(f, page) = p->index;		/* set sorted min */
		Smax(f, page) = p->sprev->index;	/* set sorted max */
	}
}

/* merge - xmax/ymax is the minimum window size to hold field f */
static void
merge(FIELD *f, FORM *form) /* adjust form dimensions to include field f */
{
	int xmax = f->fcol + f->cols;
	int ymax = f->frow + f->rows;

	if (form->rows < ymax)
		form->rows = ymax;
	if (form->cols < xmax)
		form->cols = xmax;
}

/* disconnect_fields - disconnect fields from form */
static void
disconnect_fields(FORM *form)
{
	FIELD **f = form->field;

	if (f)
		while (*f) {
			if ((*f)->form == form)
				(*f)->form = (FORM *) 0;
			++f;
		}

	form->rows		= 0;
	form->cols		= 0;
	form->maxfield	= -1;
	form->maxpage		= -1;
	form->field		= (FIELD **) 0;
}

/* connect_fields - connect fields to form */
static int
connect_fields(FORM *f, FIELD **x)
{
	_PAGE *	page;

	int	nf,		/* number of fields	*/
		np;		/* number of pages	*/
	int	i;

	f->field = x;
	f->maxfield = 0;
	f->maxpage = 0;

	if (!x)
		return (E_OK);	/* null field array */

	for (nf = 0, np = 0; x[nf]; ++nf) {
		if (nf == 0 || Status(x[nf], NEW_PAGE))
			++np;			/* count pages */

		if (x[nf]->form)
			return (E_CONNECTED);
		else
			x[nf]->form = f;	/* connect field to form */
	}
	if (nf == 0)
		return (E_BAD_ARGUMENT);		/* no fields */

	if (arrayAlloc(f->page, np, _PAGE)) {
		page = f->page;

		for (i = 0; i < nf; ++i) {
			if (i == 0)
				page->pmin = i;

			else if (Status(x[i], NEW_PAGE)) {
				page->pmax = i - 1;
				++page;
				page->pmin = i;
			}
			merge(x[i], f);
		}
		page->pmax = nf - 1;
		f->maxfield = nf;
		f->maxpage = np;
		sort_form(f);
		return (E_OK);
	}
	return (E_SYSTEM_ERROR);
}

FORM *
new_form(FIELD **field)
{
	FORM *f;

	if (Alloc(f, FORM)) {
		*f = *_DEFAULT_FORM;

		if (connect_fields(f, field) == E_OK) {
			if (f->maxpage) {
				P(f) = 0;
				C(f) = _first_active(f);
			} else {
				P(f) = -1;
				C(f) = (FIELD *) 0;
			}
			return (f);
		}
	}
	(void) free_form(f);
	return ((FORM *) 0);
}

int
free_form(FORM *f)
{
	if (!f)
		return (E_BAD_ARGUMENT);

	if (Status(f, POSTED))
		return (E_POSTED);

	disconnect_fields(f);
	Free(f->page);
	Free(f);
	return (E_OK);
}

int
set_form_fields(FORM *f, FIELD **fields)
{
	FIELD **p;
	int v;

	if (!f)
		return (E_BAD_ARGUMENT);

	if (Status(f, POSTED))
		return (E_POSTED);

	p = f->field;
	disconnect_fields(f);

	if ((v = connect_fields(f, fields)) == E_OK) {
		if (f->maxpage) {
			P(f) = 0;
			C(f) = _first_active(f);
		} else {
			P(f) = -1;
			C(f) = (FIELD *) 0;
		}
	} else
		(void) connect_fields(f, p);	/* reconnect original fields */
	return (v);
}

FIELD **
form_fields(FORM *f)
{
	return (Form(f)->field);
}

int
field_count(FORM *f)
{
	return (Form(f)->maxfield);
}

int
scale_form(FORM *f, int *rows, int *cols)
{
	if (!f)
		return (E_BAD_ARGUMENT);

	if (!f->field)
		return (E_NOT_CONNECTED);

	*rows = f->rows;
	*cols = f->cols;
	return (E_OK);
}

BOOLEAN
data_behind(FORM *f)
{
	return (OneRow(C(f)) ? B(f) != 0 : T(f) != 0);
}

/* _data_ahead - return ptr to last non-pad char in v[n] (v on failure) */
static char *
_data_ahead(char *v, int pad, int n)
{
	char *vend = v + n;
	while (vend > v && *(vend - 1) == pad) --vend;
	return (vend);
}

BOOLEAN
data_ahead(FORM *f)
{
	static char	buf[ MAX_BUF ];
	char		*bptr = buf;
	WINDOW		*w = W(f);
	FIELD		*c = C(f);
	int		ret = FALSE;
	int		pad = Pad(c);
	int		cols = c->cols;
	int		dcols;
	int		drows;
	int		flag = cols > MAX_BUF - 1;
	int		start;
	int		chunk;

	if (flag)
		bptr = malloc(cols + 1);

	if (OneRow(c)) {
		dcols = c->dcols;
		start = B(f) + cols;

		while (start < dcols) {
			chunk = MIN(cols, dcols - start);
			(void) wmove(w, 0, start);
			(void) winnstr(w, bptr, chunk);

			if (bptr != _data_ahead(bptr, pad, chunk)) {
				ret = (TRUE);
				break;
			}

			start += cols;
		}
	} else {	/* else multi-line field */
		drows = c->drows;
		start = T(f) + c->rows;

		while (start < drows) {
			(void) wmove(w, start++, 0);
			(void) winnstr(w, bptr, cols);

			if (bptr != _data_ahead(bptr, pad, cols)) {
				ret = TRUE;
				break;
			}
		}
	}

	if (flag)
		(void) free(bptr);

	(void) wmove(w, Y(f), X(f));
	return (ret);
}
