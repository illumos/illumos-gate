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

int
post_form(FORM *f)
{
	int x, y, v;

	if (!f)
		return (E_BAD_ARGUMENT);

	if (Status(f, POSTED))
		return (E_POSTED);

	if (!f->field)
		return (E_NOT_CONNECTED);

	getmaxyx(Sub(f), y, x);

	if (f->rows > y || f->cols > x)
		return (E_NO_ROOM);

	v = _set_form_page(f, P(f), C(f));

	if (v != E_OK)
		return (v);

	Set(f, POSTED);
	init_form(f);
	init_field(f);
	(void) _update_current(f);
	return (E_OK);
}

int
unpost_form(FORM *f)
{
	if (!f)
		return (E_BAD_ARGUMENT);

	if (!Status(f, POSTED))
		return (E_NOT_POSTED);

	if (Status(f, DRIVER))
		return (E_BAD_STATE);

	term_field(f);
	term_form(f);
	(void) werase(Sub(f));
	(void) delwin(W(f));
	W(f) = (WINDOW *) 0;
	Clr(f, POSTED);
	return (E_OK);
}

/* pos_form_cursor - move to cursor position and sync up */
int
pos_form_cursor(FORM *f)
{
	if (!f)
		return (E_BAD_ARGUMENT);

	if (!Status(f, POSTED))
		return (E_NOT_POSTED);

	return (_pos_form_cursor(f));
}

int
set_current_field(FORM *f, FIELD *c)
{
	if (!f || !c || c->form != f)
		return (E_BAD_ARGUMENT);

	if (!Opt(c, O_ACTIVE) || !Opt(c, O_VISIBLE))
		return (E_REQUEST_DENIED);

	if (!Status(f, POSTED)) {
		C(f) = c;
		P(f) = c->page;
		return (E_OK);
	}
	if (Status(f, DRIVER))
		return (E_BAD_STATE);

	if (c != C(f)) {
		if (_validate(f)) {
			int v;

			term_field(f);

			if (c -> page != P(f)) {	/* page change */
				term_form(f);
				v = _set_form_page(f, c->page, c);
				init_form(f);
			} else
				v = _set_current_field(f, c);

			init_field(f);
			(void) _update_current(f);
			return (v);
		} else
			return (E_INVALID_FIELD);
	}
	return (E_OK);
}

FIELD *
current_field(FORM *f)
{
	return (C(Form(f)));
}

int
field_index(FIELD *f)
{
	if (f && f->form)
		return (f->index);
	else
		return (-1);
}

int
set_form_page(FORM *f, int page)
{
	if (!f || !ValidPage(f, page))
		return (E_BAD_ARGUMENT);

	if (!Status(f, POSTED)) {
		P(f) = page;
		C(f) = _first_active(f);
		return (E_OK);
	}
	if (Status(f, DRIVER))
		return (E_BAD_STATE);

	if (page != P(f)) {
		if (_validate(f)) {
			int v;

			term_field(f);
			term_form(f);
			v = _set_form_page(f, page, (FIELD *) 0);
			init_form(f);
			init_field(f);
			(void) _update_current(f);
			return (v);
		} else
			return (E_INVALID_FIELD);
	}
	return (E_OK);
}

	/*
	 *  form_page
	 */

int
form_page(FORM *f)
{
	return (P(Form(f)));
}
