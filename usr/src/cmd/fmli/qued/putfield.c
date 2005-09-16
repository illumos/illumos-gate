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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <curses.h>
#include "wish.h"
#include "token.h"
#include "winp.h"
#include "fmacs.h"
#include "moremacros.h"
#include "terror.h"

extern 	char *fputstring();

int
putfield(fld, str)
ifield *fld;
char *str;
{
	ifield *savefield;
	chtype *sbuf_ptr;
	char *v_ptr;

	if (str == NULL)
		return (0);
	savefield = Cfld;
	if (fld != NULL)
		Cfld = fld;
	else if (!Cfld)			/* no current field */
		return (0);
	if (Flags & I_INVISIBLE) {
		Cfld = savefield;
		return (0);
	}
	Flags |= I_CHANGED;
	fgo(0, 0);			/* home the cursor */

	/*
	 * Free remains of a previous field value
	 */
	if (Value)
		free(Value);
	if (Scrollbuf)
		free_scroll_buf(Cfld);	/* if used, reset scroll buffers */

	/*
	 * If Value is LESS than the visible field size
	 * then allocate at least the field size
	 * otherwise strsave the passed value.
	 */
	if (strlen(str) < FIELDBYTES) {
		if ((Value = malloc(FIELDBYTES +1)) == NULL) /* +1 abs k15 */
			fatal(NOMEM, nil);
		strcpy(Value, str);
	}
	else
		Value = strsave(str);

	Valptr = fputstring(Value);	/* update pointer into value */
	fclear();			/* clear the rest of field */
	fgo(0, 0);			/* home the cursor */
	if ((Flags & I_SCROLL) && Currtype == SINGLE) {
		/*
		 * HORIZONTAL SCROLLING
		 * initialize scroll buffer and copy string to it
		 */
		unsigned vallength, maxlength;

		vallength = strlen(Value);
		maxlength = max(vallength, FIELDBYTES);	/* removed +1 abs k15 */
		growbuf(maxlength);
/*		strcpy(Scrollbuf, Value);  abs */
		/* THE following is >>> WRONG <<< it does not
		 * process  characters like tabs. it should be
		 * handled like vertical scroll fields.
		 */
		sbuf_ptr = Scrollbuf;
		v_ptr = Value;
		while (*v_ptr!= '\0')
		    *sbuf_ptr++ = ((chtype) *v_ptr++) | Fieldattr;
		free(Value);
		Valptr = Value = NULL;
	}
	setarrows();
	Cfld = savefield;
	return (0);
}
