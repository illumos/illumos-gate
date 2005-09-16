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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include        <curses.h>
#include	"wish.h"
#include	"token.h"
#include	"winp.h"
#include	"form.h"

/*
 * A field definition may contain:
 *
 * 	1) a field name only 
 * 	2) a field only 
 *	3) both a field name and a field
 *
 * The following macros are useful in determining which is the case
 */ 
#define HAS_NAME(x)	((x->nrow >= 0) && (x->ncol >= 0)) 
#define HAS_FIELD(x)	((x->cols > 0) && (x->rows > 0) && \
			 (x->frow >= 0) && (x->fcol >= 0))

/*
 * CHECKFFIELD will handle setting/resetting field values depending
 * on the current/previous state of the field value
 */ 
int
checkffield(fptr, pffld)
struct form *fptr;		/* pointer to the form structure */ 
register formfield *pffld;	/* how the field "should" be displayed */ 
{
	register ifield *fld;	/* how the field "is" displayed */ 
	ifield *newfield();

	if (!(*(pffld->ptr))) {
		/*
		 * this is the first time ... initialize the field 
		 */
		*(pffld->ptr) = (char *) newfield(pffld->frow, pffld->fcol,
			pffld->rows, pffld->cols, pffld->flags);
		if (!(pffld->flags & I_NOSHOW)) {
			/*
			 * if "show=true" then display the field name
			 * as well as the field itself. 
			 */
		        if (HAS_NAME(pffld)) {
				wgo(pffld->nrow, pffld->ncol);
				winputs(pffld->name, NULL);
			}
			if (HAS_FIELD(pffld))
				putfield((ifield *) *(pffld->ptr), pffld->value);
		}
		return (0);
	}
	else if (pffld->flags & I_NOSHOW) {
		/*
		 * field is a "show=false" field
		 */
		fld = (ifield *) *(pffld->ptr);
		if (!(fld->flags & I_NOSHOW)) {
			/*
			 * if field was recently a "show=true" field ...
			 * then remove the field name and the field value
			 */
			if (HAS_NAME(pffld)) {

				char tbuf[BUFSIZ];

				sprintf(tbuf, "%*s", strlen(pffld->name), " ");
				wgo(pffld->nrow, pffld->ncol);
				winputs(tbuf, NULL);
			}
			if (HAS_FIELD(fld))
				hidefield(fld);
		}
	}
	else {
		/*
		 * field is a "show=true" field
		 */
		fld = (ifield *) *(pffld->ptr);

		/*
		 * Only redisplay the field name if the field HAS 
		 * a name AND:
		 *
		 * 1) the form is all dirty OR
		 * 2) the field was previously "show=false"
		 */
		if (HAS_NAME(pffld) && ((fptr->flags & FORM_ALLDIRTY) ||
					(fld->flags & I_NOSHOW))) {
			wgo(pffld->nrow, pffld->ncol);
			winputs(pffld->name, NULL);
		}
		/*
		 * Only redisplay the field value if there IS a field AND:
		 *
		 * 1) the field went from active to inactive or vice versa OR
		 * 2) the form is all dirty OR
		 * 3) the new field value is different from
		 *    the old field value OR
		 * 4) the field was previously "show=false" 
		 */
		if (HAS_FIELD(pffld)) {
			if ((fld->flags & I_FILL) ^ (pffld->flags & I_FILL)) {
				setfieldflags(*(pffld->ptr), pffld->flags);
				putfield(fld, pffld->value);
			}
			else if ((fptr->flags & FORM_ALLDIRTY) ||
		 	    ((fld->value == NULL) || (pffld->value == NULL)) || 
			    (strcmp(fld->value, pffld->value) != 0) ||
			    (fld->flags & I_NOSHOW)) {
				putfield(fld, pffld->value);
			}
		}
	}

	/*
	 * update field flags if necessary ....
	 */ 
	if (((ifield *) *(pffld->ptr))->flags != pffld->flags)
		setfieldflags(*(pffld->ptr), pffld->flags);
	return (0);
}
