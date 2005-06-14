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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <curses.h>
#include "token.h"
#include "wish.h"
#include "winp.h"
#include "fmacs.h"
#include "terror.h"

static char *getfixedval();
static char *getscrollval();

/*
 * GETFIELD will return the contents of the current field.  It is not
 * stable as of yet and does not account for scrolling field.
 */
char *
getfield(fld, buff)
ifield *fld;
char *buff;
{
	register char *fbuf, *val;
	ifield *savefield;

	savefield = Cfld;
	if (fld != NULL)
		Cfld = fld;
	if (Flags & I_INVISIBLE) {
		if (Value == NULL)
			val = nil;
		else
			val = Value;
	}
	else if (Flags & I_SCROLL)
		val = getscrollval();
	else
		val = getfixedval();
	/*
	 * getscrollval() and getfixedval() return NULL from
	 * time to time - causing calling functions to segfault.
	 */
	if (val == NULL)
		val = nil;
	if (buff == NULL)
		fbuf = val;
	else {
		strcpy(buff, val);
		fbuf = buff;
	}
	Cfld = savefield;
	return(fbuf);
}

static char *
getfixedval()
{
	register int row;
	register char *bptr;

	if (!(Flags & I_CHANGED))
		return(Value);
	Flags &= ~(I_CHANGED);

	/*
	 * If this field does not already have a value then
	 * allocate space equal to the size of the field dimensions
	 * (Buffer is guarenteed to be at least this size if there
	 * already is a field value)
	 */
	if (!Value && (Value = malloc(FIELDBYTES +1)) == NULL) /* +1 abs k15 */
		fatal(NOMEM, nil);

	/*
	 * Read the field value from the window map and eat
	 * trailing new-line characters
	 */
	for (bptr = Value, row = 0; row <= LASTROW; row++) {
		bptr += freadline(row, bptr, TRUE);
		*bptr++ = '\n';
	}
	while (--bptr >= Value && *bptr == '\n')
		*bptr = '\0';
	return(Value);
}

static char *
getscrollval()
{
	register char *dptr;
	register chtype *sptr, *lastptr, *saveptr;
	unsigned buflength, lenvalptr;
	char *dest;

	if (!(Flags & I_CHANGED))
		return(Value);
	Flags &= ~(I_CHANGED);
	/*
	 *	HORIZONTAL SCROLL FIELD 
	 *
	 *	- syncronize the window map with the scroll buffer.
	 *	- set Value to the result
	 *
	 */
	if (Currtype == SINGLE) {
		syncbuf(Buffoffset, 0, 0);		/* syncronize buffer */
		if ((dest = malloc(Buffsize + 1)) == NULL)
			fatal(NOMEM, nil);
		dptr = dest;
		sptr = Scrollbuf;
		while ((*dptr++ = (char)(*(sptr++) & A_CHARTEXT)) != '\0')
			;
		if (Value)
			free(Value);
		Value = dest;
		return(Value);
	}

	/*
	 *	VERTICAL SCROLL FIELD 
	 *
	 *	- syncronize the window map with the scroll buffer.
	 *	- "pack" the scoll buffer (remove trailing blanks).
	 * 	- append the remaining (unprocessed) text pointed to by Valptr.
	 *	- eat trailing new-lines
	 * 	- set Value to the result. 
	 *
	 */
	syncbuf(Buffoffset, 0, Fieldrows - 1);	/* syncronize buffer */
	if ((dest = malloc(Buffsize + 1)) == NULL)
		fatal(NOMEM, nil);
	lastptr = Scrollbuf + Bufflast;
	saveptr = sptr = Scrollbuf;
	dptr = dest;
	while (sptr < lastptr) {  /* pack Scrollbuf */  
		if ((*dptr++ = (char)(*(sptr++) & A_CHARTEXT)) == '\0') {
			saveptr += LINEBYTES;
			sptr = saveptr;
			*(dptr - 1) = '\n';
		}
	} 
	*dptr = '\0';

	buflength = strlen(dest);
	if (Valptr) {				/* append unprocessed text */
		lenvalptr = strlen(Valptr);
		if ((dest = realloc(dest, buflength + lenvalptr + 1)) == NULL)
			fatal(NOMEM, nil);
		strcat(dest, Valptr);
		Valptr = dest + buflength;
		buflength += lenvalptr;
	}
	if (Value)
		free(Value);
	Value = dest;
	for (dptr = dest + buflength - 1; --dptr >= dest && *dptr == '\n'; )
		*dptr = '\0';			/* eat trailing new-lines */
	return(Value);
}

