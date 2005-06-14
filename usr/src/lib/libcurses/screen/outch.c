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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

int	outchcount;

/* Write out one character to the tty and increment outchcount. */
int
_outch(char c)
{
	return (_outwch((chtype)c));
}

int
_outwch(chtype c)
{
	chtype	o;

#ifdef	DEBUG
#ifndef	LONGDEBUG
	if (outf)
		if (c < ' ' || c == 0177)
			fprintf(outf, "^%c", c^0100);
		else
			fprintf(outf, "%c", c&0177);
#else	/* LONGDEBUG */
	if (outf)
	    fprintf(outf, "_outch: char '%s' term %x file %x=%d\n",
		unctrl(c&0177), SP, cur_term->Filedes, fileno(SP->term_file));
#endif	/* LONGDEBUG */
#endif	/* DEBUG */

	outchcount++;

	/* ASCII code */
	if (!ISMBIT(c))
		(void) putc((int)c, SP->term_file);
	/* international code */
	else if ((o = RBYTE(c)) != MBIT) {
		(void) putc((int)o, SP->term_file);
		if (_csmax > 1 && (((o = LBYTE(c))|MBIT) != MBIT)) {
			SETMBIT(o);
			(void) putc((int)o, SP->term_file);
		}
	}
	return (0);
}
