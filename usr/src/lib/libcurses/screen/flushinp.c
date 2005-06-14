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

#include	<unistd.h>
#include	<sys/types.h>
#include	"curses_inc.h"

int
flushinp(void)
{
#ifdef	DEBUG
	if (outf)
		fprintf(outf, "flushinp(), file %x, SP %x\n",
		    cur_term->Filedes, SP);
#endif	/* DEBUG */

#ifdef	SYSV
	(void) ioctl(cur_term -> Filedes, TCFLSH, 0);
#else	/* SYSV */
	/* for insurance against someone using their own buffer: */
	(void) ioctl(cur_term -> Filedes, TIOCGETP, &(PROGTTY));

	/*
	 * SETP waits on output and flushes input as side effect.
	 * Really want an ioctl like TCFLSH but Berkeley doesn't have one.
	 */
	(void) ioctl(cur_term -> Filedes, TIOCSETP, &(PROGTTY));
#endif	/* SYSV */

	/*
	 * Get rid of any typeahead which was read().
	 * Leave characters which were ungetch()'d.
	 */
	cur_term->_chars_on_queue = cur_term->_ungotten;

	/*
	 * Have to doupdate() because, if we have stopped output due to
	 * typeahead, now that typeahead is gone, so we had better catch up.
	 */
	if (_INPUTPENDING)
		(void) doupdate();
	return (OK);
}
