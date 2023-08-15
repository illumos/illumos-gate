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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"        /* SVr4.0 1.6 */

#include "mail.h"
/*
 * Put out H_RECEIVED lines if necessary, or
 * suppress their printing from the calling routine.
 */
void dumprcv (type, htype, didrcvlines, suppress, f)
register int	type;
register int	htype;
register int	*didrcvlines;
register int	*suppress;
register FILE	*f;
{
	int		rcvspot;	/* Place to put H_RECEIVED lines */
	struct hdrs	*hptr;
	char		*pn = "dumprcv";

	Dout(pn, 15, "type=%d, htype=%d/%s, *didrcvlines=%d, *suppress=%d\n", type, htype, htype >= 0 ? header[htype].tag : "None", *didrcvlines, *suppress);

	rcvspot = pckrcvspot();
	if (rcvspot == -1) {
		Dout(pn, 15, "\trcvspot==-1\n");
		return;
	}

	if (htype == H_RECEIVED) {
		*suppress = TRUE;
	}

	if (*didrcvlines == TRUE) {
		Dout(pn, 15, "\tdidrcvlines == TRUE\n");
		return;
	}
	if ((htype >= 0) && (rcvspot != htype)) {
		Dout(pn, 15, "\thtype < 0 || rcvspot != htype, *suppress=%d\n", *suppress);
		return;
	}

	*didrcvlines = TRUE;
	for (hptr = hdrlines[H_RECEIVED].head;
	     hptr != (struct hdrs *)NULL;
	     hptr = hptr->next) {
		printhdr(type, H_RECEIVED, hptr, f);
	}
	Dout(pn, 15, "\t*didrcvlines=%d, *suppress=%d\n", *didrcvlines, *suppress);
}
