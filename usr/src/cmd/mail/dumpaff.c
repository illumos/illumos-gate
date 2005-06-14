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
 * Put out H_AFWDFROM and H_AFWDCNT lines if necessary, or
 * suppress their printing from the calling routine.
 */
void dumpaff (type, htype, didafflines, suppress, f)
register int	type;
register int	htype;
register int	*didafflines;
register int	*suppress;
register FILE	*f;
{
	int		affspot;	/* Place to put H_AFWDFROM lines */
	struct hdrs	*hptr;
	char		*pn = "dumpaff";

	Dout(pn, 15, "type=%d, htype=%d/%s, *didafflines=%d, *suppress=%d\n", type, htype, htype >= 0 ? header[htype].tag : "None", *didafflines, *suppress);

	affspot = pckaffspot();
	if (affspot == -1) {
		Dout(pn, 15, "\taffspot==-1\n");
		return;
	}

	switch (htype) {
	case H_AFWDCNT:
		*suppress = TRUE;
		Dout(pn, 15, "\tAuto-Forward-Count found\n");
		return;
	case H_AFWDFROM:
		*suppress = TRUE;
		break;
	}

	if (*didafflines == TRUE) {
		Dout(pn, 15, "\tdidafflines == TRUE\n");
		return;
	}

	if ((htype >= 0) && (affspot != htype)) {
		Dout(pn, 15, "\thtype < 0 || affspot != htype, *suppress=%d\n", *suppress);
		return;
	}

	*didafflines = TRUE;
	for (hptr = hdrlines[H_AFWDFROM].head;
	     hptr != (struct hdrs *)NULL;
	     hptr = hptr->next) {
		printhdr(type, H_AFWDFROM, hptr, f);
	}
	fprintf(f,"%s %d\n", header[H_AFWDCNT].tag, affcnt);
	Dout(pn, 15, "\t*didafflines=%d, *suppress=%d\n", *didafflines, *suppress);
}
