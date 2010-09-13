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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mail.h"
/*
 * Save info on each header line for possible generation
 * of MTA positive or negative delivery notification
 */
void
savehdrs(s, hdrtype)
char *s;
int hdrtype;
{
	char		*q;
	int		rf;
	char		delim = ':';
	char		tbuf[HDRSIZ];
	static int	last_hdrtype = -1;

	if (hdrtype > H_CONT) {
		return;
	}
	if (hdrtype == H_CONT) {
		trimnl(s);
		pushlist(last_hdrtype, TAIL, s, TRUE);
		return;
	}

	last_hdrtype = hdrtype;

	if ((hdrtype == H_FROM) || (hdrtype == H_FROM1)) {
		delim = ' ';
	} else {
		if (fnuhdrtype == 0) {
			/* Save type of first non-UNIX header line */
			fnuhdrtype = hdrtype;
		}
	}
	switch (hdrtype) {
	    case H_FROM1:
		/* If first ">From " line, check for '...remote from...' */
		if (hdrlines[H_FROM1].head == (struct hdrs *)NULL) {
			if ((rf = substr(s, " remote from ")) >= 0) {
				trimnl(s + rf);
				(void) snprintf(tbuf, sizeof (tbuf),
				    "from %s by %s%s; %s",
				    s+rf+13, thissys, maildomain(),
				    RFC822datestring);
				pushlist(H_RECEIVED, HEAD, tbuf, FALSE);
			}
		}
		break;

	    /* Remember that these header line type were in orig. msg.  */
	    case H_AFWDFROM:
		orig_aff++;
		break;
	    case H_RECEIVED:
		orig_rcv++;
		break;
	    case H_TCOPY:
		orig_tcopy++;
		break;
	}
	q = strchr(s, delim) + 1;
	q = skipspace(q);
	trimnl(q);
	if ((hdrtype == H_UAID) || (hdrtype == H_MTSID)) {
		/* Check for enclosing '<' & '>', and remove if found */
		/* gendeliv() will replace them if necessary */
		if ((*q == '<') && (*(q+strlen(q)-1) == '>')) {
			q++;
			*(q+strlen(q)-1) = '\0';
		}
	}

	pushlist(hdrtype, TAIL, q, FALSE);
}
