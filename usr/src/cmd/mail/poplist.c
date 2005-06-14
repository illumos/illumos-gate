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


#pragma ident	"%Z%%M%	%I%	%E% SMI" 	/* SVr4.0 2.	*/
#include "mail.h"
/*
 * Remove an entry from its linked list and free any malloc'd memory..
 */
void poplist (hdrtype, where)
register int	hdrtype;
register int	where;
{
	struct	hdrs	*hdr2rm, *cont2rm, *nextcont;

	/* Remove first/last entry from list */

	hdr2rm = (where == HEAD ?
			hdrlines[hdrtype].head : hdrlines[hdrtype].tail);

	if (hdr2rm == (struct hdrs *)NULL) {
		return;
	}
	if (where == HEAD) {
		if (hdr2rm->next == (struct hdrs *)NULL) {
			/* Only 1 entry in list */
			hdrlines[hdrtype].head = hdrlines[hdrtype].tail =
							(struct hdrs *)NULL;
		} else {
			hdrlines[hdrtype].head = hdr2rm->next;
			hdr2rm->next->prev = (struct hdrs *)NULL;
		}
	} else {
		if (hdr2rm->prev == (struct hdrs *)NULL) {
			/* Only 1 entry in list */
			hdrlines[hdrtype].head = hdrlines[hdrtype].tail =
							(struct hdrs *)NULL;
		} else {
			hdrlines[hdrtype].tail = hdr2rm->prev;
			hdr2rm->prev->next = (struct hdrs *)NULL;
		}
	}
	/* Keep track of total bytes added to message due to    */
	/* selected lines in case non-delivery                  */
	/* notification needs to be sent. (See also copylet())  */
	if (hdrtype == H_AFWDFROM) {
	    affbytecnt -=
		(strlen(header[H_AFWDFROM].tag) + strlen(hdr2rm->value) + 2);
	    affcnt--;
	}
	if (hdrtype == H_RECEIVED) {
	    rcvbytecnt -=
		(strlen(header[H_RECEIVED].tag) + strlen(hdr2rm->value) + 2);
	}

	cont2rm = hdr2rm->cont;
	while (cont2rm != (struct hdrs *)NULL) {
		nextcont = cont2rm->next;
		if (hdrtype == H_AFWDFROM) {
		    affbytecnt -= (strlen(cont2rm->value) + 1);
		    affcnt--;
		}
		if (hdrtype == H_RECEIVED) {
		    rcvbytecnt -= (strlen(cont2rm->value) + 1);
		}
		free ((char *)cont2rm);
		cont2rm = nextcont;
	}
	free ((char *)hdr2rm);
}
