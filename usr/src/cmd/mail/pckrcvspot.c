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

#include "mail.h"
/*
 * If any H_RECEIVED lines in msg, decide where to put them.
 * Returns :
 *	-1 ==> No H_RECEIVED lines to be printed.
 *	> 0 ==> Header line type after (before) which to place H_RECEIVED lines
 */
int
pckrcvspot(void)
{
	static char pn[] = "pckrcvspot";
	int	rc;	

	if (hdrlines[H_RECEIVED].head == (struct hdrs *)NULL) {
		rc = -1;
	} else if (orig_rcv) {
		rc = H_RECEIVED;
	} else if (orig_aff) {
		rc = H_AFWDFROM;
	} else if (fnuhdrtype == H_RVERS) {
		if (hdrlines[H_EOH].head != (struct hdrs *)NULL) {
			if (hdrlines[H_DATE].head != (struct hdrs *)NULL) {
				rc = H_DATE;
			} else {
				rc = H_EOH;
			}
		}
	} else if ((fnuhdrtype == H_MVERS) &&
	    (hdrlines[H_EOH].head != (struct hdrs *)NULL)) {
		rc = H_EOH;
	} else {
		rc = H_CTYPE;
	}
	Dout(pn, 3, "'%s'\n", (rc == -1 ? "No Received: lines": header[rc].tag));
	return (rc);
}
