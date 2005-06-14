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


/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lpsched.h"

static char cerrbuf[160] = "";	/* fix for bugid 1100252	*/


/**
 ** cancel() - CANCEL A REQUEST
 **/

int
cancel (RSTATUS *prs, int spool)
{
	if (prs->request->outcome & RS_DONE)
		return (0);

	prs->request->outcome |= RS_CANCELLED;

	if (spool || (prs->request->actions & ACT_NOTIFY))
		prs->request->outcome |= RS_NOTIFY;

	if (prs->request->outcome & RS_PRINTING) {
		terminate(prs->printer->exec);
	}
	else if (prs->request->outcome & RS_FILTERING) {
		terminate (prs->exec);
	}
	else if (prs->request->outcome | RS_NOTIFY) {
		/* start fix for bugid 1100252	*/
		if (prs->printer->status & PS_REMOTE) {
			snprintf(cerrbuf, sizeof (cerrbuf),
				"Remote status=%d, canceled by remote system\n",
				prs->reason);
		}
		notify (prs, cerrbuf, 0, 0, 0);
		cerrbuf[0] = (char) NULL;
		/* end fix for bugid 1100252	*/
	}
	check_request (prs);

	return (1);
}
