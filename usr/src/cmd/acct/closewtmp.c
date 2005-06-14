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
/*	Copyright (c) 1999, 2000 by Sun Microsystems, Inc. */
/*	All rights reserved. */


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

/*
 *	fudge an entry to wtmpx for each user who is still logged on when
 *	acct is being run. This entry marks a DEAD_PROCESS, and the
 *	current time as time stamp. This should be done before connect
 *	time is processed. Called by runacct.
 */

#include <stdio.h>
#include <sys/types.h>
#include <utmpx.h>

int
main(int argc, char **argv)
{
	struct utmpx *utmpx;

	setutxent();
	while ((utmpx = getutxent()) != NULL) {
		if (utmpx->ut_type == USER_PROCESS) {
			utmpx->ut_type = DEAD_PROCESS;
			time(&utmpx->ut_xtime);
			(void) updwtmpx(WTMPX_FILE, utmpx);
		}
	}
	endutxent();
	return (0);
}
