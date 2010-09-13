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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <utmpx.h>

#ifndef TRUE
#define	TRUE 1
#define	FALSE 0
#endif

int isbusy(char *);

/* Is this login being used */
int
isbusy(char *login)
{
	struct utmpx *utxptr;

	setutxent();
	while ((utxptr = getutxent()) != NULL)
		/*
		 * If login is in the utmp file, and that process
		 * isn't dead, then it "is_busy()"
		 */
		if ((strncmp(login, utxptr->ut_user,
		    sizeof (utxptr->ut_user)) == 0) && \
			utxptr->ut_type != DEAD_PROCESS)
			return (TRUE);

	return (FALSE);
}
