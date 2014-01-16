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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/
/* LINTLIBRARY */

# include	<stdio.h>

# include	"lp.h"
# include	"users.h"
# include	<locale.h>

/*
Inputs:
Outputs:
Effects:
*/
void
print_tbl(struct user_priority * ppri_tbl)
{
    int limit;

    printf(gettext("Default priority: %d\n"), ppri_tbl->deflt);
    printf(gettext("Priority limit for users not listed below: %d\n"), ppri_tbl->deflt_limit);
    printf(gettext("Priority  Users\n"));
    printlist_setup ("", "", ",", "\n");
    for (limit = PRI_MIN; limit <= PRI_MAX; limit++) {
	if (ppri_tbl->users[limit - PRI_MIN])
	{
	    printf("   %2d     ", limit);
	    fdprintlist(1, ppri_tbl->users[limit - PRI_MIN]);
	}
    }
}

/*
Inputs:
Outputs:
Effects:
*/
void
output_tbl(int fd, struct user_priority *ppri_tbl)
{
    int		limit;

    fdprintf(fd, "%d\n%d:\n", ppri_tbl->deflt, ppri_tbl->deflt_limit);
    printlist_setup ("	", "\n", "", "");
    for (limit = PRI_MIN; limit <= PRI_MAX; limit++)
	if (ppri_tbl->users[limit - PRI_MIN])
	{
	    fdprintf(fd, "%d:", limit);
	    fdprintlist(fd, ppri_tbl->users[limit - PRI_MIN]);
	}
}
