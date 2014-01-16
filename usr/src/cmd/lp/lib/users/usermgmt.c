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

/* LINTLIBRARY */

# include	<stdio.h>

# include	"lp.h"
# include	"users.h"

static int loaded = 0;
static struct user_priority *ppri_tbl;
struct user_priority *ld_priority_file();
static USER usr;

int putuser ( char * user, USER * pri_s )
{
    int fd;

    if (!loaded)
    {
	if (!(ppri_tbl = ld_priority_file(Lp_Users)))
	    return(-1);
	loaded = 1;
    }

    if (!add_user(ppri_tbl, user, pri_s->priority_limit))
    {
	return(-1);
    }

    if ((fd = open_locked(Lp_Users, "w", LPU_MODE)) < 0)
	return(-1);
    output_tbl(fd, ppri_tbl);
    close(fd);
    return(0);
}

USER * getuser ( char * user )
{
    int limit;

    /* root and lp do not get a limit */
    if (STREQU(user, "root") || STREQU(user, LPUSER))
    {
	usr.priority_limit = 0;
	return(&usr);
    }

    if (!loaded)
    {
	if (!(ppri_tbl = ld_priority_file(Lp_Users)))
	    return((USER *)0);

	loaded = 1;
    }

    for (limit = PRI_MIN; limit <= PRI_MAX; limit++)
	if (bang_searchlist(user, ppri_tbl->users[limit - PRI_MIN]))
	{
	    usr.priority_limit = limit;
	    return(&usr);
	}

    usr.priority_limit = ppri_tbl->deflt_limit;
    return(&usr);
}

int deluser ( char * user )
{
    int fd;

    if (!loaded)
    {
	if (!(ppri_tbl = ld_priority_file(Lp_Users)))
	    return(-1);

	loaded = 1;
    }

    del_user(ppri_tbl, user);

    if ((fd = open_locked(Lp_Users, "w", LPU_MODE)) < 0)
	return(-1);

    output_tbl(fd, ppri_tbl);
    close(fd);
    return(0);
}

int getdfltpri ( void )
{
    if (!loaded)
    {
	if (!(ppri_tbl = ld_priority_file(Lp_Users)))
	    return(-1);

	loaded = 1;
    }

    return (ppri_tbl->deflt);
}

void
trashusers(void)
{
    int limit;

    if (loaded)
    {
	if (ppri_tbl)
	{
	    for (limit = PRI_MIN; limit <= PRI_MAX; limit++)
		freelist (ppri_tbl->users[limit - PRI_MIN]);
	    ppri_tbl = 0;
	}
	loaded = 0;
    }
}

