/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* LINTLIBRARY */

#include "stdlib.h"

#include "lp.h"

char	Lp_Spooldir[]		= SPOOLDIR;
char	Lp_Admins[]		= SPOOLDIR "/admins";
char	Lp_FIFO[]		= SPOOLDIR "/fifos/FIFO";
char	Lp_Requests[]		= SPOOLDIR "/requests";
char	Lp_Schedlock[]		= SPOOLDIR "/SCHEDLOCK";
char	Lp_System[]		= SPOOLDIR "/system";
char	Lp_Temp[]		= SPOOLDIR "/temp";
char	Lp_Tmp[]		= SPOOLDIR "/tmp";

char	Lp_Bin[]		= LPDIR "/bin";
char	Lp_Model[]		= LPDIR "/model";
char	Lp_Slow_Filter[]	= LPDIR "/bin/slow.filter";

char	Lp_A_Logs[]		= LOGDIR;
char	Lp_Logs[]		= LOGDIR;
char	Lp_ReqLog[]		= LOGDIR "/requests";

char	Lp_A[]			= ETCDIR;
char	Lp_Users[]		= ETCDIR "/users";
char	Lp_A_Classes[]		= ETCDIR "/classes";
char	Lp_A_Forms[]		= ETCDIR "/forms";
char	Lp_A_Interfaces[]	= ETCDIR "/interfaces";
char	Lp_A_Printers[]		= ETCDIR "/printers";
char	Lp_A_PrintWheels[]	= ETCDIR "/pwheels";
char	Lp_A_Systems[]		= ETCDIR "/systems";
char	Lp_A_Filters[]		= ETCDIR "/filter.table";
char	Lp_Default[]		= ETCDIR "/default";
char	Lp_A_Faults[]		= ETCDIR "/alerts";

/*
**	Sorry about these nonfunctional functions.  The data is
**	static now.  These exist for historical reasons.
*/

#undef	getpaths
#undef	getadminpaths

void		getpaths ( void ) { return; }
void		getadminpaths ( char * admin) { return; }

/**
 ** getprinterfile() - BUILD NAME OF PRINTER FILE
 **/

char *
getprinterfile(char *name, char *component)
{
    char	*path;

    if (!name)
	return (0);

    path = makepath(Lp_A_Printers, name, component, NULL);

    return (path);
}

/**
 ** getsystemfile() - BUILD NAME OF SYSTEM FILE
 **/

char *
getsystemfile(char *name, char *component)
{
    char	*path;

    if (!name)
	return (0);

    path = makepath(Lp_A_Systems, name, component, NULL);

    return (path);
}

/**
 ** getclassfile() - BUILD NAME OF CLASS FILE
 **/

char *
getclassfile(char *name)
{
    char	*path;

    if (!name)
	return (0);

    path = makepath(Lp_A_Classes, name, NULL);

    return (path);
}

/**
 ** getfilterfile() - BUILD NAME OF FILTER TABLE FILE
 **/

char *
getfilterfile(char *table)
{
    char	*path;

    if (!table)
	table = FILTERTABLE;

    path = makepath(ETCDIR, table, NULL);

    return (path);
}

/**
 ** getformfile() - BUILD NAME OF PRINTER FILE
 **/

char *
getformfile(char *name, char *component)
{
    char	*path;

    if (!name)
	return (0);

    path = makepath(Lp_A_Forms, name, component, NULL);

    return (path);
}
