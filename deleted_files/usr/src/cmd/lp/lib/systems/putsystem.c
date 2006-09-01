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
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/
/* LINTLIBRARY */

# include	<sys/types.h>
# include	<stdio.h>
# include	<string.h>
# include	<errno.h>
# include	<stdlib.h>

# include	"lp.h"
# include	"systems.h"


/**
 ** putsystem() - WRITE SYSTEM STRUCTURE TO DISK FILES
 **/


#if	defined(__STDC__)
int putsystem ( const char * name, const SYSTEM * sysbufp )
#else
int putsystem ( name, sysbufp )
char	*name;
SYSTEM	*sysbufp;
#endif
{
    FILE	*fp;

    /*
    **	Validate the arguments.
    **	Must have a name, but not "all".
    **	SYSTEM must have a provider, address, and a protocol.
    */
    if (!name || !*name || STREQU(name, NAME_ALL))
    {
	errno = EINVAL;
	return(-1);
    }

    if (!sysbufp ||
       (sysbufp->protocol != S5_PROTO && sysbufp->protocol != BSD_PROTO))
    {
	errno = EINVAL;
	return(-1);
    }

    /*
    **	Since, this may be an update of an existing entry, delsystem
    **	is called to prevent any duplication.
    */
    (void) delsystem(name);

    if ((fp = open_lpfile(Lp_NetData, "a", MODE_READ)) == NULL)
	return(-1);

    (void) fprintf(fp, "%s:", name);
    (void) fprintf(fp, "%s:", "x");	/* passwd */
    (void) fprintf(fp, "%s:", "-");	/* reserved1 */
    (void) fprintf(fp, "%s:", (sysbufp->protocol == S5_PROTO ?
				NAME_S5PROTO : NAME_BSDPROTO));

    if (sysbufp->threshold < 0)
	(void) fprintf(fp, "-:");
    else
    	(void) fprintf(fp, "%d:", sysbufp->threshold);

    if (sysbufp->timeout < 0)
	(void) fprintf(fp, "n:");
    else
	(void) fprintf(fp, "%d:", sysbufp->timeout);
    
    if (sysbufp->retry < 0)
	(void) fprintf(fp, "n:");
    else
    	(void) fprintf(fp, "%d:", sysbufp->retry);

    (void) fprintf(fp, "-:");	/* reserved3 */
    (void) fprintf(fp, "-:");	/* reserved4 */
    if (sysbufp->comment)
    	(void) fprintf(fp, "%s\n", sysbufp->comment);
    else
        (void) fprintf(fp, "\n");
    (void) close_lpfile(fp);
    return(0);
}
