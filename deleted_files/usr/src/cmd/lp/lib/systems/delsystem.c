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

# include	<string.h>
# include	<stdlib.h>
# include	<errno.h>

# include	"lp.h"
# include	"systems.h"

# define	SEPCHARS	":\n"

/**
 ** delsystem()
 **/

#if	defined(__STDC__)
int delsystem ( const char * name )
#else
int delsystem ( name )
char	*name;
#endif
{
    FILE	*fpi;
    FILE	*fpo;
    char	*cp;
    char	*file;
    char	buf[BUFSIZ];
    char	c;
    int		all = 0;
    int		errtmp;

    putenv("TMPDIR=");
    if ((file = tempnam(ETCDIR, "lpdat")) == NULL)
    {
	errno = ENOMEM;
	return(-1);
    }

    if ((fpi = open_lpfile(Lp_NetData, "r", MODE_READ)) == NULL)
    {
	Free(file);
	return(-1);
    }

    if ((fpo = open_lpfile(file, "w", MODE_READ)) == NULL)
    {
	errtmp = errno;
	(void) close_lpfile(fpi);
	Free(file);
	errno = errtmp;
	return(-1);
    }

    if (STREQU(NAME_ALL, name))
	all = 1;

    while (fgets(buf, BUFSIZ, fpi) != NULL)
    {
	if (*buf != '#' && *buf != '\n')
	    if ((cp = strpbrk(buf, SEPCHARS)) != NULL)
	    {
		if (all)
		    continue;
		
		c = *cp;
		*cp = '\0';
		if (STREQU(name, buf))
		    continue;
		*cp = c;
	    }

	if (fputs(buf, fpo) == EOF)
	{
	    errtmp = errno;
	    (void) close_lpfile(fpi);
	    (void) close_lpfile(fpo);
	    (void) Unlink(file);
	    Free(file);
	    errno = errtmp;
	    return(-1);
	}
    }

    (void) close_lpfile(fpi);
    (void) close_lpfile(fpo);
    (void) _Rename(file, Lp_NetData);
    Free(file);
    return(0);
}
