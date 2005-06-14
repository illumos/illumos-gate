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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	logdir()
 *
 *	This routine does not use the getpwent(3) library routine
 *	because the latter uses the stdio package.  The allocation of
 *	storage in this package destroys the integrity of the shell's
 *	storage allocation.
 */

#include <fcntl.h>	/* O_RDONLY */
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define	BUFSIZ	160

static char line[BUFSIZ+1];

static char *
passwdfield(char *p)
{
	while (*p && *p != ':')
		++p;
	if (*p)
		*p++ = 0;
	return (p);
}

char *
logdir(char *name)
{
	char	*p;
	int	i, j;
	int	pwf;

	/* attempt to open the password file */
	if ((pwf = open("/etc/passwd", O_RDONLY)) == -1)
		return (0);

	/* find the matching password entry */
	do {
		/* get the next line in the password file */
		i = read(pwf, line, BUFSIZ);
		for (j = 0; j < i; j++)
			if (line[j] == '\n')
				break;
		/* return a null pointer if the whole file has been read */
		if (j >= i)
			return (0);
		line[++j] = 0;			/* terminate the line */
		/* point at the next line */
		(void) lseek(pwf, (long)(j - i), 1);
		p = passwdfield(line);		/* get the logname */
	} while (*name != *line ||	/* fast pretest */
	    strcmp(name, line) != 0);
	(void) close(pwf);

	/* skip the intervening fields */
	p = passwdfield(p);
	p = passwdfield(p);
	p = passwdfield(p);
	p = passwdfield(p);

	/* return the login directory */
	(void) passwdfield(p);
	return (p);
}
