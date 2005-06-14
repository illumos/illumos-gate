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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"

#include "lp.h"

#define	DFLT_PREFIX	0
#define	DFLT_SUFFIX	0
#define	DFLT_SEP	"\n"
#define	DFLT_NEWLINE	"\n"

int			printlist_qsep	= 0;

static char		*print_prefix	= DFLT_PREFIX,
			*print_suffix	= DFLT_SUFFIX,
			*print_sep	= DFLT_SEP,
			*print_newline	= DFLT_NEWLINE;

static void		q_print( int, char * , char * );

/**
 ** printlist_setup() - ARRANGE FOR CUSTOM PRINTING
 ** printlist_unsetup() - RESET STANDARD PRINTING
 **/

void
printlist_setup(char *prefix, char *suffix, char *sep, char *newline)
{
	if (prefix)
		print_prefix = prefix;
	if (suffix)
		print_suffix = suffix;
	if (sep)
		print_sep = sep;
	if (newline)
		print_newline = newline;
	return;
}

void
printlist_unsetup()
{
	print_prefix = DFLT_PREFIX;
	print_suffix = DFLT_SUFFIX;
	print_sep = DFLT_SEP;
	print_newline = DFLT_NEWLINE;
	return;
}

/**
 ** printlist() - PRINT LIST ON OPEN CHANNEL
 **/

int
printlist(FILE *fp, char **list)
{
	return (fdprintlist(fileno(fp), list));
}

int
fdprintlist(int fd, char **list)
{
	register char		*sep;

	if (list)
	    for (sep = ""; *list; *list++, sep = print_sep) {

		(void)fdprintf (fd, "%s%s", sep, NB(print_prefix));
		if (printlist_qsep)
			q_print (fd, *list, print_sep);
		else
			(void)fdprintf (fd, "%s", *list);
		errno = 0;
		(void)fdprintf (fd, "%s", NB(print_suffix));
		if (errno != 0)
			return (-1);

	    }
	(void)fdprintf (fd, print_newline);

	return (0);
}


static void
q_print(int fd, char *str, char *sep)
{
	while (*str) {
		if (strchr(sep, *str))
			fdputc('\\', fd);
		fdputc(*str, fd);
		str++;
	}
	return;
}
