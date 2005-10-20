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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	LINTLIBRARY	*/
/*	putenv - change environment variables
 *
 *	input - char *change = a pointer to a string of the form
 *			       "name=value"
 *
 *	output - 0, if successful
 *		 1, otherwise
 */

#include <stdio.h>
#include <stdlib.h>

extern char **environ;		/* pointer to enviroment */
static int	reall;		/* flag to reallocate space, if putenv is called
				   more than once */
static int	find(char *);
static int	match(char *, char *);

int
putenv(char *change)
{
	char **newenv;		    /* points to new environment */
	int which;	    /* index of variable to replace */

	if ((which = find(change)) < 0)  {
		/* if a new variable */
		/* which is negative of table size, so invert and
		   count new element */
		which = (-which) + 1;
		if (reall)  {
			/* we have expanded environ before */
			newenv = (char **)realloc(environ,
				  which*sizeof(char *));
			if (newenv == NULL)  return (-1);
			/* now that we have space, change environ */
			environ = newenv;
		} else {
			/* environ points to the original space */
			reall++;
			newenv = (char **)malloc(which*sizeof(char *));
			if (newenv == NULL)  return (-1);
			(void)memcpy((char *)newenv, (char *)environ,
 				(int)(which*sizeof(char *)));
			environ = newenv;
		}
		environ[which-2] = change;
		environ[which-1] = NULL;
	}  else  {
		/* we are replacing an old variable */
		environ[which] = change;
	}
	return (0);
}

/*	find - find where s2 is in environ
 *
 *	input - str = string of form name=value
 *
 *	output - index of name in environ that matches "name"
 *		 -size of table, if none exists
*/
static int
find(char *str)
{
	int ct = 0;	/* index into environ */

	while(environ[ct] != NULL)   {
		if (match(environ[ct], str)  != 0)
			return (ct);
		ct++;
	}
	return (-(++ct));
}
/*
 *	s1 is either name, or name=value
 *	s2 is name=value
 *	if names match, return value of 1,
 *	else return 0
 */

static int
match(char *s1, char *s2)
{
	while(*s1 == *s2++)  {
		if (*s1 == '=')
			return (1);
		s1++;
	}
	return (0);
}
