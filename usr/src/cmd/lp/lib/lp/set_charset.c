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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.11	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"
#include "lp.set.h"

#if	defined(__STDC__)
char *			tparm ( char * , ... );
#else
extern char		*tparm();
#endif

#if	defined(__STDC__)
static int		cat_charset ( char *, int , char * , int );
#else
static int		cat_charset();
#endif

/**
 ** set_charset()
 **/

int
#if	defined(__STDC__)
set_charset (
	char *			char_set,
	int			putout,
	char *			type
)
#else
set_charset (char_set, putout, type)
	char			*char_set;
	int			putout;
	char			*type;
#endif
{
	int			cs,
				ret;

	char			*rest,
				*char_set_nm,
				*char_set_names,
				*select_char_set,
				*start_char_set_def,
				*p,
				*q;

	unsigned short		has_print_wheel;


	tidbit ((char *)0, "daisy", &has_print_wheel);
	if (has_print_wheel)
		return (E_SUCCESS);

	tidbit ((char *)0, "csnm", &char_set_names);
	if (
		strlen(char_set) > (size_t) 2
	     && char_set[0] == 'c'
	     && char_set[1] == 's'
	     && char_set[2]
	     && 0 <= (cs = strtol(char_set + 2, &rest, 10)) && cs <= 63
	     && !*rest
	)
		char_set_nm = tparm(char_set_names, cs);

	else {
		for (cs = 0; cs <= 63; cs++)
			if (
				(char_set_nm = tparm(char_set_names, cs))
			     && *char_set_nm
			     && STREQU(char_set_nm, char_set)
			)
				break;
		if (cs > 63)
			return (E_FAILURE);
	}

	if (cs == 0)
		return (E_SUCCESS);

	if (char_set_nm)
		if (!(char_set_nm = Strdup(char_set_nm))) {
			errno = ENOMEM;
			ret = E_FAILURE;
			goto Return;
		}

	tidbit ((char *)0, "scs", &select_char_set);
	p = q = 0;
	if ((p = tparm(select_char_set, cs)) && *p && (p = Strdup(p))) {

		tidbit ((char *)0, "scsd", &start_char_set_def);
		if ((q = tparm(start_char_set_def, cs)) && *q) {
			/*
			 * The ``start char. set def'n.'' capability
			 * is defined and set, so assume we MUST
			 * download the character set before using it.
			 */
			if (
				OKAY(char_set_nm)
			     && cat_charset(char_set_nm, 0, type, putout) != -1
			     || cat_charset((char *)0, cs, type, putout) != -1
			     || cat_charset(char_set, 0, type, putout) != -1
			)
				;
			else {
				ret = E_FAILURE;
				goto Return;
			}

		} else {
			/*
			 * The ``start char. set def'n.'' capability
			 * is not defined and or set, so assume we MAY
			 * download the character set before using it.
			 */
			if (
				OKAY(char_set_nm)
			     && cat_charset(char_set_nm, 0, type, putout) != -1
			     || cat_charset((char *)0, cs, type, putout) != -1
			     || cat_charset(char_set, 0, type, putout) != -1
			)
				;
		}

		if (putout)
			putp (p);
		ret = E_SUCCESS;

	} else
		ret = E_FAILURE;

Return:	if (p)
		Free (p);
	if (q)
		Free (q);
	if (char_set_nm)
		Free (char_set_nm);
	return (ret);
}

/**
 ** cat_charset() - DUMP CONTENT OF CHARACTER SET DEF'N FILE
 **/

static int
#if	defined(__STDC__)
cat_charset (
	char *			name,
	int			number,
	char *			type,
	int			putout
)
#else
cat_charset (name, number, type, putout)
	char			*name;
	int			number,
				putout;
	char			*type;
#endif
{
	int fd;

	char			*p,
				*parent,
				*T,
				buf[BUFSIZ];

	int			n,
				ret;

	if (!name)
		sprintf ((name = "63"), "%d", number);

	if (!(parent = getenv("CHARSETDIR")))
		parent = CHARSETDIR;

	(T = "x")[0] = type[0];
	p = makepath(parent, T, type, name, (char *)0);
	if (!p)
		return (-1);
	if ((fd = open_locked(p, "r", 0)) < 0) {
		Free (p);
		return (-1);
	}
	Free (p);

	if (putout) {

		errno = 0;
		while ((n = read(fd, buf, BUFSIZ)))
			fwrite (buf, 1, n, stdout);

		if (errno != 0)
			ret = -1;
		else
			ret = 0;

	}
	close(fd);
	return (ret);
}
