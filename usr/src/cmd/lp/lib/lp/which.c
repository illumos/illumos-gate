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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "ctype.h"
#include "string.h"
#include "stdlib.h"
#include "unistd.h"

#include "lp.h"

/**
 ** isprinter() - SEE IF ARGUMENT IS A REAL PRINTER
 **/

int
#if	defined(__STDC__)
isprinter (
	char *			str
)
#else
isprinter (str)
	char			*str;
#endif
{
	char			*path	= 0;

	int			bool;

	bool = (
		str
	     && *str
	     && (path = getprinterfile(str, CONFIGFILE))
	     && Access(path, F_OK) == 0
	);
	if (path)
		Free (path);
	return (bool);
}

/**
 ** isclass() - SEE IF ARGUMENT IS A REAL CLASS
 **/

int
#if	defined(__STDC__)
isclass (
	char *			str
)
#else
isclass (str)
	char			*str;
#endif
{
	char			*path	= 0;

	int			bool;

	bool = (
		str
	     && *str
	     && (path = getclassfile(str))
	     && Access(path, F_OK) == 0
	);
	if (path)
		Free (path);
	return (bool);
}

/**
 ** isrequest() - SEE IF ARGUMENT LOOKS LIKE A REAL REQUEST
 **/

int
#if	defined(__STDC__)
isrequest (
	char *			str
)
#else
isrequest (str)
	char			*str;
#endif
{
	char			*dashp;

	/*
	 * Valid print requests have the form
	 *
	 *	dest-NNN
	 *
	 * where ``dest'' looks like a printer or class name.
	 * An earlier version of this routine checked to see if
	 * the ``dest'' was an EXISTING printer or class, but
	 * that caused problems with valid requests moved from
	 * a deleted printer or class (the request ID doesn't
	 * change in the new LP).
	 */

	if (!str || !*str)
		return (0);

	if (!(dashp = strrchr(str, '-')))
		return (0);

	if (dashp == str)
	    return(0);

	*dashp = 0;
	if (!syn_name(str)) {
		*dashp = '-';
		return (0);
	}
	*dashp++ = '-';

	if (!isnumber(dashp))
		return (0);

	return (1);
}

int
#if	defined(__STDC__)
isnumber (
	char *			s
)
#else
isnumber (s)
	char			*s;
#endif
{
	register int		c;

	if (!s || !*s)
		return (0);
	while ((c = *(s++)) != '\0')
		if (!isdigit(c))
			return (0);
	return (1);
}
