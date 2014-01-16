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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* LINTLIBRARY */

#if	defined(__STDC__)
#include "stdarg.h"
#else
#include "varargs.h"
#endif

#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"

/**
 ** makepath() - CREATE PATHNAME FROM COMPONENTS
 **/

/*VARARGS1*/
char *
#if	defined(__STDC__)
makepath (
	char *			s,
	...
)
#else
makepath (s, va_alist)
	char *			s;
	va_dcl
#endif
{
	va_list			ap;

	register char		*component,
				*p,
				*q;

	register int		len;

	char			*ret;


#if	defined(__STDC__)
	va_start (ap, s);
#else
	va_start (ap);
#endif

	for (len = strlen(s) + 1; (component = va_arg(ap, char *)); )
		len += strlen(component) + 1;

	va_end (ap);

	if (!len) {
		errno = 0;
		return (0);
	}

	if (!(ret = Malloc(len))) {
		errno = ENOMEM;
		return (0);
	}

#if	defined(__STDC__)
	va_start (ap, s);
#else
	va_start (ap);
#endif

	for (
		p = ret, component = s;
		component;
		component = va_arg(ap, char *)
	) {
		for (q = component; *q; )
			*p++ = *q++;
		*p++ = '/';
	}
	p[-1] = 0;

	va_end (ap);

	return (ret);
}
