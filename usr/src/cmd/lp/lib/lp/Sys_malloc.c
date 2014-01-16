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


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.14	*/
/* LINTLIBRARY */

#include "unistd.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "errno.h"
#include "fcntl.h"
#include "stdlib.h"
#include "string.h"

/**
 ** _Malloc()
 ** _Realloc()
 ** _Calloc()
 ** _Strdup()
 ** _Free()
 **/

#if	!defined(TRACE_MALLOC)

#if	defined(__STDC__)
void			(*lp_alloc_fail_handler)( void ) = 0;
#else
void			(*lp_alloc_fail_handler)() = 0;
#endif

#if	defined(__STDC__)
typedef void *alloc_type;
#else
typedef char *alloc_type;
#endif

alloc_type
#if	defined(__STDC__)
_Malloc (
	size_t			size,
	const char *		file,
	int			line
)
#else
_Malloc (size, file, line)
	size_t			size;
	char *			file;
	int			line;
#endif
{
	alloc_type		ret	= malloc(size);

	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

alloc_type
#if	defined(__STDC__)
_Realloc (
	void *			ptr,
	size_t			size,
	const char *		file,
	int			line
)
#else
_Realloc (ptr, size, file, line)
	char *			ptr;
	size_t			size;
	char *			file;
	int			line;
#endif
{
	alloc_type		ret	= realloc(ptr, size);

	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

alloc_type
#if	defined(__STDC__)
_Calloc (
	size_t			nelem,
	size_t			elsize,
	const char *		file,
	int			line
)
#else
_Calloc (nelem, elsize, file, line)
	size_t			nelem;
	size_t			elsize;
	char *			file;
	int			line;
#endif
{
	alloc_type		ret	= calloc(nelem, elsize);

	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

char *
#if	defined(__STDC__)
_Strdup (
	const char *		s,
	const char *		file,
	int			line
)
#else
_Strdup (s, file, line)
	char *			s;
	char *			file;
	int			line;
#endif
{
	char *			ret;

	if (!s)
		return( (char *) 0);

	ret = strdup(s);

	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

void
#if	defined(__STDC__)
_Free (
	void *			ptr,
	const char *		file,
	int			line
)
#else
_Free (ptr, file, line)
	char *			ptr;
	char *			file;
	int			line;
#endif
{
	free (ptr);
	return;
}

#else
# include "mdl.c"
#endif
