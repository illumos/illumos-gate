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
 * Copyright (c) 1992, 1993, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <meta.h>

/*
 * free
 */
#ifdef	_DEBUG_MALLOC_INC

void
_Free(
	char	*file,
	int	line,
	void	*p
)
{
	debug_free(file, line, p);
}

#else	/* ! _DEBUG_MALLOC_INC */

void
Free(
	void	*p
)
{
	free(p);
}

#endif	/* ! _DEBUG_MALLOC_INC */

/*
 * malloc
 */
#ifdef	_DEBUG_MALLOC_INC

void *
_Malloc(
	char	*file,
	int	line,
	size_t	s
)
{
	void *mem;

	mem = debug_malloc(file, line, s);
	if (mem == NULL) {
		md_perror("");
		md_exit(NULL, 1);
	}
	return (mem);
}

#else	/* ! _DEBUG_MALLOC_INC */

void *
Malloc(
	size_t	s
)
{
	void *mem;

	if ((mem = malloc(s)) == NULL) {
		md_perror("");
		md_exit(NULL, 1);
	}
	return (mem);
}

#endif	/* ! _DEBUG_MALLOC_INC */

/*
 * zalloc
 */
#ifdef	_DEBUG_MALLOC_INC

void *
_Zalloc(
	char	*file,
	int	line,
	size_t	s
)
{
	return (memset(_Malloc(file, line, s), 0, s));
}

#else	/* ! _DEBUG_MALLOC_INC */

void *
Zalloc(
	size_t	s
)
{
	return (memset(Malloc(s), 0, s));
}

#endif	/* ! _DEBUG_MALLOC_INC */

/*
 * realloc
 */
#ifdef	_DEBUG_MALLOC_INC

void *
_Realloc(
	char	*file,
	int	line,
	void	*p,
	size_t	s
)
{
	if (p == NULL)
		p = debug_malloc(file, line, s);
	else
		p = debug_realloc(file, line, p, s);
	if (p == NULL) {
		md_perror("");
		md_exit(NULL, 1);
	}
	return (p);
}

#else	/* ! _DEBUG_MALLOC_INC */

void *
Realloc(
	void	*p,
	size_t	s
)
{
	if ((p = realloc(p, s)) == NULL) {
		md_perror("");
		md_exit(NULL, 1);
	}
	return (p);
}

#endif	/* ! _DEBUG_MALLOC_INC */

/*
 * calloc
 */
#ifdef	_DEBUG_MALLOC_INC

void *
_Calloc(
	char	*file,
	int	line,
	size_t	n,
	size_t	s
)
{
	unsigned long total;

	if (n == 0 || s == 0) {
		total = 0;
	} else {
		total = (unsigned long)n * s;
		/* check for overflow */
		if (total / n != s)
			return (NULL);
	}
	return (_Zalloc(file, line, total));
}

#else	/* ! _DEBUG_MALLOC_INC */

void *
Calloc(
	size_t	n,
	size_t	s
)
{
	unsigned long total;

	if (n == 0 || s == 0) {
		total = 0;
	} else {
		total = (unsigned long)n * s;
		/* check for overflow */
		if (total / n != s)
			return (NULL);
	}
	return (Zalloc(total));
}

#endif	/* ! _DEBUG_MALLOC_INC */

/*
 * strdup
 */
#ifdef	_DEBUG_MALLOC_INC

char *
_Strdup(
	char	*file,
	int	line,
	char	*p
)
{
	p = DBstrdup(file, line, p);
	if (p == NULL) {
		md_perror("");
		md_exit(NULL, 1);
	}
	return (p);
}

#else	/* ! _DEBUG_MALLOC_INC */

char *
Strdup(
	char	*p
)
{
	if ((p = strdup(p)) == NULL) {
		md_perror("");
		md_exit(NULL, 1);
	}
	return (p);
}

#endif	/* ! _DEBUG_MALLOC_INC */
