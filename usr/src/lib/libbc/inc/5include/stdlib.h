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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1988 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * stdlib.h
 */

#ifndef	__stdlib_h
#define	__stdlib_h

#include <sys/stdtypes.h>	/* to get size_t */

#define	EXIT_SUCCESS	0
#define	EXIT_FAILURE	1
#define	RAND_MAX	0x7fff

#ifndef NULL
#define	NULL		0
#endif

extern unsigned int _mb_cur_max;

#define MB_CUR_MAX	_mb_cur_max

/* declaration of various libc functions */
extern void	abort(/* void */);
extern int	abs(/* int j */);
extern double	atof(/* const char *nptr */);
extern int	atoi(/* const char *nptr */);
extern long int	atol(/* const char *nptr */);
extern void *	bsearch(/* const void *key, const void *base, size_t nmemb,
		    size_t size, int (*compar)(const void *, const void *) */);
extern void *	calloc(/* size_t nmemb, size_t size */);
extern void	exit(/* int status */);
extern void	free(/* void *ptr */);
extern char *	getenv(/* const char *name */);
extern void *	malloc(/* size_t size */);
extern void	qsort(/* void *base, size_t nmemb, size_t size,
		    int (*compar)(const void *, const void *) */);
extern int	rand(/* void */);
extern void *	realloc(/* void *ptr, size_t size */);
extern void	srand(/* unsigned int seed */);

extern int 	mbtowc(/* wchar_t *pwc, const char *s, size_t n */);
extern int 	wctomb(/* char *s, wchar_t wchar */);
extern size_t 	mbstowcs(/* wchar_t *pwcs, const char *s, size_t n */);
extern size_t 	wcstombs(/* char *s, const wchar_t *pwcs, size_t n */);
#define	mblen(s, n)	mbtowc((wchar_t *)0, s, n)

#endif
