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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 */

#ifndef	_WORDEXP_H
#define	_WORDEXP_H

#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	struct	wordexp_t {
	size_t	we_wordc;		/* Count of paths matched by pattern */
	char	**we_wordv;		/* List of matched pathnames */
	size_t	we_offs;		/* # of slots reserved in we_pathv */
	/* following are internal to the implementation */
	char	**we_wordp;		/* we_pathv + we_offs */
	int	we_wordn;		/* # of elements allocated */
} wordexp_t;

/*
 * wordexp flags.
 */
#define	WRDE_APPEND	0x0001		/* append to existing wordexp_t */
#define	WRDE_DOOFFS	0x0002		/* use we_offs */
#define	WRDE_NOCMD	0x0004		/* don't allow $() */
#define	WRDE_REUSE	0x0008
#define	WRDE_SHOWERR	0x0010		/* don't 2>/dev/null */
#define	WRDE_UNDEF	0x0020		/* set -u */

/*
 * wordexp errors.
 */
#define	WRDE_ERRNO	(2)		/* error in "errno" */
#define	WRDE_BADCHAR	(3)		/* shell syntax character */
#define	WRDE_BADVAL	(4)		/* undefined variable expanded */
#define	WRDE_CMDSUB	(5)		/* prohibited $() */
#define	WRDE_NOSPACE	(6)		/* no memory */
#define	WRDE_SYNTAX	(7)		/* bad syntax */
#define	WRDE_NOSYS	(8)		/* function not supported (XPG4) */

extern int wordexp(const char *_RESTRICT_KYWD, wordexp_t *_RESTRICT_KYWD, int);
extern void wordfree(wordexp_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _WORDEXP_H */
