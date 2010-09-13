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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 */

#ifndef	_GLOB_H
#define	_GLOB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	struct	glob_t	{
	size_t	gl_pathc;		/* Count of paths matched by pattern */
	char	**gl_pathv;		/* List of matched pathnames */
	size_t	gl_offs;		/* # of slots reserved in gl_pathv */
	/* following are internal to the implementation */
	char	**gl_pathp;		/* gl_pathv + gl_offs */
	int	gl_pathn;		/* # of elements allocated */
}	glob_t;

/*
 * "flags" argument to glob function.
 */
#define	GLOB_ERR	0x0001		/* Don't continue on directory error */
#define	GLOB_MARK	0x0002		/* Mark directories with trailing / */
#define	GLOB_NOSORT	0x0004		/* Don't sort pathnames */
#define	GLOB_NOCHECK	0x0008		/* Return unquoted arg if no match */
#define	GLOB_DOOFFS	0x0010		/* Ignore gl_offs unless set */
#define	GLOB_APPEND	0x0020		/* Append to previous glob_t */
#define	GLOB_NOESCAPE	0x0040		/* Backslashes do not quote M-chars */

/*
 * Error returns from "glob"
 */
#define	GLOB_NOSYS	(-4)		/* function not supported (XPG4) */
#define	GLOB_NOMATCH	(-3)		/* Pattern does not match */
#define	GLOB_NOSPACE	(-2)		/* Not enough memory */
#define	GLOB_ABORTED	(-1)		/* GLOB_ERR set or errfunc return!=0 */

#if defined(__STDC__)
extern int glob(const char *_RESTRICT_KYWD, int, int(*)(const char *, int),
		glob_t *_RESTRICT_KYWD);
extern void globfree(glob_t *);
#else
extern int glob();
extern void globfree();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _GLOB_H */
