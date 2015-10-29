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
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 */

/*
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)glob.h	8.1 (Berkeley) 6/2/93
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2013 Gary Mills
 */

#ifndef	_GLOB_H
#define	_GLOB_H

#include <sys/feature_tests.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef	struct	glob_t	{
	/*
	 * Members specified by POSIX
	 */
	size_t	gl_pathc;	/* Total count of paths matched by pattern */
	char	**gl_pathv;	/* List of matched pathnames */
	size_t	gl_offs;	/* # of slots reserved in gl_pathv */

	/*
	 * Internal-use members:
	 *
	 * NB: The next two members are carried in both the
	 * libc backward compatibility wrapper functions and
	 * the extended functions.
	 */
	char	**gl_pathp;	/* gl_pathv + gl_offs */
	int	gl_pathn;	/* # of elements allocated */

	/*
	 * Non-POSIX extensions
	 *
	 * NB: The following members are not carried in
	 * the libc backward compatibility wrapper functions.
	 */
	int	gl_matchc;	/* Count of paths matching pattern. */
	int	gl_flags;	/* Copy of flags parameter to glob. */
	struct	stat **gl_statv; /* Stat entries corresponding to gl_pathv */

	/*
	 * Alternate filesystem access methods for glob; replacement
	 * versions of closedir(3), readdir(3), opendir(3), stat(2)
	 * and lstat(2).
	 */
	void (*gl_closedir)(void *);
	struct dirent *(*gl_readdir)(void *);
	void *(*gl_opendir)(const char *);
	int (*gl_lstat)(const char *, struct stat *);
	int (*gl_stat)(const char *, struct stat *);
}	glob_t;

/*
 * POSIX "flags" argument to glob function.
 */
#define	GLOB_ERR	0x0001		/* Don't continue on directory error */
#define	GLOB_MARK	0x0002		/* Mark directories with trailing / */
#define	GLOB_NOSORT	0x0004		/* Don't sort pathnames */
#define	GLOB_NOCHECK	0x0008		/* Return unquoted arg if no match */
#define	GLOB_DOOFFS	0x0010		/* Ignore gl_offs unless set */
#define	GLOB_APPEND	0x0020		/* Append to previous glob_t */
#define	GLOB_NOESCAPE	0x0040		/* Backslashes do not quote M-chars */

/*
 * Non-POSIX "flags" argument to glob function, from OpenBSD.
 */
#if !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__)
#define	GLOB_POSIX	0x007F	/* All POSIX flags */
#define	GLOB_BRACE	0x0080	/* Expand braces ala csh. */
#define	GLOB_MAGCHAR	0x0100	/* Pattern had globbing characters. */
#define	GLOB_NOMAGIC	0x0200	/* GLOB_NOCHECK without magic chars (csh). */
#define	GLOB_QUOTE	0x0400	/* Quote special chars with \. */
#define	GLOB_TILDE	0x0800	/* Expand tilde names from the passwd file. */
#define	GLOB_LIMIT	0x2000	/* Limit pattern match output to ARG_MAX */
#define	GLOB_KEEPSTAT	0x4000	/* Retain stat data for paths in gl_statv. */
#define	GLOB_ALTDIRFUNC	0x8000	/* Use alternately specified directory funcs. */
#endif /* !defined(__XOPEN_OR_POSIX) || defined(__EXTENSIONS__) */

/*
 * Error returns from "glob"
 */
#define	GLOB_NOSYS	(-4)		/* function not supported (XPG4) */
#define	GLOB_NOMATCH	(-3)		/* Pattern does not match */
#define	GLOB_NOSPACE	(-2)		/* Not enough memory */
#define	GLOB_ABORTED	(-1)		/* GLOB_ERR set or errfunc return!=0 */
#define	GLOB_ABEND	GLOB_ABORTED	/* backward compatibility */


#ifdef __PRAGMA_REDEFINE_EXTNAME
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#pragma	redefine_extname	glob	_glob_ext64
#pragma	redefine_extname	globfree	_globfree_ext64
#else
#pragma	redefine_extname	glob	_glob_ext
#pragma	redefine_extname	globfree	_globfree_ext
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */
#else /* __PRAGMA_REDEFINE_EXTNAME */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#define	glob	_glob_ext64
#define	globfree	_globfree_ext64
#else
#define	glob	_glob_ext
#define	globfree	_globfree_ext
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */
#endif /* __PRAGMA_REDEFINE_EXTNAME */

extern int glob(const char *_RESTRICT_KYWD, int, int(*)(const char *, int),
		glob_t *_RESTRICT_KYWD);
extern void globfree(glob_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _GLOB_H */
