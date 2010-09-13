/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * posix fnmatch interface definitions
 */

#ifndef _FNMATCH_H
#define _FNMATCH_H

#include <ast_common.h>

/* fnmatch flags */

#define FNM_NOESCAPE	0x0001		/* \ is literal			*/
#define FNM_PATHNAME	0x0002		/* explicit match for /		*/
#define FNM_PERIOD	0x0004		/* explicit match for leading .	*/
#define FNM_NOSYS	0x0010		/* not implemented		*/

/* nonstandard fnmatch() flags */

#define FNM_AUGMENTED	0x0008		/* enable ! & ( | )		*/
#define FNM_ICASE	0x0020		/* ignore case in match		*/
#define FNM_LEADING_DIR	0x0040		/* match up to implicit /	*/

#define FNM_CASEFOLD	FNM_ICASE	/* gnu compatibility		*/
#define FNM_FILE_NAME	FNM_PATHNAME	/* gnu compatibility		*/

/* fnmatch error codes -- other non-zero values from <regex.h> */

#define FNM_NOMATCH	1		/* == REG_NOMATCH		*/

#if _BLD_ast && defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern int	fnmatch(const char*, const char*, int);

#undef	extern

#endif
