/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
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
 * Phong Vo
 * Glenn Fowler
 * AT&T Research
 *
 * ast ftwalk interface definitions
 * ftwalk was the initial improvement on ftw and nftw
 * which formed the basis for the POSIX fts proposal
 *
 * NOTE: this file is in cahoots with the fts implementation
 */

#ifndef _FTWALK_H
#define _FTWALK_H

#define fts_info	info
#define fts_level	level
#define fts_link	link
#define fts_name	name
#define fts_namelen	namelen
#define fts_parent	parent
#define fts_path	path
#define fts_pathlen	pathlen
#define _fts_status	status
#define _fts_statb	statb

#define FTSENT		Ftw_t			/* <fts.h> internal	*/
#define Ftsent		FTW			/* <fts.h> internal	*/

#define _FTSENT_LOCAL_PRIVATE_			/* <fts.h> internal	*/ \
	union								   \
	{								   \
	long		number;			/* local numeric value	*/ \
	void*		pointer;		/* local pointer value	*/ \
	}		local;

#include <fts.h>

/*
 * ftwalk() argument flags
 */

#define FTW_CANON	FTS_CANON
#define FTW_CHILDREN	(FTS_USER<<0)
#define FTW_DELAY	FTS_NOSTAT
#define FTW_DOT		FTS_NOCHDIR
#define FTW_META	FTS_META
#define FTW_MOUNT	FTS_XDEV
#define FTW_MULTIPLE	FTS_ONEPATH
#define FTW_NOSEEDOTDIR	FTS_NOSEEDOTDIR
#define FTW_PHYSICAL	FTS_PHYSICAL
#define FTW_POST	(FTS_USER<<1)
#define FTW_SEEDOTDIR	FTS_SEEDOTDIR
#define FTW_TOP		FTS_TOP
#define FTW_TWICE	(FTS_USER<<2)
#define FTW_USER	(FTS_USER<<3)

/*
 * Ftw_t.info type bits
 */

#define FTW_C		FTS_C
#define FTW_D		FTS_D
#define FTW_DC		FTS_DC
#define FTW_DNR		FTS_DNR
#define FTW_DNX		FTS_DNX
#define FTW_DP		FTS_DP
#define FTW_F		FTS_F
#define FTW_NR		FTS_NR
#define FTW_NS		FTS_NS
#define FTW_NSOK	FTS_NSOK
#define FTW_NX		FTS_NX
#define FTW_P		FTS_P
#define FTW_SL		FTS_SL

/*
 * Ftw_t.status entry values
 */

#define FTW_NAME	FTS_DOT		/* access by Ftw_t.name		*/
#define FTW_PATH	FTS_NOCHDIR	/* access by Ftw_t.path		*/

/*
 * Ftw_t.status return values
 */

#define FTW_AGAIN	FTS_AGAIN
#define FTW_FOLLOW	FTS_FOLLOW
#define FTW_NOPOST	FTS_NOPOSTORDER
#define FTW_SKIP	FTS_SKIP
#define FTW_STAT	FTS_STAT

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int	ftwalk(const char*, int(*)(Ftw_t*), int, int(*)(Ftw_t*, Ftw_t*));
extern int	ftwflags(void);

#undef	extern

#endif
