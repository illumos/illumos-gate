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
 * ftw,nftw over ftwalk
 */

#ifndef _FTW_H
#define _FTW_H

#define FTW		FTWALK
#include <ftwalk.h>
#undef			FTW

#define FTW_SLN		(FTW_SL|FTW_NR)

#define FTW_PHYS	(FTW_PHYSICAL)
#define FTW_CHDIR	(FTW_DOT)
#define FTW_DEPTH	(FTW_POST)
#define FTW_OPEN	(0)

struct FTW
{
	int		quit;
	int		base;
	int		level;
};

#define FTW_SKD		FTW_SKIP
#define FTW_PRUNE	FTW_SKIP

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int	ftw(const char*, int(*)(const char*, const struct stat*, int), int);
extern int	nftw(const char*, int(*)(const char*, const struct stat*, int, struct FTW*), int, int);

#undef	extern

#endif
