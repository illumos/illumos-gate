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
 * machine independent binary message catalog interface
 *
 * file layout
 * all numbers are sfputu() format
 *
 *	4 char magic (^M^S^G0)
 *	<method locale YYYY-MM-DD>\0
 *	(<optional strings>\0)*
 *	\0
 *	string table size
 *	#msgs total
 *	#max set number
 *	#set-id 1
 *	#msgs in set 1
 *	 ...
 *	#set-id #sets
 *	#msgs in set #sets
 *	end of sets (0)
 *	msg(1,1) size
 *	 ...
 *	msg(#sets,#msgs) size
 *	string table
 */

#ifndef _MC_H
#define _MC_H

#include <ast.h>

#define MC_MAGIC	"\015\023\007\000"
#define MC_MAGIC_SIZE	4

#define MC_SET_MAX	1023
#define MC_NUM_MAX	32767

#define MC_NLS		(1<<10)

#define MC_MESSAGE_SET(s)	mcindex(s,NiL,NiL,NiL)

typedef struct Mcset_s
{
	char**		msg;
	int		num;
	int		gen;
} Mcset_t;

typedef struct Mc_s
{
	Mcset_t*	set;
	int		num;
	int		gen;
	char*		translation;
#ifdef _MC_PRIVATE_
	_MC_PRIVATE_
#endif
} Mc_t;

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern char*		mcfind(const char*, const char*, int, int, char*, size_t);
extern Mc_t*		mcopen(Sfio_t*);
extern char*		mcget(Mc_t*, int, int, const char*);
extern int		mcput(Mc_t*, int, int, const char*);
extern int		mcdump(Mc_t*, Sfio_t*);
extern int		mcindex(const char*, char**, int*, int*);
extern int		mcclose(Mc_t*);

#undef	extern

#endif
