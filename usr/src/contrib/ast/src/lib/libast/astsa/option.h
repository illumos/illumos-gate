/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 * Glenn Fowler
 * AT&T Research
 *
 * command line option parse interface
 */

#ifndef _OPTION_H
#define _OPTION_H	1

#include <ast.h>

#define OPT_VERSION	20000401L

#define opt_info	_opt_info_

#define OPT_USER	(1L<<16)	/* first user flag bit		*/

struct Opt_s;
struct Optdisc_s;

typedef int (*Optinfo_f)(struct Opt_s*, Sfio_t*, const char*, struct Optdisc_s*);

typedef struct Optdisc_s
{
	unsigned long	version;	/* OPT_VERSION			*/
	unsigned long	flags;		/* OPT_* flags			*/
	char*		catalog;	/* error catalog id		*/
	Optinfo_f	infof;		/* runtime info function	*/
} Optdisc_t;

/* NOTE: Opt_t member order fixed by a previous binary release */

#ifndef _OPT_PRIVATE_
#define _OPT_PRIVATE_	void*	_opt_private;
#endif

typedef struct Opt_s
{
	int		again;		/* see optjoin()		*/
	char*		arg;		/* {:,#} string argument	*/
	char**		argv;		/* most recent argv		*/
	int		index;		/* argv index			*/
	char*		msg;		/* error/usage message buffer	*/
	long		num;		/* # numeric argument		*/
	int		offset;		/* char offset in argv[index]	*/
	char		option[8];	/* current flag {-,+} + option  */
	char		name[64];	/* current long name or flag	*/
	Optdisc_t*	disc;		/* user discipline		*/
	intmax_t	number;		/* # numeric argument		*/
	unsigned char	assignment;	/* option arg assigment op	*/
	unsigned char	pads[sizeof(void*)-1];
	_OPT_PRIVATE_
} Opt_t;

#define optinit(d,f)	(memset(d,0,sizeof(*(d))),(d)->version=OPT_VERSION,(d)->infof=(f),opt_info.disc=(d))

#if _BLD_ast && defined(__EXPORT__)
#define __PUBLIC_DATA__		__EXPORT__
#else
#if !_BLD_ast && defined(__IMPORT__)
#define __PUBLIC_DATA__		__IMPORT__
#else
#define __PUBLIC_DATA__
#endif
#endif

extern __PUBLIC_DATA__ Opt_t		opt_info;

#undef	__PUBLIC_DATA__

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int		optget(char**, const char*);
extern int		optjoin(char**, ...);
extern char*		opthelp(const char*, const char*);
extern char*		optusage(const char*);
extern int		optstr(const char*, const char*);

#undef	extern

#endif
