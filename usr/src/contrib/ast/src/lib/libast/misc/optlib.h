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
 * Glenn Fowler
 * AT&T Research
 *
 * command line option parser and usage formatter private definitions
 */

#ifndef _OPTLIB_H
#define _OPTLIB_H

#include <ast.h>
#include <cdt.h>

#define OPT_append		0x001
#define OPT_cache		0x002
#define OPT_functions		0x004
#define OPT_ignore		0x008
#define OPT_long		0x010
#define OPT_minus		0x020
#define OPT_module		0x040
#define OPT_numeric		0x080
#define OPT_old			0x100
#define OPT_plus		0x200

#define OPT_cache_flag		0x001
#define OPT_cache_invert	0x002
#define OPT_cache_numeric	0x004
#define OPT_cache_optional	0x008
#define OPT_cache_string	0x010

#define OPT_CACHE		128
#define OPT_FLAGS		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

struct Optdisc_s;

typedef struct Optpass_s
{
	char*			opts;
	char*			oopts;
	char*			id;
	char*			catalog;
	char*			release;
	char			section[4];
	unsigned char		version;
	unsigned char		prefix;
	unsigned short		flags;
} Optpass_t;

typedef struct Optcache_s
{
	struct Optcache_s*	next;
	Optpass_t		pass;
	int			caching;
	unsigned char		flags[sizeof(OPT_FLAGS)];
} Optcache_t;

typedef struct Optstate_s
{
	Sfio_t*		mp;		/* opt_info.msg string stream	*/
	Sfio_t*		vp;		/* translation string stream	*/
	Sfio_t*		xp;		/* translation string stream	*/
	Sfio_t*		cp;		/* compatibility string stream	*/
	Optpass_t	pass[8];	/* optjoin() list		*/
	char*		argv[2];	/* initial argv copy		*/
	char*		strv[3];	/* optstr() argv		*/
	char*		str;		/* optstr() string		*/
	Sfio_t*		strp;		/* optstr() stream		*/
	int		force;		/* force this style		*/
	int		pindex;		/* prev index for backup	*/
	int		poffset;	/* prev offset for backup	*/
	int		npass;		/* # optjoin() passes		*/
	int		join;		/* optjoin() pass #		*/
	int		plus;		/* + ok				*/
	int		style;		/* default opthelp() style	*/
	int		width;		/* format line width		*/
	int		flags;		/* display flags		*/
	int		emphasis;	/* ansi term emphasis ok	*/
	int		localized;	/* locale initialized		*/
	Dtdisc_t	msgdisc;	/* msgdict discipline		*/
	Dt_t*		msgdict;	/* default ast.id catalog msgs	*/
	Optcache_t*	cache;		/* OPT_cache cache		*/
	char**		conformance;	/* conformance id vector	*/
} Optstate_t;

#define _OPT_PRIVATE_ \
	char            pad[2*sizeof(void*)]; \
	Optstate_t*	state;

#include <error.h>

extern Optstate_t*	optstate(Opt_t*);

#endif
