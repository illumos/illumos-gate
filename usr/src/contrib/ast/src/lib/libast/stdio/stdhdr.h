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

#ifndef _STDHDR_H
#define _STDHDR_H	1

#ifndef _NO_LARGEFILE64_SOURCE
#define _NO_LARGEFILE64_SOURCE	1
#endif
#undef	_LARGEFILE64_SOURCE

#define _ast_fseeko	______fseeko
#define _ast_ftello	______ftello
#include "sfhdr.h"
#undef	_ast_fseeko
#undef	_ast_ftello

#include "stdio.h"

#define SF_MB		010000
#define SF_WC		020000

#if _UWIN

#define STDIO_TRANSFER	1

typedef int (*Fun_f)();

typedef struct Funvec_s
{
	const char*	name;
	Fun_f		vec[2];
} Funvec_t;

extern int	_stdfun(Sfio_t*, Funvec_t*);

#define STDIO_INT(p,n,t,f,a) \
	{ \
		typedef t (*_s_f)f; \
		int		_i; \
		static Funvec_t	_v = { n }; \
		if ((_i = _stdfun(p, &_v)) < 0) \
			return -1; \
		else if (_i > 0) \
			return ((_s_f)_v.vec[_i])a; \
	}

#define STDIO_PTR(p,n,t,f,a) \
	{ \
		typedef t (*_s_f)f; \
		int		_i; \
		static Funvec_t	_v = { n }; \
		if ((_i = _stdfun(p, &_v)) < 0) \
			return 0; \
		else if (_i > 0) \
			return ((_s_f)_v.vec[_i])a; \
	}

#define STDIO_VOID(p,n,t,f,a) \
	{ \
		typedef t (*_s_f)f; \
		int		_i; \
		static Funvec_t	_v = { n }; \
		if ((_i = _stdfun(p, &_v)) < 0) \
			return; \
		else if (_i > 0) \
		{ \
			((_s_f)_v.vec[_i])a; \
			return; \
		} \
	}

#else

#define STDIO_INT(p,n,t,f,a)
#define STDIO_PTR(p,n,t,f,a)
#define STDIO_VOID(p,n,t,f,a)

#endif

#define FWIDE(f,r) \
	do \
	{ \
		if (fwide(f, 0) < 0) \
			return r; \
		f->bits |= SF_WC; \
	} while (0)

#ifdef __EXPORT__
#define extern	__EXPORT__
#endif

extern int		sfdcwide(Sfio_t*);

#endif
