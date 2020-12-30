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
 * AT&T Research
 *
 * sfio discipline interface definitions
 */

#ifndef _SFDISC_H
#define _SFDISC_H

#include <ast.h>

#define SFDCEVENT(a,b,n)	((((a)-'A'+1)<<11)^(((b)-'A'+1)<<6)^(n))

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

#define SFSK_DISCARD		SFDCEVENT('S','K',1)

/*
 * %(...) printf support
 */

typedef int (*Sf_key_lookup_t)(void*, Sffmt_t*, const char*, char**, Sflong_t*);
typedef char* (*Sf_key_convert_t)(void*, Sffmt_t*, const char*, char*, Sflong_t);

extern int		sfkeyprintf(Sfio_t*, void*, const char*, Sf_key_lookup_t, Sf_key_convert_t);
extern int		sfkeyprintf_20000308(Sfio_t*, void*, const char*, Sf_key_lookup_t, Sf_key_convert_t);

/*
 * pure sfio read and/or write disciplines
 */

extern int		sfdcdio(Sfio_t*, size_t);
extern int		sfdcdos(Sfio_t*);
extern int		sfdcfilter(Sfio_t*, const char*);
extern int		sfdcmore(Sfio_t*, const char*, int, int);
extern int		sfdcprefix(Sfio_t*, const char*);
extern int		sfdcseekable(Sfio_t*);
extern int		sfdcslow(Sfio_t*);
extern int		sfdctee(Sfio_t*, Sfio_t*);
extern int		sfdcunion(Sfio_t*, Sfio_t**, int);

extern Sfio_t*		sfdcsubstream(Sfio_t*, Sfio_t*, Sfoff_t, Sfoff_t);

#undef	extern

#endif
