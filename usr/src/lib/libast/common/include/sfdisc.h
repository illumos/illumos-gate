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
#define sfkeyprintf	sfkeyprintf_20000308 /* Sffmt_t* callback args */
extern int		sfkeyprintf(Sfio_t*, void*, const char*, Sf_key_lookup_t, Sf_key_convert_t);

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
