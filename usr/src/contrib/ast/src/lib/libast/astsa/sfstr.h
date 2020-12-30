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
#ifndef _SFSTR_H
#define _SFSTR_H	1

#include <ast.h>

typedef struct Sfstr_s
{
	char*		beg;
	char*		nxt;
	char*		end;
} Sfstr_t;

#undef	sfclose
#undef	sfprintf
#undef	sfprints
#undef	sfputc
#undef	sfputr
#undef	sfstrbase
#undef	sfstropen
#undef	sfstrseek
#undef	sfstrset
#undef	sfstrtell
#undef	sfstruse
#undef	sfwrite

extern int	sfclose(Sfio_t*);
extern int	sfprintf(Sfio_t*, const char*, ...);
extern char*	sfprints(const char*, ...);
extern int	sfputc(Sfio_t*, int);
extern int	sfputr(Sfio_t*, const char*, int);
extern char*	sfstrbase(Sfio_t*);
extern Sfio_t*	sfstropen(void);
extern char*	sfstrseek(Sfio_t*, int, int);
extern char*	sfstrset(Sfio_t*, int);
extern int	sfstrtell(Sfio_t*);
extern char*	sfstruse(Sfio_t*);
extern int	sfwrite(Sfio_t*, void*, int);

#endif
