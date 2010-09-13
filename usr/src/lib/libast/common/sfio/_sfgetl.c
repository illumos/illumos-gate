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
#include	"sfhdr.h"

/*
 * for backwards compatibility with pre-threaded sfgetl() inline
 */

#ifdef __EXPORT__
#define extern	__EXPORT__
#endif

extern
#if __STD_C
Sflong_t _sfgetl(reg Sfio_t* f)
#else
Sflong_t _sfgetl(f)
reg Sfio_t*	f;
#endif
{
	sfungetc(f, (unsigned char)_SF_(f)->val);
	return sfgetl(f);
}
