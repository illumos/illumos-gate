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
/* OBSOLETE 19961031 -- for shared library compatibility */

#include	"sfhdr.h"

#undef	_sfgetl2

_BEGIN_EXTERNS_
#if _BLD_sfio && defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern long	_sfgetl2 _ARG_((Sfio_t*, long));

#undef	extern
_END_EXTERNS_

#if __STD_C
long _sfgetl2(reg Sfio_t* f, long v)
#else
long _sfgetl2(f, v)
reg Sfio_t*	f;
long		v;
#endif
{
	if (v < 0)
		return -1;
	sfungetc(f, v);
	return sfgetl(f);
}
