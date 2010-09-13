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

#include "stdhdr.h"

int
fwide(Sfio_t* f, int mode)
{
	STDIO_INT(f, "fwide", int, (Sfio_t*, int), (f, mode))

	if (mode > 0)
	{
		f->bits &= ~SF_MB;
		f->bits |= SF_WC;
	}
	else if (mode < 0)
	{
		f->bits &= ~SF_WC;
		f->bits |= SF_MB;
	}
	if (f->bits & SF_MB)
		return -1;
	if (f->bits & SF_WC)
		return 1;
	if ((f->flags & SF_SYNCED) || f->next > f->data)
	{
		f->bits |= SF_MB;
		return -1;
	}
	return 0;
}
