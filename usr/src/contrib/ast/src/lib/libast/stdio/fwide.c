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
