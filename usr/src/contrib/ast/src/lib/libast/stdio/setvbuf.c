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
setvbuf(Sfio_t* f, char* buf, int type, size_t size)
{
	STDIO_INT(f, "setvbuf", int, (Sfio_t*, char*, int, size_t), (f, buf, type, size))

	if (type == _IOLBF)
		sfset(f, SF_LINE, 1);
	else if (f->flags & SF_STRING)
		return -1;
	else if (type == _IONBF)
	{	
		sfsync(f);
		sfsetbuf(f, NiL, 0);
	}
	else if (type == _IOFBF)
	{	
		if (size == 0)
			size = SF_BUFSIZE;
		sfsync(f);
		sfsetbuf(f, (Void_t*)buf, size);
	}
	return 0;
}
