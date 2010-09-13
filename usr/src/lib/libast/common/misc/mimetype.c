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
 * mime/mailcap to magic support
 */

#include "mimelib.h"

/*
 * close magic handle
 * done this way so that magic is only pulled in
 * if mimetype() is used
 */

static void
drop(Mime_t* mp)
{
	if (mp->magic)
	{
		magicclose(mp->magic);
		mp->magic = 0;
	}
}

/*
 * return mime type for file
 */

char*
mimetype(Mime_t* mp, Sfio_t* fp, const char* file, struct stat* st)
{
	if (mp->disc->flags & MIME_NOMAGIC)
		return 0;
	if (!mp->magic)
	{
		mp->magicd.version = MAGIC_VERSION;
		mp->magicd.flags = MAGIC_MIME;
		mp->magicd.errorf = mp->disc->errorf;
		if (!(mp->magic = magicopen(&mp->magicd)))
		{
			mp->disc->flags |= MIME_NOMAGIC;
			return 0;
		}
		mp->freef = drop;
		magicload(mp->magic, NiL, 0);
	}
	return magictype(mp->magic, fp, file, st);
}
