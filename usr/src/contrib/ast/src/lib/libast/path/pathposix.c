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
 * Glenn Fowler
 * AT&T Research
 *
 * convert native path to posix fs representation in <buf,siz>
 * length of converted path returned
 * if return length >= siz then buf is indeterminate, but another call
 * with siz=length+1 would work
 * if buf==0 then required size is returned
 */

#include <ast.h>

#if _UWIN

#include <uwin.h>

size_t
pathposix(const char* path, char* buf, size_t siz)
{
	return uwin_unpath(path, buf, siz);
}

#else

#if __CYGWIN__

extern void	cygwin_conv_to_posix_path(const char*, char*);

size_t
pathposix(const char* path, char* buf, size_t siz)
{
	size_t		n;

	if (!buf || siz < PATH_MAX)
	{
		char	tmp[PATH_MAX];

		cygwin_conv_to_posix_path(path, tmp);
		if ((n = strlen(tmp)) < siz && buf)
			memcpy(buf, tmp, n + 1);
		return n;
	}
	cygwin_conv_to_posix_path(path, buf);
	return strlen(buf);
}

#else

#if __EMX__ && 0 /* show me the docs */

size_t
pathposix(const char* path, char* buf, size_t siz)
{
	char*		s;
	size_t		n;

	if (!_posixpath(buf, path, siz))
	{
		for (s = buf; *s; s++)
			if (*s == '/')
				*s = '\\';
	}
	else if ((n = strlen(path)) < siz && buf)
		memcpy(buf, path, n + 1);
	return n;
}

#else

#if __INTERIX

#include <interix/interix.h>

size_t
pathposix(const char* path, char *buf, size_t siz)
{
	static const char	pfx[] = "/dev/fs";

	*buf = 0;
	if (!strncasecmp(path, pfx, sizeof(pfx) - 1))
		strlcpy(buf, path, siz);
	else
		winpath2unix(path, PATH_NONSTRICT, buf, siz);
	return strlen(buf);
}

#else

size_t
pathposix(const char* path, char* buf, size_t siz)
{
	size_t		n;

	if ((n = strlen(path)) < siz && buf)
		memcpy(buf, path, n + 1);
	return n;
}

#endif

#endif

#endif

#endif
