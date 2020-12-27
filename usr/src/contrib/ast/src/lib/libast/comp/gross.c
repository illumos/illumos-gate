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
/*
 * porting hacks here
 */

#include <ast.h>
#include <ls.h>

#include "FEATURE/hack"

void _STUB_gross(){}

#if _lcl_xstat

extern int fstat(int fd, struct stat* st)
{
#if _lib___fxstat
	return __fxstat(_STAT_VER, fd, st);
#else
	return _fxstat(_STAT_VER, fd, st);
#endif
}

extern int lstat(const char* path, struct stat* st)
{
#if _lib___lxstat
	return __lxstat(_STAT_VER, path, st);
#else
	return _lxstat(_STAT_VER, path, st);
#endif
}

extern int stat(const char* path, struct stat* st)
{
#if _lib___xstat
	return __xstat(_STAT_VER, path, st);
#else
	return _xstat(_STAT_VER, path, st);
#endif
}

#endif

#if _lcl_xstat64

extern int fstat64(int fd, struct stat64* st)
{
#if _lib___fxstat64
	return __fxstat64(_STAT_VER, fd, st);
#else
	return _fxstat64(_STAT_VER, fd, st);
#endif
}

extern int lstat64(const char* path, struct stat64* st)
{
#if _lib___lxstat64
	return __lxstat64(_STAT_VER, path, st);
#else
	return _lxstat64(_STAT_VER, path, st);
#endif
}

extern int stat64(const char* path, struct stat64* st)
{
#if _lib___xstat64
	return __xstat64(_STAT_VER, path, st);
#else
	return _xstat64(_STAT_VER, path, st);
#endif
}

#endif

#if __sgi && _hdr_locale_attr

#include "gross_sgi.h"

#endif
