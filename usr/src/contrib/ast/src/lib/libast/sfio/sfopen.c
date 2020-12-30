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
#include	"sfhdr.h"

/*
 * _sfopen() wrapper to allow user sfopen() intercept
 */

extern Sfio_t*		_sfopen _ARG_((Sfio_t*, const char*, const char*));

#if __STD_C
Sfio_t* sfopen(Sfio_t* f, const char* file, const char* mode)
#else
Sfio_t* sfopen(f,file,mode)
Sfio_t*		f;		/* old stream structure */
char*		file;		/* file/string to be opened */
reg char*	mode;		/* mode of the stream */
#endif
{
	return _sfopen(f, file, mode);
}
