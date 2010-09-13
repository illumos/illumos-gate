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
 * Glenn Fowler
 * AT&T Research
 *
 * sfio tmp string buffer support
 */

#include <sfio_t.h>
#include <ast.h>

#if __OBSOLETE__ >= 20070101 /* sfstr* macros now use sfsetbuf() */

NoN(sfstrtmp)

#else

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

/*
 * replace buffer in string stream f for either SF_READ or SF_WRITE
 */

extern int
sfstrtmp(register Sfio_t* f, int mode, void* buf, size_t siz)
{
	if (!(f->_flags & SF_STRING))
		return -1;
	if (f->_flags & SF_MALLOC)
		free(f->_data);
	f->_flags &= ~(SF_ERROR|SF_MALLOC);
	f->mode = mode;
	f->_next = f->_data = (unsigned char*)buf;
	f->_endw = f->_endr = f->_endb = f->_data + siz;
	f->_size = siz;
	return 0;
}

#endif
