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

/*	Obtain/release exclusive use of a stream.
**
**	Written by Kiem-Phong Vo.
*/

/* the main locking/unlocking interface */
#if __STD_C
int sfmutex(Sfio_t* f, int type)
#else
int sfmutex(f, type)
Sfio_t*	f;
int	type;
#endif
{
#if !vt_threaded
	NOTUSED(f); NOTUSED(type);
	return 0;
#else

	SFONCE();

	if(!f)
		return -1;

	if(!f->mutex)
	{	if(f->bits&SF_PRIVATE)
			return 0;

		vtmtxlock(_Sfmutex);
		f->mutex = vtmtxopen(NIL(Vtmutex_t*), VT_INIT);
		vtmtxunlock(_Sfmutex);
		if(!f->mutex)
			return -1;
	}

	if(type == SFMTX_LOCK)
		return vtmtxlock(f->mutex);
	else if(type == SFMTX_TRYLOCK)
		return vtmtxtrylock(f->mutex);
	else if(type == SFMTX_UNLOCK)
		return vtmtxunlock(f->mutex);
	else if(type == SFMTX_CLRLOCK)
		return vtmtxclrlock(f->mutex);
	else	return -1;
#endif /*vt_threaded*/
}
