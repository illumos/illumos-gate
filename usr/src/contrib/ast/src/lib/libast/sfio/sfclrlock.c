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

/*	Function to clear a locked stream.
**	This is useful for programs that longjmp from the mid of an sfio function.
**	There is no guarantee on data integrity in such a case.
**
**	Written by Kiem-Phong Vo
*/
#if __STD_C
int sfclrlock(Sfio_t* f)
#else
int sfclrlock(f)
Sfio_t	*f;
#endif
{
	int	rv;
	SFMTXDECL(f); /* declare a local stream variable for multithreading */

	/* already closed */
	if(f && (f->mode&SF_AVAIL))
		return 0;

	SFMTXENTER(f,0);

	/* clear error bits */
	f->flags &= ~(SF_ERROR|SF_EOF);

	/* clear peek locks */
	if(f->mode&SF_PKRD)
	{	f->here -= f->endb-f->next;
		f->endb = f->next;
	}

	SFCLRBITS(f);

	/* throw away all lock bits except for stacking state SF_PUSH */
	f->mode &= (SF_RDWR|SF_INIT|SF_POOL|SF_PUSH|SF_SYNCED|SF_STDIO);

	rv = (f->mode&SF_PUSH) ? 0 : (f->flags&SF_FLAGS);

	SFMTXRETURN(f, rv);
}
