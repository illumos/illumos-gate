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
#include	"sfhdr.h"

/*	Resize a stream.
	Written by Kiem-Phong Vo.
*/

#if __STD_C
int sfresize(Sfio_t* f, Sfoff_t size)
#else
int sfresize(f, size)
Sfio_t*		f;
Sfoff_t		size;
#endif
{
	SFMTXDECL(f);

	SFMTXENTER(f, -1);

	if(size < 0 || f->extent < 0 ||
	   (f->mode != SF_WRITE && _sfmode(f,SF_WRITE,0) < 0) )
		SFMTXRETURN(f, -1);

	SFLOCK(f,0);

	if(f->flags&SF_STRING)
	{	SFSTRSIZE(f);

		if(f->extent >= size)
		{	if((f->flags&SF_MALLOC) && (f->next - f->data) <= size)
			{	size_t	s = (((size_t)size + 1023)/1024)*1024;
				Void_t*	d;
				if(s < f->size && (d = realloc(f->data, s)) )
				{	f->data = d;
					f->size = s;
					f->extent = s;
				}
			}
			memclear((char*)(f->data+size), (int)(f->extent-size));
		}
		else
		{	if(SFSK(f, size, SEEK_SET, f->disc) != size)
				SFMTXRETURN(f, -1);
			memclear((char*)(f->data+f->extent), (int)(size-f->extent));
		}
	}
	else
	{	if(f->next > f->data)
			SFSYNC(f);
#if _lib_ftruncate
		if(ftruncate(f->file, (sfoff_t)size) < 0)
			SFMTXRETURN(f, -1);
#else
		SFMTXRETURN(f, -1);
#endif
	}

	f->extent = size;

	SFOPEN(f, 0);

	SFMTXRETURN(f, 0);
}
