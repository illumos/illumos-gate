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

/*	Change the file descriptor
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
static int _sfdup(int fd, int newfd)
#else
static int _sfdup(fd,newfd)
int	fd;
int	newfd;
#endif
{
	reg int	dupfd;

#ifdef F_DUPFD	/* the simple case */
	while((dupfd = sysfcntlf(fd,F_DUPFD,newfd)) < 0 && errno == EINTR)
		errno = 0;
	return dupfd;

#else	/* do it the hard way */
	if((dupfd = sysdupf(fd)) < 0 || dupfd >= newfd)
		return dupfd;

	/* dup() succeeded but didn't get the right number, recurse */
	newfd = _sfdup(fd,newfd);

	/* close the one that didn't match */
	CLOSE(dupfd);

	return newfd;
#endif
}

#if __STD_C
int sfsetfd(Sfio_t* f, int newfd)
#else
int sfsetfd(f,newfd)
Sfio_t	*f;
int	newfd;
#endif
{
	reg int		oldfd;
	SFMTXDECL(f);

	SFMTXENTER(f, -1);

	if(f->flags&SF_STRING)
		SFMTXRETURN(f, -1);

	if((f->mode&SF_INIT) && f->file < 0)
	{	/* restoring file descriptor after a previous freeze */
		if(newfd < 0)
			SFMTXRETURN(f, -1);
	}
	else
	{	/* change file descriptor */
		if((f->mode&SF_RDWR) != f->mode && _sfmode(f,0,0) < 0)
			SFMTXRETURN(f, -1);
		SFLOCK(f,0);

		oldfd = f->file;
		if(oldfd >= 0)
		{	if(newfd >= 0)
			{	if((newfd = _sfdup(oldfd,newfd)) < 0)
				{	SFOPEN(f,0);
					SFMTXRETURN(f, -1);
				}
				CLOSE(oldfd);
			}
			else
			{	/* sync stream if necessary */
				if(((f->mode&SF_WRITE) && f->next > f->data) ||
				   (f->mode&SF_READ) || f->disc == _Sfudisc)
				{	if(SFSYNC(f) < 0)
					{	SFOPEN(f,0);
						SFMTXRETURN(f, -1);
					}
				}

				if(((f->mode&SF_WRITE) && f->next > f->data) ||
				   ((f->mode&SF_READ) && f->extent < 0 &&
				    f->next < f->endb) )
				{	SFOPEN(f,0);
					SFMTXRETURN(f, -1);
				}

#ifdef MAP_TYPE
				if((f->bits&SF_MMAP) && f->data)
				{	SFMUNMAP(f,f->data,f->endb-f->data);
					f->data = NIL(uchar*);
				}
#endif

				/* make stream appears uninitialized */
				f->endb = f->endr = f->endw = f->data;
				f->extent = f->here = 0;
				f->mode = (f->mode&SF_RDWR)|SF_INIT;
				f->bits &= ~SF_NULL;	/* off /dev/null handling */
			}
		}

		SFOPEN(f,0);
	}

	/* notify changes */
	if(_Sfnotify)
		(*_Sfnotify)(f, SF_SETFD, (void*)((long)newfd));

	f->file = newfd;

	SFMTXRETURN(f,newfd);
}
