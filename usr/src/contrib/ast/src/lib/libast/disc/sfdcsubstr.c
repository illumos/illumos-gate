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
#include	"sfdchdr.h"


/*	Discipline to treat a contiguous segment of a stream as a stream
**	in its own right. The hard part in all this is to allow multiple
**	segments of the stream to be used as substreams at the same time.
**
**	Written by David G. Korn and Kiem-Phong Vo (03/18/1998)
*/

typedef struct _subfile_s
{
	Sfdisc_t	disc;	/* sfio discipline */
	Sfio_t*		parent;	/* parent stream */
	Sfoff_t		offset;	/* starting offset */
	Sfoff_t		extent;	/* size wanted */
	Sfoff_t		here;	/* current seek location */
} Subfile_t;

#if __STD_C
static ssize_t streamio(Sfio_t* f, Void_t* buf, size_t n, Sfdisc_t* disc, int type)
#else
static ssize_t streamio(f, buf, n, disc, type)
Sfio_t*		f;
Void_t*		buf;
size_t		n;
Sfdisc_t*	disc;
int		type;
#endif
{
	reg Subfile_t	*su;
	reg Sfoff_t	here, parent;
	reg ssize_t	io;

	su = (Subfile_t*)disc;

	/* read just what we need */
	if(su->extent >= 0 && (ssize_t)n > (io = (ssize_t)(su->extent - su->here)) )
		n = io;
	if(n <= 0)
		return n;

	/* save current location in parent stream */
	parent = sfsk(f,(Sfoff_t)0,SEEK_CUR,disc);

	/* read data */
	here = su->here + su->offset;
	if(sfsk(f,here,SEEK_SET,disc) != here)
		io = 0;
	else
	{	if(type == SF_WRITE) 
			io = sfwr(f,buf,n,disc);
		else	io = sfrd(f,buf,n,disc);
		if(io > 0)
			su->here += io;
	}

	/* restore parent current position */
	sfsk(f,parent,SEEK_SET,disc);

	return io;
}

#if __STD_C
static ssize_t streamwrite(Sfio_t* f, const Void_t* buf, size_t n, Sfdisc_t* disc)
#else
static ssize_t streamwrite(f, buf, n, disc)
Sfio_t*		f;
Void_t*		buf;
size_t		n;
Sfdisc_t*	disc;
#endif
{
	return streamio(f,(Void_t*)buf,n,disc,SF_WRITE);
}

#if __STD_C
static ssize_t streamread(Sfio_t* f, Void_t* buf, size_t n, Sfdisc_t* disc)
#else
static ssize_t streamread(f, buf, n, disc)
Sfio_t*		f;
Void_t*		buf;
size_t		n;
Sfdisc_t*	disc;
#endif
{
	return streamio(f,buf,n,disc,SF_READ);
}

#if __STD_C
static Sfoff_t streamseek(Sfio_t* f, Sfoff_t pos, int type, Sfdisc_t* disc)
#else
static Sfoff_t streamseek(f, pos, type, disc)
Sfio_t*		f;
Sfoff_t		pos;
int		type;
Sfdisc_t*	disc;
#endif
{
	reg Subfile_t*	su;
	reg Sfoff_t	here, parent;

	su = (Subfile_t*)disc;

	switch(type)
	{
	case SEEK_SET:
		here = 0;
		break;
	case SEEK_CUR:
		here = su->here;
		break;
	case SEEK_END:
		if(su->extent >= 0)
			here = su->extent;
		else
		{	parent = sfsk(f,(Sfoff_t)0,SEEK_CUR,disc);
			if((here = sfsk(f,(Sfoff_t)0,SEEK_END,disc)) < 0)
				return -1;
			else	here -= su->offset;
			sfsk(f,parent,SEEK_SET,disc);
		}
		break;
	default:
		return -1;
	}

	pos += here;
	if(pos < 0 || (su->extent >= 0 && pos >= su->extent))
		return -1;

	return (su->here = pos);
}

#if __STD_C
static int streamexcept(Sfio_t* f, int type, Void_t* data, Sfdisc_t* disc)
#else
static int streamexcept(f, type, data, disc)
Sfio_t*		f;
int		type;
Void_t*		data;
Sfdisc_t*	disc;
#endif
{
	if(type == SF_FINAL || type == SF_DPOP)
		free(disc);
	return 0;
}

#if __STD_C
Sfio_t* sfdcsubstream(Sfio_t* f, Sfio_t* parent, Sfoff_t offset, Sfoff_t extent)
#else
Sfio_t* sfdcsubstream(f, parent, offset, extent)
Sfio_t*	f;	/* stream */
Sfio_t*	parent;	/* parent stream */
Sfoff_t	offset;	/* offset in f */
Sfoff_t	extent;	/* desired size */
#endif
{
	reg Sfio_t*	sp;
	reg Subfile_t*	su;
	reg Sfoff_t	here;

	/* establish that we can seek to offset */
	if((here = sfseek(parent,(Sfoff_t)0,SEEK_CUR)) < 0 || sfseek(parent,offset,SEEK_SET) < 0)
		return 0;
	else	sfseek(parent,here,SEEK_SET);
	sfpurge(parent);

	if (!(sp = f) && !(sp = sfnew(NIL(Sfio_t*), NIL(Void_t*), (size_t)SF_UNBOUND, dup(sffileno(parent)), parent->flags)))
		return 0;

	if(!(su = (Subfile_t*)malloc(sizeof(Subfile_t))))
	{	if(sp != f)
			sfclose(sp);
		return 0;
	}
	memset(su, 0, sizeof(*su));

	su->disc.readf = streamread;
	su->disc.writef = streamwrite;
	su->disc.seekf = streamseek;
	su->disc.exceptf = streamexcept;
	su->parent = parent;
	su->offset = offset;
	su->extent = extent;

	if(sfdisc(sp, (Sfdisc_t*)su) != (Sfdisc_t*)su)
	{	free(su);
		if(sp != f)
			sfclose(sp);
		return 0;
	}

	return sp;
}
