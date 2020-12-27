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
#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide getpagesize
#else
#define getpagesize	______getpagesize
#endif

#include	"sfhdr.h"

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide getpagesize
#else
#undef	getpagesize
#endif

#if _lib_getpagesize
_BEGIN_EXTERNS_
extern int	getpagesize _ARG_((void));
_END_EXTERNS_
#endif

/*	Set a (new) buffer for a stream.
**	If size < 0, it is assigned a suitable value depending on the
**	kind of stream. The actual buffer size allocated is dependent
**	on how much memory is available.
**
**	Written by Kiem-Phong Vo.
*/

#if !_sys_stat
struct stat
{	int	st_mode;
	int	st_size;
};
#undef sysfstatf
#define sysfstatf(fd,st)	(-1)
#endif /*_sys_stat*/

#if _PACKAGE_ast && !defined(SFSETLINEMODE)
#define SFSETLINEMODE		1
#endif

#if SFSETLINEMODE

static int sfsetlinemode()
{	char*			astsfio;
	char*			endw;

	static int		modes = -1;
	static const char	sf_line[] = "SF_LINE";
	static const char	sf_maxr[] = "SF_MAXR=";
	static const char	sf_wcwidth[] = "SF_WCWIDTH";

#define ISSEPAR(c)	((c) == ',' || (c) == ' ' || (c) == '\t')
	if (modes < 0)
	{	modes = 0;
		if(astsfio = getenv("SFIO_OPTIONS"))
		{	for(; *astsfio != 0; astsfio = endw)
			{	while(ISSEPAR(*astsfio) )
					++astsfio;
				for(endw = astsfio; *endw && !ISSEPAR(*endw); ++endw)
					;
				if((endw-astsfio) > (sizeof(sf_line)-1) &&
				   strncmp(astsfio,sf_line,sizeof(sf_line)-1) == 0)
					modes |= SF_LINE;
				else if((endw-astsfio) > (sizeof(sf_maxr)-1) &&
				   strncmp(astsfio,sf_maxr,sizeof(sf_maxr)-1) == 0)
#if _PACKAGE_ast
					_Sfmaxr = (ssize_t)strtonll(astsfio+sizeof(sf_maxr)-1,NiL,NiL,0);
#else
					_Sfmaxr = (ssize_t)strtol(astsfio+sizeof(sf_maxr)-1,NiL,0);
#endif
				else if((endw-astsfio) > (sizeof(sf_wcwidth)-1) &&
				   strncmp(astsfio,sf_wcwidth,sizeof(sf_wcwidth)-1) == 0)
					modes |= SF_WCWIDTH;
			}
		}
	}
	return modes;
}

#endif

#if __STD_C
Void_t* sfsetbuf(Sfio_t* f, Void_t* buf, size_t size)
#else
Void_t* sfsetbuf(f,buf,size)
Sfio_t*	f;	/* stream to be buffered */
Void_t*	buf;	/* new buffer */
size_t	size;	/* buffer size, -1 for default size */
#endif
{
	int		sf_malloc, oflags, init, okmmap, local;
	ssize_t		bufsize, blksz;
	Sfdisc_t*	disc;
	sfstat_t	st;
	uchar*		obuf = NIL(uchar*);
	ssize_t		osize = 0;
	SFMTXDECL(f);

	SFONCE();

	SFMTXENTER(f,NIL(Void_t*));

	GETLOCAL(f,local);

	if(size == 0 && buf)
	{	/* special case to get buffer info */
		_Sfi = f->val = (f->bits&SF_MMAP) ? (f->endb-f->data) : f->size;
		SFMTXRETURN(f, (Void_t*)f->data);
	}

	/* cleanup actions already done, don't allow write buffering any more */
	if(_Sfexiting && !(f->flags&SF_STRING) && (f->mode&SF_WRITE))
	{	buf = NIL(Void_t*);
		size = 0;
	}

	if((init = f->mode&SF_INIT) )
	{	if(!f->pool && _sfsetpool(f) < 0)
			SFMTXRETURN(f, NIL(Void_t*));
	}
	else if((f->mode&SF_RDWR) != SFMODE(f,local) && _sfmode(f,0,local) < 0)
		SFMTXRETURN(f, NIL(Void_t*));

	if(init)
		f->mode = (f->mode&SF_RDWR)|SF_LOCK;
	else
	{	int	rv;

		/* make sure there is no hidden read data */
		if(f->proc && (f->flags&SF_READ) && (f->mode&SF_WRITE) &&
		   _sfmode(f,SF_READ,local) < 0)
			SFMTXRETURN(f, NIL(Void_t*));

		/* synchronize first */
		SFLOCK(f,local); rv = SFSYNC(f); SFOPEN(f,local);
		if(rv < 0)
			SFMTXRETURN(f, NIL(Void_t*));

		/* turn off the SF_SYNCED bit because buffer is changing */
		f->mode &= ~SF_SYNCED;
	}

	SFLOCK(f,local);

	if((Sfio_t*)buf != f)
		blksz = -1;
	else /* setting alignment size only */
	{	blksz = (ssize_t)size;

		if(!init) /* stream already initialized */
		{	obuf = f->data;
			osize = f->size;
			goto done;
		}
		else /* initialize stream as if in the default case */
		{	buf = NIL(Void_t*);
			size = (size_t)SF_UNBOUND;
		}
	}

	bufsize = 0;
	oflags = f->flags;

	/* see if memory mapping is possible (see sfwrite for SF_BOTH) */
	okmmap = (buf || (f->flags&SF_STRING) || (f->flags&SF_RDWR) == SF_RDWR) ? 0 : 1;

	/* save old buffer info */
#ifdef MAP_TYPE
	if(f->bits&SF_MMAP)
	{	if(f->data)
		{	SFMUNMAP(f,f->data,f->endb-f->data);
			f->data = NIL(uchar*);
		}
	} else
#endif
	if(f->data == f->tiny)
	{	f->data = NIL(uchar*);
		f->size = 0;
	}
	obuf  = f->data;
	osize = f->size;

	f->flags &= ~SF_MALLOC;
	f->bits  &= ~SF_MMAP;

	/* pure read/string streams must have a valid string */
	if((f->flags&(SF_RDWR|SF_STRING)) == SF_RDSTR &&
	   (size == (size_t)SF_UNBOUND || !buf))
		size = 0;

	/* set disc to the first discipline with a seekf */
	for(disc = f->disc; disc; disc = disc->disc)
		if(disc->seekf)
			break;

	if((init || local) && !(f->flags&SF_STRING))
	{	/* ASSERT(f->file >= 0) */
		st.st_mode = 0;

		/* if has discipline, set size by discipline if possible */
		if(!_sys_stat || disc)
		{	if((f->here = SFSK(f,(Sfoff_t)0,SEEK_CUR,disc)) < 0)
				goto unseekable;
			else
			{	Sfoff_t	e;
				if((e = SFSK(f,(Sfoff_t)0,SEEK_END,disc)) >= 0)
					f->extent = e > f->here ? e : f->here;
				(void)SFSK(f,f->here,SEEK_SET,disc);
				goto setbuf;
			}
		}

		/* get file descriptor status */
		if(sysfstatf((int)f->file,&st) < 0)
			f->here = -1;
		else
		{
#if _sys_stat && _stat_blksize	/* preferred io block size */
			f->blksz = (size_t)st.st_blksize;
#endif
			bufsize = 64 * 1024;
			if(S_ISDIR(st.st_mode) || (Sfoff_t)st.st_size < (Sfoff_t)SF_GRAIN)
				okmmap = 0;
			if(S_ISREG(st.st_mode) || S_ISDIR(st.st_mode))
				f->here = SFSK(f,(Sfoff_t)0,SEEK_CUR,f->disc);
			else	f->here = -1;

#if O_TEXT /* no memory mapping with O_TEXT because read()/write() alter data stream */
			if(okmmap && f->here >= 0 &&
			   (sysfcntlf((int)f->file,F_GETFL,0) & O_TEXT) )
				okmmap = 0;
#endif
		}

#if SFSETLINEMODE
		if(init)
			f->flags |= sfsetlinemode();
#endif

		if(f->here >= 0)
		{	f->extent = (Sfoff_t)st.st_size;

			/* seekable std-devices are share-public by default */
			if(f == sfstdin || f == sfstdout || f == sfstderr)
				f->flags |= SF_SHARE|SF_PUBLIC;
		}
		else
		{
		unseekable:
			f->extent = -1;
			f->here = 0;

			if(init)
			{	if(S_ISCHR(st.st_mode) )
				{	int oerrno = errno;

					bufsize = SF_GRAIN;

					/* set line mode for terminals */
					if(!(f->flags&(SF_LINE|SF_WCWIDTH)) && isatty(f->file))
						f->flags |= SF_LINE|SF_WCWIDTH;
#if _sys_stat
					else	/* special case /dev/null */
					{	reg int	dev, ino;
						static int null_checked, null_dev, null_ino;
						dev = (int)st.st_dev;	
						ino = (int)st.st_ino;	
						if(!null_checked)
						{	if(sysstatf(DEVNULL,&st) < 0)
								null_checked = -1;
							else
							{	null_checked = 1;
								null_dev = (int)st.st_dev;	
								null_ino = (int)st.st_ino;	
							}
						}
						if(null_checked >= 0 && dev == null_dev && ino == null_ino)
							SFSETNULL(f);
					}
#endif
					errno = oerrno;
				}

				/* initialize side buffer for r+w unseekable streams */
				if(!f->proc && (f->bits&SF_BOTH) )
					(void)_sfpopen(f,-1,-1,1);
			}
		}

		/* set page size, this is also the desired default buffer size */
		if(_Sfpage <= 0)
		{
#if _lib_getpagesize
			if((_Sfpage = (size_t)getpagesize()) <= 0)
#endif
				_Sfpage = SF_PAGE;
		}
	}

#ifdef MAP_TYPE
	if(okmmap && size && (f->mode&SF_READ) && f->extent >= 0 )
	{	/* see if we can try memory mapping */
		if(!disc)
			for(disc = f->disc; disc; disc = disc->disc)
				if(disc->readf)
					break;
		if(!disc)
		{	f->bits |= SF_MMAP;
			if(size == (size_t)SF_UNBOUND)
			{	if(bufsize > _Sfpage)
					size = bufsize * SF_NMAP;
				else	size = _Sfpage * SF_NMAP;
				if(size > 256*1024)
					size = 256*1024;
			}
		}
	}
#endif

	/* get buffer space */
setbuf:
	if(size == (size_t)SF_UNBOUND)
	{	/* define a default size suitable for block transfer */
		if(init && osize > 0)
			size = osize;
		else if(f == sfstderr && (f->mode&SF_WRITE))
			size = 0;
		else if(f->flags&SF_STRING )
			size = SF_GRAIN;
		else if((f->flags&SF_READ) && !(f->bits&SF_BOTH) &&
			f->extent > 0 && f->extent < (Sfoff_t)_Sfpage )
			size = (((size_t)f->extent + SF_GRAIN-1)/SF_GRAIN)*SF_GRAIN;
		else if((ssize_t)(size = _Sfpage) < bufsize)
			size = bufsize;

		buf = NIL(Void_t*);
	}

	sf_malloc = 0;
	if(size > 0 && !buf && !(f->bits&SF_MMAP))
	{	/* try to allocate a buffer */
		if(obuf && size == (size_t)osize && init)
		{	buf = (Void_t*)obuf;
			obuf = NIL(uchar*);
			sf_malloc = (oflags&SF_MALLOC);
		}
		if(!buf)
		{	/* do allocation */
			while(!buf && size > 0)
			{	if((buf = (Void_t*)malloc(size)) )
					break;
				else	size /= 2;
			}
			if(size > 0)
				sf_malloc = SF_MALLOC;
		}
	}

	if(size == 0 && !(f->flags&SF_STRING) && !(f->bits&SF_MMAP) && (f->mode&SF_READ))
	{	/* use the internal buffer */
		size = sizeof(f->tiny);
		buf = (Void_t*)f->tiny;
	}

	/* set up new buffer */
	f->size = size;
	f->next = f->data = f->endr = f->endw = (uchar*)buf;
	f->endb = (f->mode&SF_READ) ? f->data : f->data+size;
	if(f->flags&SF_STRING)
	{	/* these fields are used to test actual size - see sfseek() */
		f->extent = (!sf_malloc &&
			     ((f->flags&SF_READ) || (f->bits&SF_BOTH)) ) ? size : 0;
		f->here = 0;

		/* read+string stream should have all data available */
		if((f->mode&SF_READ) && !sf_malloc)
			f->endb = f->data+size;
	}

	f->flags = (f->flags & ~SF_MALLOC)|sf_malloc;

	if(obuf && obuf != f->data && osize > 0 && (oflags&SF_MALLOC))
	{	free((Void_t*)obuf);
		obuf = NIL(uchar*);
	}

done:
	_Sfi = f->val = obuf ? osize : 0;

	/* blksz is used for aligning disk block boundary while reading data to
	** optimize data transfer from disk (eg, via direct I/O). blksz can be
	** at most f->size/2 so that data movement in buffer can be optimized.
	** blksz should also be a power-of-2 for optimal disk seeks.
	*/
	if(blksz <= 0 || (blksz & (blksz-1)) != 0 )
		blksz = SF_GRAIN;
	while(blksz > f->size/2)
		blksz /= 2;
	f->blksz = blksz;

	SFOPEN(f,local);

	SFMTXRETURN(f, (Void_t*)obuf);
}
