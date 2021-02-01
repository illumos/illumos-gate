/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 *   Routines to implement a stack-like storage library
 *   
 *   A stack consists of a link list of variable size frames
 *   The beginning of each frame is initialized with a frame structure
 *   that contains a pointer to the previous frame and a pointer to the
 *   end of the current frame.
 *
 *   This is a rewrite of the stk library that uses sfio
 *
 *   David Korn
 *   AT&T Research
 *   dgk@research.att.com
 *
 */

#include	<sfio_t.h>
#include	<ast.h>
#include	<align.h>
#include	<stk.h>

/*
 *  A stack is a header and a linked list of frames
 *  The first frame has structure
 *	Sfio_t
 *	Sfdisc_t
 *	struct stk
 * Frames have structure
 *	struct frame
 *	data
 */

#define STK_ALIGN	ALIGN_BOUND
#define STK_FSIZE	(1024*sizeof(char*))
#define STK_HDRSIZE	(sizeof(Sfio_t)+sizeof(Sfdisc_t))

typedef char* (*_stk_overflow_)(int);

static int stkexcept(Sfio_t*,int,void*,Sfdisc_t*);
static Sfdisc_t stkdisc = { 0, 0, 0, stkexcept };

Sfio_t _Stak_data = SFNEW((char*)0,0,-1,SF_STATIC|SF_WRITE|SF_STRING,&stkdisc,0);

__EXTERN__(Sfio_t, _Stak_data);

struct frame
{
	char	*prev;		/* address of previous frame */
	char	*end;		/* address of end this frame */
	char	**aliases;	/* address aliases */
	int	nalias;		/* number of aliases */
};

struct stk
{
	_stk_overflow_	stkoverflow;	/* called when malloc fails */
	short		stkref;	/* reference count; */
	short		stkflags;	/* stack attributes */
	char		*stkbase;	/* beginning of current stack frame */
	char		*stkend;	/* end of current stack frame */
};

static size_t		init;		/* 1 when initialized */
static struct stk	*stkcur;	/* pointer to current stk */
static char		*stkgrow(Sfio_t*, size_t);

#define stream2stk(stream)	((stream)==stkstd? stkcur:\
				 ((struct stk*)(((char*)(stream))+STK_HDRSIZE)))
#define stk2stream(sp)		((Sfio_t*)(((char*)(sp))-STK_HDRSIZE))
#define stkleft(stream)		((stream)->_endb-(stream)->_data)
	

#ifdef STKSTATS
    static struct
    {
	int	create;
	int	delete;
	int	install;
	int	alloc;
	int	copy;
	int	puts;
	int	seek;
	int	set;
	int	grow;
	int	addsize;
	int	delsize;
	int	movsize;
    } _stkstats;
#   define increment(x)	(_stkstats.x++)
#   define count(x,n)	(_stkstats.x += (n))
#else
#   define increment(x)
#   define count(x,n)
#endif /* STKSTATS */

static const char Omsg[] = "malloc failed while growing stack\n";

/*
 * default overflow exception
 */
static char *overflow(int n)
{
	NoP(n);
	write(2,Omsg, sizeof(Omsg)-1);
	exit(2);
	/* NOTREACHED */
	return(0);
}

/*
 * initialize stkstd, sfio operations may have already occcured
 */
static void stkinit(size_t size)
{
	register Sfio_t *sp;
	init = size;
	sp = stkopen(0);
	init = 1;
	stkinstall(sp,overflow);
}

static int stkexcept(register Sfio_t *stream, int type, void* val, Sfdisc_t* dp)
{
	NoP(dp);
	NoP(val);
	switch(type)
	{
	    case SF_CLOSING:
		{
			register struct stk *sp = stream2stk(stream); 
			register char *cp = sp->stkbase;
			register struct frame *fp;
			if(--sp->stkref<=0)
			{
				increment(delete);
				if(stream==stkstd)
					stkset(stream,(char*)0,0);
				else
				{
					while(1)
					{
						fp = (struct frame*)cp;
						if(fp->prev)
						{
							cp = fp->prev;
							free(fp);
						}
						else
						{
							free(fp);
							break;
						}
					}
				}
			}
			stream->_data = stream->_next = 0;
		}
		return(0);
	    case SF_FINAL:
		free(stream);
		return(1);
	    case SF_DPOP:
		return(-1);
	    case SF_WRITE:
	    case SF_SEEK:
		{
			long size = sfvalue(stream);
			if(init)
			{
				Sfio_t *old = 0;
				if(stream!=stkstd)
					old = stkinstall(stream,NiL);
				if(!stkgrow(stkstd,size-(stkstd->_endb-stkstd->_data)))
					return(-1);
				if(old)
					stkinstall(old,NiL);
			}
			else
				stkinit(size);
		}
		return(1);
	    case SF_NEW:
		return(-1);
	}
	return(0);
}

/*
 * create a stack
 */
Sfio_t *stkopen(int flags)
{
	register size_t bsize;
	register Sfio_t *stream;
	register struct stk *sp;
	register struct frame *fp;
	register Sfdisc_t *dp;
	register char *cp;
	if(!(stream=newof((char*)0,Sfio_t, 1, sizeof(*dp)+sizeof(*sp))))
		return(0);
	increment(create);
	count(addsize,sizeof(*stream)+sizeof(*dp)+sizeof(*sp));
	dp = (Sfdisc_t*)(stream+1);
	dp->exceptf = stkexcept;
	sp = (struct stk*)(dp+1);
	sp->stkref = 1;
	sp->stkflags = (flags&STK_SMALL);
	if(flags&STK_NULL) sp->stkoverflow = 0;
	else sp->stkoverflow = stkcur?stkcur->stkoverflow:overflow;
	bsize = init+sizeof(struct frame);
#ifndef USE_REALLOC
	if(flags&STK_SMALL)
		bsize = roundof(bsize,STK_FSIZE/16);
	else
#endif /* USE_REALLOC */
		bsize = roundof(bsize,STK_FSIZE);
	bsize -= sizeof(struct frame);
	if(!(fp=newof((char*)0,struct frame, 1,bsize)))
	{
		free(stream);
		return(0);
	}
	count(addsize,sizeof(*fp)+bsize);
	cp = (char*)(fp+1);
	sp->stkbase = (char*)fp;
	fp->prev = 0;
	fp->nalias = 0;
	fp->aliases = 0;
	fp->end = sp->stkend = cp+bsize;
	if(!sfnew(stream,cp,bsize,-1,SF_STRING|SF_WRITE|SF_STATIC|SF_EOF))
		return((Sfio_t*)0);
	sfdisc(stream,dp);
	return(stream);
}

/*
 * return a pointer to the current stack
 * if <stream> is not null, it becomes the new current stack
 * <oflow> becomes the new overflow function
 */
Sfio_t *stkinstall(Sfio_t *stream, _stk_overflow_ oflow)
{
	Sfio_t *old;
	register struct stk *sp;
	if(!init)
	{
		stkinit(1);
		if(oflow)
			stkcur->stkoverflow = oflow;
		return((Sfio_t*)0);
	}
	increment(install);
	old = stkcur?stk2stream(stkcur):0;
	if(stream)
	{
		sp = stream2stk(stream);
		while(sfstack(stkstd, SF_POPSTACK));
		if(stream!=stkstd)
			sfstack(stkstd,stream);
		stkcur = sp;
#ifdef USE_REALLOC
		/*** someday ***/
#endif /* USE_REALLOC */
	}
	else
		sp = stkcur;
	if(oflow)
		sp->stkoverflow = oflow;
	return(old);
}

/*
 * increase the reference count on the given <stack>
 */
int stklink(register Sfio_t* stream)
{
	register struct stk *sp = stream2stk(stream);
	return(sp->stkref++);
}

/*
 * terminate a stack and free up the space
 * >0 returned if reference decremented but still > 0
 *  0 returned on last close
 * <0 returned on error
 */
int stkclose(Sfio_t* stream)
{
	register struct stk *sp = stream2stk(stream); 
	if(sp->stkref>1)
	{
		sp->stkref--;
		return(1);
	}
	return(sfclose(stream));
}

/*
 * returns 1 if <loc> is on this stack
 */
int stkon(register Sfio_t * stream, register char* loc)
{
	register struct stk *sp = stream2stk(stream); 
	register struct frame *fp;
	for(fp=(struct frame*)sp->stkbase; fp; fp=(struct frame*)fp->prev)
		if(loc>=((char*)(fp+1)) && loc< fp->end)
			return(1);
	return(0);
}
/*
 * reset the bottom of the current stack back to <loc>
 * if <loc> is not in this stack, then the stack is reset to the beginning
 * otherwise, the top of the stack is set to stkbot+<offset>
 *
 */
char *stkset(register Sfio_t * stream, register char* loc, size_t offset)
{
	register struct stk *sp = stream2stk(stream); 
	register char *cp;
	register struct frame *fp;
	register int frames = 0;
	int n;
	if(!init)
		stkinit(offset+1);
	increment(set);
	while(1)
	{
		fp = (struct frame*)sp->stkbase;
		cp = sp->stkbase + roundof(sizeof(struct frame), STK_ALIGN);
		n = fp->nalias;
		while(n-->0)
		{
			if(loc==fp->aliases[n])
			{
				loc = cp;
				break;
			}
		}
		/* see whether <loc> is in current stack frame */
		if(loc>=cp && loc<=sp->stkend)
		{
			if(frames)
				sfsetbuf(stream,cp,sp->stkend-cp);
			stream->_data = (unsigned char*)(cp + roundof(loc-cp,STK_ALIGN));
			stream->_next = (unsigned char*)loc+offset;
			goto found;
		}
		if(fp->prev)
		{
			sp->stkbase = fp->prev;
			sp->stkend = ((struct frame*)(fp->prev))->end;
			free((void*)fp);
		}
		else
			break;
		frames++;
	}
	/* set stack back to the beginning */
	cp = (char*)(fp+1);
	if(frames)
		sfsetbuf(stream,cp,sp->stkend-cp);
	else
		stream->_data = stream->_next = (unsigned char*)cp;
found:
	return((char*)stream->_data);
}

/*
 * allocate <n> bytes on the current stack
 */
char *stkalloc(register Sfio_t *stream, register size_t n)
{
	register unsigned char *old;
	if(!init)
		stkinit(n);
	increment(alloc);
	n = roundof(n,STK_ALIGN);
	if(stkleft(stream) <= (int)n && !stkgrow(stream,n))
		return(0);
	old = stream->_data;
	stream->_data = stream->_next = old+n;
	return((char*)old);
}

/*
 * begin a new stack word of at least <n> bytes
 */
char *_stkseek(register Sfio_t *stream, register ssize_t n)
{
	if(!init)
		stkinit(n);
	increment(seek);
	if(stkleft(stream) <= n && !stkgrow(stream,n))
		return(0);
	stream->_next = stream->_data+n;
	return((char*)stream->_data);
}

/*
 * advance the stack to the current top
 * if extra is non-zero, first add a extra bytes and zero the first
 */
char	*stkfreeze(register Sfio_t *stream, register size_t extra)
{
	register unsigned char *old, *top;
	if(!init)
		stkinit(extra);
	old = stream->_data;
	top = stream->_next;
	if(extra)
	{
		if(extra > (stream->_endb-stream->_next))
		{
			if (!(top = (unsigned char*)stkgrow(stream,extra)))
				return(0);
			old = stream->_data;
		}
		*top = 0;
		top += extra;
	}
	stream->_next = stream->_data += roundof(top-old,STK_ALIGN);
	return((char*)old);
}

/*
 * copy string <str> onto the stack as a new stack word
 */
char	*stkcopy(Sfio_t *stream, const char* str)
{
	register unsigned char *cp = (unsigned char*)str;
	register size_t n;
	register int off=stktell(stream);
	char buff[40], *tp=buff;
	if(off)
	{
		if(off > sizeof(buff))
		{
			if(!(tp = malloc(off)))
			{
				struct stk *sp = stream2stk(stream);
				if(!sp->stkoverflow || !(tp = (*sp->stkoverflow)(off)))
					return(0);
			}
		}
		memcpy(tp, stream->_data, off);
	}
	while(*cp++);
	n = roundof(cp-(unsigned char*)str,STK_ALIGN);
	if(!init)
		stkinit(n);
	increment(copy);
	if(stkleft(stream) <= n && !stkgrow(stream,n))
		cp = 0;
	else
	{
		strcpy((char*)(cp=stream->_data),str);
		stream->_data = stream->_next = cp+n;
		if(off)
		{
			_stkseek(stream,off);
			memcpy(stream->_data, tp, off);
		}
	}
	if(tp!=buff)
		free((void*)tp);
	return((char*)cp);
}

/*
 * add a new stack frame of size >= <n> to the current stack.
 * if <n> > 0, copy the bytes from stkbot to stktop to the new stack
 * if <n> is zero, then copy the remainder of the stack frame from stkbot
 * to the end is copied into the new stack frame
 */

static char *stkgrow(register Sfio_t *stream, size_t size)
{
	register size_t n = size;
	register struct stk *sp = stream2stk(stream);
	register struct frame *fp= (struct frame*)sp->stkbase;
	register char *cp, *dp=0;
	register size_t m = stktell(stream);
	size_t endoff;
	char *end=0;
	int nn=0,add=1;
	n += (m + sizeof(struct frame)+1);
	if(sp->stkflags&STK_SMALL)
#ifndef USE_REALLOC
		n = roundof(n,STK_FSIZE/16);
	else
#endif /* !USE_REALLOC */
		n = roundof(n,STK_FSIZE);
	/* see whether current frame can be extended */
	if(stkptr(stream,0)==sp->stkbase+sizeof(struct frame))
	{
		nn = fp->nalias+1;
		dp=sp->stkbase;
		sp->stkbase = ((struct frame*)dp)->prev;
		end = fp->end;
	}
	endoff = end - dp;
	cp = newof(dp, char, n, nn*sizeof(char*));
	if(!cp && (!sp->stkoverflow || !(cp = (*sp->stkoverflow)(n))))
		return(0);
	increment(grow);
	count(addsize,n - (dp?m:0));
	if(dp==cp)
	{
		nn--;
		add = 0;
	}
	else if(dp)
	{
		dp = cp;
		end = dp + endoff;
	}
	fp = (struct frame*)cp;
	fp->prev = sp->stkbase;
	sp->stkbase = cp;
	sp->stkend = fp->end = cp+n;
	cp = (char*)(fp+1);
	cp = sp->stkbase + roundof((cp-sp->stkbase),STK_ALIGN);
	if(fp->nalias=nn)
	{
		fp->aliases = (char**)fp->end;
		if(end && nn>1)
			memmove(fp->aliases,end,(nn-1)*sizeof(char*));
		if(add)
			fp->aliases[nn-1] = dp + roundof(sizeof(struct frame),STK_ALIGN);
	}
	if(m && !dp)
	{
		memcpy(cp,(char*)stream->_data,m);
		count(movsize,m);
	}
	sfsetbuf(stream,cp,sp->stkend-cp);
	return((char*)(stream->_next = stream->_data+m));
}
