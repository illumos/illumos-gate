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
#ifndef _SFIO_T_H
#define _SFIO_T_H	1

/*	This header file is for library writers who need to know certain
**	internal info concerning the full Sfio_t structure. Including this
**	file means that you agree to track closely with sfio development
**	in case its internal architecture is changed.
**
**	Written by Kiem-Phong Vo
*/

/* the parts of Sfio_t private to sfio functions */
#define _SFIO_PRIVATE \
	Sfoff_t			extent;	/* current file	size		*/ \
	Sfoff_t			here;	/* current physical location	*/ \
	unsigned char		unused_1;/* unused #1			*/ \
	unsigned char		tiny[1];/* for unbuffered read stream	*/ \
	unsigned short		bits;	/* private flags		*/ \
	unsigned int		mode;	/* current io mode		*/ \
	struct _sfdisc_s*	disc;	/* discipline			*/ \
	struct _sfpool_s*	pool;	/* the pool containing this	*/ \
	struct _sfrsrv_s*	rsrv;	/* reserved buffer		*/ \
	struct _sfproc_s*	proc;	/* coprocess id, etc.		*/ \
	Void_t*			mutex;	/* mutex for thread-safety	*/ \
	Void_t*			stdio;	/* stdio FILE if any		*/ \
	Sfoff_t			lpos;	/* last seek position		*/ \
	size_t			iosz;	/* preferred size for I/O	*/ \
	size_t			blksz;	/* preferred block size		*/ \
	int			getr;	/* the last sfgetr separator 	*/ \
	_SFIO_PRIVATE_PAD

#if _ast_sizeof_pointer == 8
#define _SFIO_PRIVATE_PAD	int pad;
#else
#define _SFIO_PRIVATE_PAD
#endif

#include	"sfio.h"

/* mode bit to indicate that the structure hasn't been initialized */
#define SF_INIT		0000004
#define SF_DCDOWN	00010000

/* short-hand for common stream types */
#define SF_RDWR		(SF_READ|SF_WRITE)
#define SF_RDSTR	(SF_READ|SF_STRING)
#define SF_WRSTR	(SF_WRITE|SF_STRING)
#define SF_RDWRSTR	(SF_RDWR|SF_STRING)

/* for static initialization of an Sfio_t structure */
#define SFNEW(data,size,file,type,disc,mutex)	\
	{ (unsigned char*)(data),			/* next		*/ \
	  (unsigned char*)(data),			/* endw		*/ \
	  (unsigned char*)(data),			/* endr		*/ \
	  (unsigned char*)(data),			/* endb		*/ \
	  (Sfio_t*)0,					/* push		*/ \
	  (unsigned short)((type)&SF_FLAGS),		/* flags	*/ \
	  (short)(file),				/* file		*/ \
	  (unsigned char*)(data),			/* data		*/ \
	  (ssize_t)(size),				/* size		*/ \
	  (ssize_t)(-1),				/* val		*/ \
	  (Sfoff_t)0,					/* extent	*/ \
	  (Sfoff_t)0,					/* here		*/ \
	  0,						/* getr		*/ \
	  {0},						/* tiny		*/ \
	  0,						/* bits		*/ \
	  (unsigned int)(((type)&(SF_RDWR))|SF_INIT),	/* mode		*/ \
	  (struct _sfdisc_s*)(disc),			/* disc		*/ \
	  (struct _sfpool_s*)0,				/* pool		*/ \
	  (struct _sfrsrv_s*)0,				/* rsrv		*/ \
	  (struct _sfproc_s*)0,				/* proc		*/ \
	  (mutex),					/* mutex	*/ \
	  (Void_t*)0,					/* stdio	*/ \
	  (Sfoff_t)0,					/* lpos		*/ \
	  (size_t)0					/* iosz		*/ \
	}

/* function to clear an Sfio_t structure */
#define SFCLEAR(f,mtx) \
	( (f)->next = (unsigned char*)0,		/* next		*/ \
	  (f)->endw = (unsigned char*)0,		/* endw		*/ \
	  (f)->endr = (unsigned char*)0,		/* endr		*/ \
	  (f)->endb = (unsigned char*)0,		/* endb		*/ \
	  (f)->push = (Sfio_t*)0,			/* push		*/ \
	  (f)->flags = (unsigned short)0,		/* flags	*/ \
	  (f)->file = -1,				/* file		*/ \
	  (f)->data = (unsigned char*)0,		/* data		*/ \
	  (f)->size = (ssize_t)(-1),			/* size		*/ \
	  (f)->val = (ssize_t)(-1),			/* val		*/ \
	  (f)->extent = (Sfoff_t)(-1),			/* extent	*/ \
	  (f)->here = (Sfoff_t)0,			/* here		*/ \
	  (f)->getr = 0,				/* getr		*/ \
	  (f)->tiny[0] = 0,				/* tiny		*/ \
	  (f)->bits = 0,				/* bits		*/ \
	  (f)->mode = 0,				/* mode		*/ \
	  (f)->disc = (struct _sfdisc_s*)0,		/* disc		*/ \
	  (f)->pool = (struct _sfpool_s*)0,		/* pool		*/ \
	  (f)->rsrv = (struct _sfrsrv_s*)0,		/* rsrv		*/ \
	  (f)->proc = (struct _sfproc_s*)0,		/* proc		*/ \
	  (f)->mutex = (mtx),				/* mutex	*/ \
	  (f)->stdio = (Void_t*)0,			/* stdio	*/ \
	  (f)->lpos = (Sfoff_t)0,			/* lpos		*/ \
	  (f)->iosz = (size_t)0				/* iosz		*/ \
	)

/* expose next stream inside discipline function; state saved in int f */
#define SFDCNEXT(sp,f)	(((f)=(sp)->bits&SF_DCDOWN),(sp)->bits|=SF_DCDOWN)

/* restore SFDCNEXT() state from int f */
#define SFDCPREV(sp,f)	((f)?(0):((sp)->bits&=~SF_DCDOWN))

#endif /* _SFIO_T_H */
