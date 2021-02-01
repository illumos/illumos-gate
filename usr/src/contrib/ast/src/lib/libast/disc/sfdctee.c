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

/*	A discipline to tee the output to a stream to another stream.
**	This is similar to what the "tee" program does. As implemented
**	this discipline only works with file streams.
**
**	Written by Kiem-Phong Vo, kpv@research.att.com, 03/18/1998.
*/

/* the discipline structure for tee-ing */
typedef struct _tee_s
{	Sfdisc_t	disc;	/* the sfio discipline structure */
	Sfio_t*		tee;	/* the stream to tee to */
	int		status;	/* if tee stream is still ok */
} Tee_t;

/*	write to the teed stream.  */
#if __STD_C
static ssize_t teewrite(Sfio_t* f, const Void_t* buf, size_t size, Sfdisc_t* disc)
#else
static ssize_t teewrite(f,buf,size,disc)
Sfio_t* 	f;	/* the stream being written to */
Void_t*		buf;	/* the buffer of data being output */
size_t		size;	/* the data size */
Sfdisc_t*	disc;	/* the tee discipline */
#endif
{
	reg Tee_t*	te = (Tee_t*)disc;

	/* tee data if still ok */
	if(te->status == 0 && sfwrite(te->tee,buf,size) != (ssize_t)size)
		te->status = -1;

	/* do the actual write */
	return sfwr(f,buf,size,disc);
}

/* on close, remove the discipline */
#if __STD_C
static int teeexcept(Sfio_t* f, int type, Void_t* data, Sfdisc_t* disc)
#else
static int teeexcept(f,type,data,disc)
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
int sfdctee(Sfio_t* f, Sfio_t* tee)
#else
int sfdctee(f, tee)
Sfio_t*	f;	/* stream to tee from	*/
Sfio_t*	tee;	/* stream to tee to	*/
#endif
{
	reg Tee_t*	te;

	if(!(te = (Tee_t*)malloc(sizeof(Tee_t))) )
		return -1;

	te->disc.readf = NIL(Sfread_f);
	te->disc.seekf = NIL(Sfseek_f);
	te->disc.writef = teewrite;
	te->disc.exceptf = teeexcept;
	te->tee = tee;
	te->status = 0;

	if(sfdisc(f,(Sfdisc_t*)te) != (Sfdisc_t*)te)
	{	free(te);
		return -1;
	}

	return 0;
}
