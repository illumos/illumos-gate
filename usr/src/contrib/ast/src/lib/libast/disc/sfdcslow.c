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
#include "sfdchdr.h"

/*	Make a stream op return immediately on interrupts.
**	This is useful on slow streams (hence the name).
**
**	Written by Glenn Fowler (03/18/1998).
*/

#if __STD_C
static int slowexcept(Sfio_t* f, int type, Void_t* v, Sfdisc_t* disc)
#else
static int slowexcept(f, type, v, disc)
Sfio_t*		f;
int		type;
Void_t*		v;
Sfdisc_t*	disc;
#endif
{
	NOTUSED(f);
	NOTUSED(v);
	NOTUSED(disc);

	switch (type)
	{
	case SF_FINAL:
	case SF_DPOP:
		free(disc);
		break;
	case SF_READ:
	case SF_WRITE:
		if (errno == EINTR)
			return(-1);
		break;
	}

	return(0);
}

#if __STD_C
int sfdcslow(Sfio_t* f)
#else
int sfdcslow(f)
Sfio_t*	f;
#endif
{
	Sfdisc_t*	disc;

	if(!(disc = (Sfdisc_t*)malloc(sizeof(Sfdisc_t))) )
		return(-1);

	disc->readf = NIL(Sfread_f);
	disc->writef = NIL(Sfwrite_f);
	disc->seekf = NIL(Sfseek_f);
	disc->exceptf = slowexcept;

	if(sfdisc(f,disc) != disc)
	{	free(disc);
		return(-1);
	}
	sfset(f,SF_IOINTR,1);

	return(0);
}
