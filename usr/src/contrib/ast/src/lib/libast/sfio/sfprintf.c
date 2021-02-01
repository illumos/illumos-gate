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
#include	"sfhdr.h"

/*	Print data with a given format
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
int sfprintf(Sfio_t* f, const char* form, ...)
#else
int sfprintf(va_alist)
va_dcl
#endif
{
	va_list	args;
	reg int	rv;

#if __STD_C
	va_start(args,form);
#else
	reg Sfio_t*	f;
	reg char*	form;
	va_start(args);
	f = va_arg(args,Sfio_t*);
	form = va_arg(args,char*);
#endif
	rv = sfvprintf(f,form,args);

	va_end(args);
	return rv;
}

#if __STD_C
ssize_t sfvsprintf(char* s, size_t n, const char* form, va_list args)
#else
ssize_t sfvsprintf(s, n, form, args)
char*	s;
size_t	n;
char*	form;
va_list	args;
#endif
{
	Sfio_t		*f;
	ssize_t		rv;
	Sfnotify_f	notify = _Sfnotify;

	/* make a temp stream */
	_Sfnotify = 0;
	f = sfnew(NIL(Sfio_t*),NIL(char*),(size_t)SF_UNBOUND, -1,SF_WRITE|SF_STRING);
	_Sfnotify = notify;
	if(!f)
		return -1;

	if((rv = sfvprintf(f,form,args)) < 0 )
		return -1;
	if(s && n > 0)
	{	if((rv+1) >= n)
			n--;
		else
			n = rv;
		memcpy(s, f->data, n);
		s[n] = 0;
	}

	sfclose(f);

	_Sfi = rv;

	return rv;
}

#if __STD_C
ssize_t sfsprintf(char* s, size_t n, const char* form, ...)
#else
ssize_t sfsprintf(va_alist)
va_dcl
#endif
{
	va_list	args;
	ssize_t	rv;

#if __STD_C
	va_start(args,form);
#else
	reg char*	s;
	reg size_t	n;
	reg char*	form;
	va_start(args);
	s = va_arg(args,char*);
	n = va_arg(args,size_t);
	form = va_arg(args,char*);
#endif

	rv = sfvsprintf(s,n,form,args);
	va_end(args);

	return rv;
}
