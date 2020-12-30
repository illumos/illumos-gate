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

/*	Construct a string with the given format and data.
**	These functions allocate space as necessary to store the string.
**	This avoids overflow problems typical with sprintf() in stdio.
**
**	Written by Kiem-Phong Vo.
*/

#if __STD_C
char* sfvprints(const char* form, va_list args)
#else
char* sfvprints(form, args)
char*	form;
va_list	args;
#endif
{
	reg int		rv;
	Sfnotify_f	notify = _Sfnotify;
	static Sfio_t*	f;

	if(!f) /* make a string stream to write into */
	{	_Sfnotify = 0;
		f = sfnew(NIL(Sfio_t*),NIL(char*),(size_t)SF_UNBOUND, -1,SF_WRITE|SF_STRING);
		_Sfnotify = notify;
		if(!f)
			return NIL(char*);
	}

	sfseek(f,(Sfoff_t)0,SEEK_SET);
	rv = sfvprintf(f,form,args);

	if(rv < 0 || sfputc(f,'\0') < 0)
		return NIL(char*);

	_Sfi = (f->next - f->data) - 1;
	return (char*)f->data;
}

#if __STD_C
char* sfprints(const char* form, ...)
#else
char* sfprints(va_alist)
va_dcl
#endif
{
	char*	s;
	va_list	args;

#if __STD_C
	va_start(args,form);
#else
	char	*form;
	va_start(args);
	form = va_arg(args,char*);
#endif
	s = sfvprints(form, args);
	va_end(args);

	return s;
}

#if __STD_C
ssize_t sfvaprints(char** sp, const char* form, va_list args)
#else
ssize_t sfvaprints(sp, form, args)
char**	sp;
char*	form;
va_list	args;
#endif
{
	char	*s;
	ssize_t	n;

	if(!sp || !(s = sfvprints(form,args)) )
		return -1;
	else
	{	if(!(*sp = (char*)malloc(n = strlen(s)+1)) )
			return -1;
		memcpy(*sp, s, n);
		return n-1;
	}
}

#if __STD_C
ssize_t sfaprints(char** sp, const char* form, ...)
#else
ssize_t sfaprints(va_alist)
va_dcl
#endif
{
	ssize_t	n;
	va_list	args;

#if __STD_C
	va_start(args,form);
#else
	char	**sp, *form;
	va_start(args);
	sp = va_arg(args, char**);
	form = va_arg(args, char*);
#endif
	n = sfvaprints(sp, form, args);
	va_end(args);

	return n;
}
