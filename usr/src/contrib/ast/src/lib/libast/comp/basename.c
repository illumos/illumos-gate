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
#pragma prototyped
/*
 * basename(3) implementation
 */

#include <ast_std.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern char *basename(register char *pathname)
{
	register char *first, *last;
	for(first=last=pathname; *last; last++);
	/* back over trailing '/' */
	if(last>first)
		while(*--last=='/' && last > first);
	if(last==first && *last=='/')
	{
		/* all '/' or "" */
		if(*first=='/')
			if(*++last=='/')	/* keep leading // */
				last++;
	}
	else
	{
		for(first=last++;first>pathname && *first!='/';first--);
		if(*first=='/')
			first++;
	}
	*last = 0;
	return(first);
}
