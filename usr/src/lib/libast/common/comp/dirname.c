/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
 * dirname(3) implementation
 */

#include <ast_std.h>

#if defined(__EXPORT__)
#define extern	__EXPORT__
#endif

extern char *dirname(register char *pathname)
{
	register char  *last;
	/* go to end of path */
	for(last=pathname; *last; last++);
	/* back over trailing '/' */
	while(last>pathname && *--last=='/');
	/* back over non-slash chars */
	for(;last>pathname && *last!='/';last--);
	if(last==pathname)
	{
		/* all '/' or "" */
		if(*last!='/')
			*last = '.';
		/* preserve // */
		else if(last[1]=='/')
			last++;
	}
	else
	{
		/* back over trailing '/' */
		for(;*last=='/' && last > pathname; last--);
		/* preserve // */
		if(last==pathname && *pathname=='/' && pathname[1]=='/')
			last++;
	}
	*(last + 1) = 0;
	return(pathname);
}
