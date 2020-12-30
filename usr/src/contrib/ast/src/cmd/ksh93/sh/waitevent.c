/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2011 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include	"defs.h"
/*
 *  This installs a hook to allow the processing of events when
 *  the shell is waiting for input and when the shell is
 *  waiting for job completion.
 *  The previous waitevent hook function is returned
 */


void	*sh_waitnotify(int(*newevent)(int,long,int))
{
	int (*old)(int,long,int);
	old = shgd->waitevent;
	shgd->waitevent = newevent;
	return((void*)old);
}

#if __OBSOLETE__ < 20080101
/*
 * this used to be a private symbol
 * retain the old name for a bit for a smooth transition
 */

#if defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern void	*_sh_waitnotify(int(*newevent)(int,long,int))
{
	return sh_waitnotify(newevent);
}

#endif
