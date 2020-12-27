/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1997-2011 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 */

#include "dlllib.h"

Dllstate_t	state;

/*
 * return error message from last failed dl*() call
 * retain==0 resets the last dl*() error
 */

extern char*
dllerror(int retain)
{
	char*	s;

	if (state.error)
	{
		state.error = retain;
		return state.errorbuf;
	}
	s = dlerror();
	if (retain)
	{
		state.error = retain;
		sfsprintf(state.errorbuf, sizeof(state.errorbuf), "%s", s);
	}
	return s;
}
