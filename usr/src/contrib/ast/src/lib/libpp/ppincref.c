/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2011 AT&T Intellectual Property          *
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
 *
 * common include reference handler
 * the type arg is inclusive or of PP_SYNC_*
 */

#include "pplib.h"

void
ppincref(char* parent, char* file, int line, int type)
{
	register struct ppinstk*	sp;
	int				level;

	NoP(parent);
	NoP(line);
	if (type & PP_SYNC_PUSH)
	{
		level = 0;
		for (sp = pp.in; sp; sp = sp->prev)
			if (sp->type == IN_FILE)
				level++;
		if (level > 0)
			level--;
		error(0, "%-*s%s", level * 4, "", file);
	}
}
