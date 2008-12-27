/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
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
