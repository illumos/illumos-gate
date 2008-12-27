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
 * common preprocessor line sync handler
 */

#include "pplib.h"

void
ppline(int line, char* file)
{
	char*		s;
	static char	type[5];

	if (pp.flags & PP_lineignore)
	{
		pp.flags &= ~PP_lineignore;
		if (!(pp.flags & PP_linetype) || *pp.lineid)
		{
			ppline(1, file);
			file = error_info.file;
		}
		else
			type[1] = PP_sync_ignore;
	}
	else if (file != pp.lastfile)
	{
		if (!pp.firstfile)
			pp.firstfile = file;
		type[1] = ((pp.flags & PP_linetype) && !*pp.lineid && pp.lastfile) ? (line <= 1 ? (file == pp.firstfile ? PP_sync : PP_sync_push) : PP_sync_pop) : PP_sync;
		pp.lastfile = file;
	}
	else
	{
		if (!(pp.flags & PP_linefile))
			file = 0;
		type[1] = PP_sync;
	}
	if (!(pp.flags & PP_linetype) || *pp.lineid || type[1] == PP_sync)
		type[0] = 0;
	else
	{
		type[0] = ' ';
		if ((pp.flags & (PP_hosted|PP_linehosted)) == (PP_hosted|PP_linehosted))
		{
			type[2] = ' ';
			type[3] = PP_sync_hosted;
		}
		else
			type[2] = 0;
	}

	/*
	 * some front ends can't handle two line syncs in a row
	 */

	if (pp.pending == pppendout() || pplastout() != '\n')
		ppputchar('\n');
	if (file)
		ppprintf("#%s %d \"%s\"%s\n", pp.lineid, line, (pp.flags & PP_linebase) && (s = strrchr(file, '/')) ? s + 1 : file, type);
	else
		ppprintf("#%s %d\n", pp.lineid, line);
	if (!pp.macref)
		pp.pending = pppendout();
}
