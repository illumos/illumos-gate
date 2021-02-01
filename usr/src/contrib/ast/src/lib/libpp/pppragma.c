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
 * common preprocessor pragma handler
 */

#include "pplib.h"

void
pppragma(char* directive, char* pass, char* name, char* value, int newline)
{
	register int	sep = 0;

	ppsync();
	if (directive)
	{
		ppprintf("#%s", directive);
		sep = 1;
	}
	if (pass)
	{
		if (sep)
		{
			sep = 0;
			ppprintf(" ");
		}
		ppprintf("%s:", pass);
	}
	if (name)
	{
		if (sep)
			ppprintf(" ");
		else
			sep = 1;
		ppprintf("%s", name);
	}
	if (value)
	{
		if (sep || pass)
			ppprintf(" ");
		ppprintf("%s", value);
	}
	if (newline)
		ppprintf("\n");
}
