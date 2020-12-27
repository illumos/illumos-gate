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
 * local device pathname for portable tape unit specification is returned
 * if e is non-null then it is set to the next unused char in s
 *
 *	<unit><density>[<no-rewind>]
 *	{0-7}[l,m,h,u,c][n]
 */

#include <ast.h>

char*
strtape(register const char* s, register char** e)
{
	int		mtunit = '0';
	int		mtdensity = 0;
	char		mtrewind[2];
	char		mtbehavior[2];

	static char	tapefile[sizeof("/dev/Xrmt/123456789")];

	mtrewind[0] = mtrewind[1] = mtbehavior[0] = mtbehavior[1] = 0;
	for (;;)
	{
		switch (*s)
		{
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			mtunit = *s++;
			continue;
		case 'b':
		case 'v':
			mtbehavior[0] = *s++;
			continue;
		case 'l':
		case 'm':
		case 'h':
		case 'u':
		case 'c':
			mtdensity = *s++;
			continue;
		case 'n':
			mtrewind[0] = *s++;
			continue;
		}
		break;
	}
	if (e) *e = (char*)s;
	if (!access("/dev/rmt/.", F_OK))
	{
		/*
		 * system V
		 */

		if (!mtdensity) mtdensity = 'm';
		sfsprintf(tapefile, sizeof(tapefile), "/dev/rmt/ctape%c%s", mtunit, mtrewind);
		if (!access(tapefile, F_OK)) return(tapefile);
		for (;;)
		{
			sfsprintf(tapefile, sizeof(tapefile), "/dev/rmt/%c%c%s%s", mtunit, mtdensity, mtbehavior, mtrewind);
			if (!access(tapefile, F_OK)) return(tapefile);
			if (!mtbehavior[0]) break;
			mtbehavior[0] = 0;
		}
	}
	else if (!access("/dev/nst0", F_OK))
	{
		/*
		 * linux
		 */

		sfsprintf(tapefile, sizeof(tapefile), "/dev/%sst%c", mtrewind, mtunit);
	}
	else if (!access("/dev/nrmt0", F_OK))
	{
		/*
		 * 9th edition
		 */

		switch (mtdensity)
		{
		case 'l':
			mtunit = '0';
			break;
		case 'm':
			mtunit = '1';
			break;
		case 'h':
			mtunit = '2';
			break;
		}
		sfsprintf(tapefile, sizeof(tapefile), "/dev/%srmt%c", mtrewind, mtunit);
	}
	else
	{
		/*
		 * BSD
		 */

		mtunit -= '0';
		switch (mtdensity)
		{
		case 'l':
			break;
		case 'h':
			mtunit |= 020;
			break;
		default:
			mtunit |= 010;
			break;
		}
		switch (mtrewind[0])
		{
		case 'n':
			mtunit |= 040;
			break;
		}
		sfsprintf(tapefile, sizeof(tapefile), "/dev/rmt%d", mtunit);
	}
	return(tapefile);
}
