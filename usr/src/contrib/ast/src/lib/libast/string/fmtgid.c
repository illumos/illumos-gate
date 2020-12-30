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
 * Glenn Fowler
 * AT&T Bell Laboratories
 *
 * cached gid number -> name
 */

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide getgrgid
#else
#define getgrgid	______getgrgid
#endif

#include <ast.h>
#include <cdt.h>
#include <grp.h>

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide getgrgid
#else
#undef	getgrgid
#endif

extern struct group*	getgrgid(gid_t);

typedef struct Id_s
{
	Dtlink_t	link;
	int		id;
	char		name[1];
} Id_t;

/*
 * return gid name given gid number
 */

char*
fmtgid(int gid)
{
	register Id_t*		ip;
	register char*		name;
	register struct group*	gr;
	int			z;

	static Dt_t*		dict;
	static Dtdisc_t		disc;

	if (!dict)
	{
		disc.key = offsetof(Id_t, id);
		disc.size = sizeof(int);
		dict = dtopen(&disc, Dtset);
	}
	else if (ip = (Id_t*)dtmatch(dict, &gid))
		return ip->name;
	if (gr = getgrgid(gid))
	{
		name = gr->gr_name;
#if _WINIX
		if (streq(name, "Administrators"))
			name = "sys";
#endif
	}
	else if (gid == 0)
		name = "sys";
	else
	{
		name = fmtbuf(z = sizeof(gid) * 3 + 1);
		sfsprintf(name, z, "%I*d", sizeof(gid), gid);
	}
	if (dict && (ip = newof(0, Id_t, 1, strlen(name))))
	{
		ip->id = gid;
		strcpy(ip->name, name);
		dtinsert(dict, ip);
		return ip->name;
	}
	return name;
}
