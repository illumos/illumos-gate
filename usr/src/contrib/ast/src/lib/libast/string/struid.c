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
 * uid name -> number
 */

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:hide getpwnam getpwuid
#else
#define getpwnam	______getpwnam
#define getpwuid	______getpwuid
#endif

#include <ast.h>
#include <cdt.h>
#include <pwd.h>

#if defined(__STDPP__directive) && defined(__STDPP__hide)
__STDPP__directive pragma pp:nohide getpwnam getpwuid
#else
#undef	getpwnam
#undef	getpwuid
#endif

extern struct passwd*	getpwnam(const char*);
extern struct passwd*	getpwuid(uid_t);

typedef struct Id_s
{
	Dtlink_t	link;
	int		id;
	char		name[1];
} Id_t;

/*
 * return uid number given uid name
 * -1 on first error for a given name
 * -2 on subsequent errors for a given name
 */

int
struid(const char* name)
{
	register Id_t*		ip;
	register struct passwd*	pw;
	int			id;
	char*			e;

	static Dt_t*		dict;
	static Dtdisc_t		disc;

	if (!dict)
	{
		disc.key = offsetof(Id_t, name);
		dict = dtopen(&disc, Dtset);
	}
	else if (ip = (Id_t*)dtmatch(dict, name))
		return ip->id;
	if (pw = getpwnam(name))
		id = pw->pw_uid;
	else
	{
		id = strtol(name, &e, 0);
#if _WINIX
		if (!*e)
		{
			if (!getpwuid(id))
				id = -1;
		}
		else if (streq(name, "root") && (pw = getpwnam("Administrator")))
			id = pw->pw_uid;
		else
			id = -1;
#else
		if (*e || !getpwuid(id))
			id = -1;
#endif
	}
	if (dict && (ip = newof(0, Id_t, 1, strlen(name))))
	{
		strcpy(ip->name, name);
		ip->id = id >= 0 ? id : -2;
		dtinsert(dict, ip);
	}
	return id;
}
