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
 * trace systems calls if possible
 */

#include <ast.h>
#include <error.h>
#include <proc.h>
#include <debug.h>

void
systrace(const char* id)
{
	register int	n;
	register char*	out;
	char*		s;
	char		buf[PATH_MAX];
	char*		av[7];
	long		ov[2];

	static char*	trace[] = { "trace", "truss", "strace", "traces" };

	if (!(s = getenv("HOME")))
		return;
	if (!id && !(id = (const char*)error_info.id))
		id = (const char*)trace[0];
	out = buf;
	out += sfsprintf(out, sizeof(buf), "%s/.%s/%s", s, trace[0], id);
	if (access(buf, F_OK))
		return;
	av[1] = trace[0];
	av[2] = "-o";
	av[3] = buf;
	av[4] = "-p";
	av[5] = out + 1;
	av[6] = 0;
	ov[0] = PROC_FD_DUP(open("/dev/null", O_WRONLY), 2, PROC_FD_PARENT|PROC_FD_CHILD);
	ov[1] = 0;
	sfsprintf(out, &buf[sizeof(buf)] - out, ".%d", getpid());
	for (n = 0; n < elementsof(trace); n++)
		if (!procfree(procopen(trace[n], av + 1, NiL, ov, PROC_ARGMOD|PROC_GID|PROC_UID|(n == (elementsof(trace) - 1) ? PROC_CLEANUP : 0))))
		{
			sleep(1);
			break;
		}
}
