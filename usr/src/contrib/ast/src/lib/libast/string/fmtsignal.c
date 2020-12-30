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
 * if sig>=0 then return signal text for signal sig
 * otherwise return signal name for signal -sig
 */

#include <ast.h>
#include <sig.h>

char*
fmtsignal(register int sig)
{
	char*	buf;
	int	z;

	if (sig >= 0)
	{
		if (sig <= sig_info.sigmax)
			buf = sig_info.text[sig];
		else
		{
			buf = fmtbuf(z = 20);
			sfsprintf(buf, z, "Signal %d", sig);
		}
	}
	else
	{
		sig = -sig;
		if (sig <= sig_info.sigmax)
			buf = sig_info.name[sig];
		else
		{
			buf = fmtbuf(z = 20);
			sfsprintf(buf, z, "%d", sig);
		}
	}
	return buf;
}
