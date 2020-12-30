/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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
 * regex collation symbol support
 */

#include "reglib.h"

/*
 * return the collating symbol delimited by [c c], where c is either '=' or '.'
 * s points to the first char after the initial [
 * if e!=0 it is set to point to the next char in s on return
 *
 * the collating symbol is converted to multibyte in <buf,size>
 * the return value is:
 *	-1	syntax error / invalid collating element
 *	>=0	size with 0-terminated mb character (*wc != 0)
 *		or collating element (*wc == 0) in buf
 */

int
regcollate(register const char* s, char** e, char* buf, size_t size, wchar_t* wc)
{
	register int			c;
	register char*			b;
	register char*			x;
	const char*			t;
	int				i;
	int				r;
	int				term;
	wchar_t				w;
	char				xfm[256];
	char				tmp[sizeof(xfm)];

	if (size < 2 || (term = *s) != '.' && term != '=' || !*++s || *s == term && *(s + 1) == ']')
		goto nope;
	t = s;
	w = mbchar(s);
	if ((r = (s - t)) > 1)
	{
		if (*s++ != term || *s++ != ']')
			goto oops;
		goto done;
	}
	if (*s == term && *(s + 1) == ']')
	{
		s += 2;
		goto done;
	}
	b = buf;
	x = buf + size - 2;
	s = t;
	for (;;)
	{
		if (!(c = *s++))
			goto oops;
		if (c == term)
		{
			if (!(c = *s++))
				goto oops;
			if (c != term)
			{
				if (c != ']')
					goto oops;
				break;
			}
		}
		if (b < x)
			*b++ = c;
	}
	r = s - t - 2;
	w = 0;
	if (b >= x)
		goto done;
	*b = 0;
	for (i = 0; i < r && i < sizeof(tmp) - 1; i++)
		tmp[i] = '0';
	tmp[i] = 0;
	if (mbxfrm(xfm, buf, sizeof(xfm)) >= mbxfrm(xfm, tmp, sizeof(xfm)))
		goto nope;
	t = (const char*)buf;
 done:
	if (r <= size && (char*)t != buf)
	{
		memcpy(buf, t, r);
		if (r < size)
			buf[r] = 0;
	}
	if (wc)
		*wc = w;
	if (e)
		*e = (char*)s;
	return r;
 oops:
 	s--;
 nope:
	if (e)
		*e = (char*)s;
	return -1;
}
