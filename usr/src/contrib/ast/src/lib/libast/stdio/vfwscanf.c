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

#include "stdhdr.h"

typedef struct
{
	Sfdisc_t	sfdisc;		/* sfio discipline		*/
	Sfio_t*		f;		/* original wide stream		*/
	char		fmt[1];		/* mb fmt			*/
} Wide_t;

/*
 * wide exception handler
 * free on close
 */

static int
wideexcept(Sfio_t* f, int op, void* val, Sfdisc_t* dp)
{
	if (sffileno(f) >= 0)
		return -1;
	switch (op)
	{
	case SF_ATEXIT:
		sfdisc(f, SF_POPDISC);
		break;
	case SF_CLOSING:
	case SF_DPOP:
	case SF_FINAL:
		if (op != SF_CLOSING)
			free(dp);
		break;
	}
	return 0;
}

/*
 * sfio wide discipline read
 * 1 wchar_t at a time
 * go pure multibyte for best performance
 */

static ssize_t
wideread(Sfio_t* f, Void_t* buf, size_t size, Sfdisc_t* dp)
{
	register Wide_t*	w = (Wide_t*)dp;
	wchar_t			wuf[2];

#if 0
	if (sfread(w->f, wuf, sizeof(wuf[0])) != sizeof(wuf[0]))
		return -1;
	wuf[1] = 0;
	return wcstombs(buf, wuf, size);
#else
	ssize_t	r;

	r = sfread(w->f, wuf, sizeof(wuf[0]));
	if (r != sizeof(wuf[0]))
		return -1;
	wuf[1] = 0;
	r = wcstombs(buf, wuf, size);
	return r;
#endif
}

int
vfwscanf(Sfio_t* f, const wchar_t* fmt, va_list args)
{
	size_t	n;
	int	v;
	Sfio_t*	t;
	Wide_t*	w;
	char	buf[1024];

	STDIO_INT(f, "vfwscanf", int, (Sfio_t*, const wchar_t*, va_list), (f, fmt, args))

	FWIDE(f, WEOF);
	n = wcstombs(NiL, fmt, 0);
	if (w = newof(0, Wide_t, 1, n))
	{
		if (t = sfnew(NiL, buf, sizeof(buf), OPEN_MAX+1, SF_READ))
		{
			w->sfdisc.exceptf = wideexcept;
			w->sfdisc.readf = wideread;
			w->f = f;
			if (sfdisc(t, &w->sfdisc) == &w->sfdisc)
			{
				wcstombs(w->fmt, fmt, n + 1);
				v = sfvscanf(t, w->fmt, args);
			}
			else
			{
				free(w);
				v = -1;
			}
			sfsetfd(t, -1);
			sfclose(t);
		}
		else
		{
			free(w);
			v = -1;
		}
	}
	else
		v = -1;
	return v;
}
