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
 * return the length of the current record at b, size n, according to f
 * -1 returned on error
 *  0 returned if more data is required
 */

#include <recfmt.h>
#include <ctype.h>

ssize_t
reclen(Recfmt_t f, const void* b, size_t n)
{
	register unsigned char*	s = (unsigned char*)b;
	register unsigned char*	e;
	size_t			h;
	size_t			z;

	switch (RECTYPE(f))
	{
	case REC_delimited:
		if (e = (unsigned char*)memchr(s, REC_D_DELIMITER(f), n))
			return e - s + 1;
		return 0;
	case REC_fixed:
		return REC_F_SIZE(f);
	case REC_variable:
		h = REC_V_HEADER(f);
		if (n < h)
			return 0;
		z = 0;
		s += REC_V_OFFSET(f);
		e = s + REC_V_LENGTH(f);
		if (REC_V_LITTLE(f))
			while (e > s)
				z = (z<<8)|*--e;
		else
			while (s < e)
				z = (z<<8)|*s++;
		if (!REC_V_INCLUSIVE(f))
			z += h;
		else if (z < h)
			z = h;
		return z;
	case REC_method:
		return -1;
	}
	return -1;
}
