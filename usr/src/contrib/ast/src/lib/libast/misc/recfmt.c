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
 * determine record format by sampling data in <buf,size>
 * total is the total file size, <=0 if not available
 * return r:
 *	-1				could not determine
 *	RECTYPE(r)==REC_fixed		fixed length REC_F_SIZE(r)
 *	RECTYPE(r)==REC_delimited	variable length delimiter=REC_D_DELIMITER(r)
 *	RECTYPE(r)==REC_variable	variable length
 */

#include <recfmt.h>

typedef struct
{
	unsigned int	rep[4 * 1024];
	unsigned int	hit[UCHAR_MAX + 1];
} Sample_t;

Recfmt_t
recfmt(const void* buf, size_t size, off_t total)
{
	register unsigned char*		s;
	register unsigned char*		t;
	register Sample_t*		q;
	register unsigned int*		h;
	register unsigned int		i;
	unsigned int			j;
	unsigned int			k;
	unsigned int			n;
	unsigned int			m;
	unsigned int			x;
	unsigned long			f;
	unsigned long			g;

	static unsigned char		terminators[] = { '\n', 0x15, 0x25 };

	/*
	 * check for V format
	 */

	s = (unsigned char*)buf;
	t = s + size;
	while ((k = (t - s)) >= 4 && !s[2] && !s[3])
	{
		if ((i = (s[0]<<8)|s[1]) > k)
			break;
		s += i;
	}
	if (!k || size > 2 * k)
		return REC_V_TYPE(4, 0, 2, 0, 1);
	s = (unsigned char*)buf;

	/*
	 * check for terminated records
	 */

	for (i = 0; i < elementsof(terminators); i++)
		if ((t = (unsigned char*)memchr((void*)s, k = terminators[i], size / 2)) && (n = t - s + 1) > 1 && (total <= 0 || !(total % n)))
		{
			for (j = n - 1; j < size; j += n)
				if (s[j] != k)
				{
					n = 0;
					break;
				}
			if (n)
				return REC_D_TYPE(terminators[i]);
		}

	/*
	 * check fixed length record frequencies
	 */

	if (!(q = newof(0, Sample_t, 1, 0)))
		return REC_N_TYPE();
	x = 0;
	for (i = 0; i < size; i++)
	{
		h = q->hit + s[i];
		m = i - *h;
		*h = i;
		if (m < elementsof(q->rep))
		{
			if (m > x)
				x = m;
			q->rep[m]++;
		}
	}
	n = 0;
	m = 0;
	f = ~0;
	for (i = x; i > 1; i--)
	{
		if ((total <= 0 || !(total % i)) && q->rep[i] > q->rep[n])
		{
			m++;
			g = 0;
			for (j = i; j < size - i; j += i)
				for (k = 0; k < i; k++)
					if (s[j + k] != s[j + k - i])
						g++;
			g = (((g * 100) / i) * 100) / q->rep[i];
			if (g <= f)
			{
				f = g;
				n = i;
			}
		}
	}
	if (m <= 1 && n <= 2 && total > 1 && total < 256)
	{
		n = 0;
		for (i = 0; i < size; i++)
			for (j = 0; j < elementsof(terminators); j++)
				if (s[i] == terminators[j])
					n++;
		n = n ? 0 : total;
	}
	free(q);
	return n ? REC_F_TYPE(n) : REC_N_TYPE();
}

#if MAIN

main()
{
	void*	s;
	size_t	size;
	off_t	total;

	if (!(s = sfreserve(sfstdin, SF_UNBOUND, 0)))
	{
		sfprintf(sfstderr, "read error\n");
		return 1;
	}
	size = sfvalue(sfstdin);
	total = sfsize(sfstdin);
	sfprintf(sfstdout, "%d\n", recfmt(s, size, total));
	return 0;
}

#endif
