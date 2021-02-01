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
 * mime base64 encode/decode
 *
 * Glenn Fowler
 * David Korn
 * AT&T Research
 */

#include <ast.h>

#define PAD		'='

#define B64_UC		3
#define B64_EC		4
#define B64_CHUNK	15
#define B64_PAD		64
#define B64_SPC		65
#define B64_IGN		66

static unsigned char	map[UCHAR_MAX+1];

static const char	alp[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * mime base64 encode
 */

ssize_t
base64encode(const void* fb, size_t fz, void** fn, void* tb, size_t tz, void** tn)
{
	register unsigned char*	fp;
	register unsigned char*	tp;
	register unsigned char*	fe;
	register unsigned char*	te;
	register unsigned char*	tc;
	register unsigned char*	m;
	register unsigned long	b;
	size_t			n;
	unsigned char		tmp[B64_EC * B64_CHUNK];

	m = (unsigned char*)alp;
	fp = fe = (unsigned char*)fb;
	if (fz >= 3)
	{
		n = fz % 3;
		fe += fz - n;
		fz = n;
	}
	if (tp = (unsigned char*)tb)
	{
		te = tp + tz - B64_EC + 1;
		n = 0;
	}
	else
	{
		if (fn)
			*fn = fp;
		if (tn)
			*tn = 0;
		tp = tmp;
		te = tp + sizeof(tmp) - B64_EC + 1;
		n = 1;
	}
	for (;;)
	{
		tc = tp + B64_EC * B64_CHUNK;
		do
		{
			if (fp >= fe)
				goto done;
			if (tp >= te)
			{
				if (fn)
					*fn = fp;
				if (tn)
					*tn = tp;
				n = tp - (unsigned char*)tb + 1;
				tp = tmp;
				te = tp + sizeof(tmp) - B64_EC + 1;
			}
			b = *fp++ << 16;
			b |= *fp++ << 8;
			b |= *fp++;
			*tp++ = m[b >> 18];
			*tp++ = m[(b >> 12) & 077];
			*tp++ = m[(b >> 6) & 077];
			*tp++ = m[b & 077];
		} while (tp < tc);
		if (n)
		{
			n += tp - tmp + (fp < fe);
			tp = tmp;
		}
		else
			*tp++ = '\n';
	}
 done:
	if (fz)
	{
		if (tp >= te)
		{
			if (fn)
				*fn = fp;
			if (tn)
				*tn = tp;
			n = tp - (unsigned char*)tb + 1;
			tp = tmp;
			te = tp + sizeof(tmp) - B64_EC + 1;
		}
		b = *fp++ << 16;
		if (fz == 2)
			b |= *fp++ << 8;
		*tp++ = m[b >> 18];
		*tp++ = m[(b >> 12) & 077];
		*tp++ = (fz == 2) ? m[(b >> 6) & 077] : PAD;
		*tp++ = PAD;
	}
	if (n)
		n += (tp - tmp) - 1;
	else
	{
		if (tp > (unsigned char*)tb && *(tp - 1) == '\n')
			tp--;
		if (tp < te)
			*tp = 0;
		n = tp - (unsigned char*)tb;
		if (tn)
			*tn = tp;
		if (fn)
			*fn = fp;
	}
	return n;
}

/*
 * mime base64 decode
 */

ssize_t
base64decode(const void* fb, size_t fz, void** fn, void* tb, size_t tz, void** tn)
{
	register unsigned char*	fp;
	register unsigned char*	tp;
	register unsigned char*	fe;
	register unsigned char*	te;
	register unsigned char*	tx;
	register unsigned char*	m;
	register int		c;
	register int		state;
	register unsigned long	v;
	unsigned char*		fc;
	ssize_t			n;

	if (!(m = map)[0])
	{
		memset(m, B64_IGN, sizeof(map));
		for (tp = (unsigned char*)alp; c = *tp; tp++)
			m[c] =  tp - (unsigned char*)alp;
		m[PAD] = B64_PAD;
		m[' '] = m['\t'] = m['\n'] = B64_SPC;
	}
	fp = (unsigned char*)fb;
	fe = fp + fz;
	if (tp = (unsigned char*)tb)
	{
		te = tp + tz;
		if (tz > 2)
			tz = 2;
		tx = te - tz;
		n = 0;
	}
	else
	{
		te = tx = tp;
		n = 1;
	}
	for (;;)
	{
		fc = fp;
		state = 0;
		v = 0;
		while (fp < fe)
		{
			if ((c = m[*fp++]) < 64)
			{
				v = (v << 6) | c;
				if (++state == 4)
				{
					if (tp >= tx)
					{
						if (n)
							n += 3;
						else
						{
							n = tp - (unsigned char*)tb + 4;
							if (tp < te)
							{
								*tp++ = (v >> 16);
								if (tp < te)
								{
									*tp++ = (v >> 8);
									if (tp < te)
										*tp++ = (v);
								}
							}
							if (tn)
								*tn = tp;
							if (fn)
								*fn = fc;
						}
					}
					else
					{
						*tp++ = (v >> 16);
						*tp++ = (v >> 8);
						*tp++ = (v);
					}
					fc = fp;
					state = 0;
					v = 0;
				}
			}
			else if (c == B64_PAD)
				break;
		}
		switch (state)
		{
		case 0:
			goto done;
		case 2:
			if (tp < te)
				*tp++ = v >> 4;
			else if (n)
				n++;
			else
			{
				n = tp - (unsigned char*)tb + 2;
				if (tn)
					*tn = tp;
				if (fn)
					*fn = fc;
			}
			break;
		case 3:
			if (tp < te)
			{
				*tp++ = v >> 10;
				if (tp < te)
					*tp++ = v >> 2;
				else
				{
					n = tp - (unsigned char*)tb + 2;
					if (tn)
						*tn = tp;
					if (fn)
						*fn = fc;
				}
			}
			else if (n)
				n += 2;
			else
			{
				n = tp - (unsigned char*)tb + 3;
				if (tn)
					*tn = tp;
				if (fn)
					*fn = fc;
			}
			break;
		}
		while (fp < fe && ((c = m[*fp++]) == B64_PAD || c == B64_SPC));
		if (fp >= fe || c >= 64)
			break;
		fp--;
	}
 done:
	if (n)
		n--;
	else
	{
		if (tp < te)
			*tp = 0;
		n = tp - (unsigned char*)tb;
		if (fn)
			*fn = fp;
		if (tn)
			*tn = tp;
	}
	return n;
}
