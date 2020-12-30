/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1996-2011 AT&T Intellectual Property          *
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
*                                                                      *
***********************************************************************/
#pragma prototyped

/*
 * prng
 */

#include <fnv.h>

#define prng_description \
	"32 bit PRNG (pseudo random number generator) hash."
#define prng_options	"\
[+mpy?The 32 bit PRNG multiplier.]:[number:=0x01000193]\
[+add?The 32 bit PRNG addend.]:[number:=0]\
[+init?The PRNG initial value. 0xffffffff is used if \anumber\a is omitted.]:?[number:=0x811c9dc5]\
"
#define prng_match	"prng"
#define prng_done	long_done
#define prng_print	long_print
#define prng_data	long_data
#define prng_scale	0

typedef uint32_t Prngnum_t;

typedef struct Prng_s
{
	_SUM_PUBLIC_
	_SUM_PRIVATE_
	_INTEGRAL_PRIVATE_
	Prngnum_t		init;
	Prngnum_t		mpy;
	Prngnum_t		add;
} Prng_t;

static Sum_t*
prng_open(const Method_t* method, const char* name)
{
	register Prng_t*	sum;
	register const char*	s;
	register const char*	t;
	register const char*	v;
	register int		i;

	if (sum = newof(0, Prng_t, 1, 0))
	{
		sum->method = (Method_t*)method;
		sum->name = name;
	}
	s = name;
	while (*(t = s))
	{
		for (t = s, v = 0; *s && *s != '-'; s++)
			if (*s == '=' && !v)
				v = s;
		i = (v ? v : s) - t;
		if (isdigit(*t) || v && strneq(t, "mpy", i) && (t = v + 1))
			sum->mpy = strtoul(t, NiL, 0);
		else if (strneq(t, "add", i))
			sum->add = v ? strtoul(v + 1, NiL, 0) : ~sum->add;
		else if (strneq(t, "init", i))
			sum->init = v ? strtoul(v + 1, NiL, 0) : ~sum->init;
		if (*s == '-')
			s++;
	}
	if (!sum->mpy)
	{
		sum->mpy = FNV_MULT;
		if (!sum->init)
			sum->init = FNV_INIT;
	}
	return (Sum_t*)sum;
}

static int
prng_init(Sum_t* p)
{
	Prng_t*		sum = (Prng_t*)p;

	sum->sum = sum->init;
	return 0;
}

static int
prng_block(Sum_t* p, const void* s, size_t n)
{
	Prng_t*			sum = (Prng_t*)p;
	register Prngnum_t	c = sum->sum;
	register unsigned char*	b = (unsigned char*)s;
	register unsigned char*	e = b + n;

	while (b < e)
		c = c * sum->mpy + sum->add + *b++;
	sum->sum = c;
	return 0;
}
