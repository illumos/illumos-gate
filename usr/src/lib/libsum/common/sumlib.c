/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1996-2010 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
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
 * Glenn Fowler
 * AT&T Research
 *
 * man this is sum library
 */

#define _SUM_PRIVATE_	\
			struct Method_s*	method;	\
			uintmax_t		total_count;	\
			uintmax_t		total_size;	\
			uintmax_t		size;

#include <sum.h>
#include <ctype.h>
#include <swap.h>
#include <hashpart.h>

#define SCALE(n,m)	(((n)+(m)-1)/(m))

typedef struct Method_s
{
	const char*	match;
	const char*	description;
	const char*	options;
	Sum_t*		(*open)(const struct Method_s*, const char*);
	int		(*init)(Sum_t*);
	int		(*block)(Sum_t*, const void*, size_t);
	int		(*data)(Sum_t*, Sumdata_t*);
	int		(*print)(Sum_t*, Sfio_t*, int, size_t);
	int		(*done)(Sum_t*);
	int		scale;
} Method_t;

typedef struct Map_s
{
	const char*	match;
	const char*	description;
	const char*	map;
} Map_t;

/*
 * 16 and 32 bit common code
 */

#define _INTEGRAL_PRIVATE_ \
	uint32_t	sum; \
	uint32_t	total_sum;
	
typedef struct Integral_s
{
	_SUM_PUBLIC_
	_SUM_PRIVATE_
	_INTEGRAL_PRIVATE_
} Integral_t;

static Sum_t*
long_open(const Method_t* method, const char* name)
{
	Integral_t*	p;

	if (p = newof(0, Integral_t, 1, 0))
	{
		p->method = (Method_t*)method;
		p->name = name;
	}
	return (Sum_t*)p;
}

static int
long_init(Sum_t* p)
{
	((Integral_t*)p)->sum = 0;
	return 0;
}

static int
long_done(Sum_t* p)
{
	register Integral_t*	x = (Integral_t*)p;

	x->total_sum ^= (x->sum &= 0xffffffff);
	return 0;
}

static int
short_done(Sum_t* p)
{
	register Integral_t*	x = (Integral_t*)p;

	x->total_sum ^= (x->sum &= 0xffff);
	return 0;
}

static int
long_print(Sum_t* p, Sfio_t* sp, register int flags, size_t scale)
{
	register Integral_t*	x = (Integral_t*)p;
	register uint32_t	c;
	register uintmax_t	z;
	register size_t		n;

	c = (flags & SUM_TOTAL) ? x->total_sum : x->sum;
	sfprintf(sp, "%.*I*u", (flags & SUM_LEGACY) ? 5 : 1, sizeof(c), c);
	if (flags & SUM_SIZE)
	{
		z = (flags & SUM_TOTAL) ? x->total_size : x->size;
		if ((flags & SUM_SCALE) && ((n = scale) || (n = x->method->scale)))
			z = SCALE(z, n);
		sfprintf(sp, " %*I*u", (flags & SUM_LEGACY) ? 6 : 0, sizeof(z), z);
	}
	if (flags & SUM_TOTAL)
		sfprintf(sp, " %*I*u", (flags & SUM_LEGACY) ? 6 : 0, sizeof(x->total_count), x->total_count);
	return 0;
}

static int
long_data(Sum_t* p, Sumdata_t* data)
{
	register Integral_t*	x = (Integral_t*)p;

	data->size = sizeof(data->num);
	data->num = x->sum;
	data->buf = 0;
	return 0;
}

#include "FEATURE/sum"

#include "sum-att.c"
#include "sum-ast4.c"
#include "sum-bsd.c"
#include "sum-crc.c"
#include "sum-prng.c"

#if _LIB_md && _lib_MD5Init && _hdr_md5 && _lib_SHA2Init && _hdr_sha2

#include "sum-lmd.c"

#else

#include "sum-md5.c"
#include "sum-sha1.c"
#include "sum-sha2.c"

#endif

/*
 * now the library interface
 */

#undef	METHOD		/* solaris <sys/localedef.h>! */
#define METHOD(x)	x##_match,x##_description,x##_options,x##_open,x##_init,x##_block,x##_data,x##_print,x##_done,x##_scale

static const Method_t	methods[] =
{
	METHOD(att),
	METHOD(ast4),
	METHOD(bsd),
	METHOD(crc),
	METHOD(prng),
#ifdef md4_description
	METHOD(md4),
#endif
#ifdef md5_description
	METHOD(md5),
#endif
#ifdef sha1_description
	METHOD(sha1),
#endif
#ifdef sha256_description
	METHOD(sha256),
#endif
#ifdef sha384_description
	METHOD(sha384),
#endif
#ifdef sha512_description
	METHOD(sha512),
#endif
};

static const Map_t	maps[] =
{
	{
		"posix|cksum|std|standard",
		"The posix 1003.2-1992 32 bit crc checksum. This is the"
		" default \bcksum\b(1)  method.",
		"crc-0x04c11db7-rotate-done-size"
	},
	{
		"zip",
		"The \bzip\b(1) crc.",
		"crc-0xedb88320-init-done"
	},
	{
		"fddi",
		"The FDDI crc.",
		"crc-0xedb88320-size=0xcc55cc55"
	},
	{
		"fnv|fnv1",
		"The Fowler-Noll-Vo 32 bit PRNG hash with non-zero"
		" initializer (FNV-1).",
		"prng-0x01000193-init=0x811c9dc5"
	},
	{
		"ast|strsum",
		"The \bast\b \bstrsum\b(3) PRNG hash.",
		"prng-0x63c63cd9-add=0x9c39c33d"
	},
};

/*
 * simple alternation prefix match
 */

static int
match(register const char* s, register const char* p)
{
	register const char*	b = s;

	for (;;)
	{
		do
		{
			if (*p == '|' || *p == 0)
				return 1;
		} while (*s++ == *p++);
		for (;;)
		{
			switch (*p++)
			{
			case 0:
				return 0;
			case '|':
				break;
			default:
				continue;
			}
			break;
		}
		s = b;
	}
	return 0;
}

/*
 * open sum method name
 */

Sum_t*
sumopen(register const char* name)
{
	register int	n;

	if (!name || !name[0] || name[0] == '-' && !name[1])
		name = "default";
	for (n = 0; n < elementsof(maps); n++)
		if (match(name, maps[n].match))
		{
			name = maps[n].map;
			break;
		}
	for (n = 0; n < elementsof(methods); n++)
		if (match(name, methods[n].match))
			return (*methods[n].open)(&methods[n], name);
	return 0;
}

/*
 * initialize for a new run of blocks
 */

int
suminit(Sum_t* p)
{
	p->size = 0;
	return (*p->method->init)(p);
}

/*
 * compute the running sum on buf
 */

int
sumblock(Sum_t* p, const void* buf, size_t siz)
{
	p->size += siz;
	return (*p->method->block)(p, buf, siz);
}

/*
 * done with this run of blocks
 */

int
sumdone(Sum_t* p)
{
	p->total_count++;
	p->total_size += p->size;
	return (*p->method->done)(p);
}

/*
 * print the sum [size] on sp
 */

int
sumprint(Sum_t* p, Sfio_t* sp, int flags, size_t scale)
{
	return (*p->method->print)(p, sp, flags, scale);
}

/*
 * return the current sum (internal) data
 */

int
sumdata(Sum_t* p, Sumdata_t* d)
{
	return (*p->method->data)(p, d);
}

/*
 * close an open sum handle
 */

int
sumclose(Sum_t* p)
{
	free(p);
	return 0;
}

/*
 * print the checksum method optget(3) usage on sp and return the length
 */

int
sumusage(Sfio_t* sp)
{
	register int	i;
	register int	n;

	for (i = n = 0; i < elementsof(methods); i++)
	{
		n += sfprintf(sp, "[+%s?%s]", methods[i].match, methods[i].description);
		if (methods[i].options)
			n += sfprintf(sp, "{\n%s\n}", methods[i].options);
	}
	for (i = 0; i < elementsof(maps); i++)
		n += sfprintf(sp, "[+%s?%s Shorthand for \b%s\b.]", maps[i].match, maps[i].description, maps[i].map);
	return n;
}
