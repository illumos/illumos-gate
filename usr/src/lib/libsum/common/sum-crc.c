/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1996-2008 AT&T Intellectual Property          *
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
 * crc
 */

#define crc_description \
	"32 bit CRC (cyclic redundancy check)."
#define crc_options	"\
[+polynomial?The 32 bit crc polynomial bitmask with implicit bit 32.]:[mask:=0xedb88320]\
[+done?XOR the final crc value with \anumber\a. 0xffffffff is used if \anumber\a is omitted.]:?[number:=0]\
[+init?The initial crc value. 0xffffffff is used if \anumber\a is omitted.]:?[number:=0]\
[+rotate?XOR each input character with the high order crc byte (instead of the low order).]\
[+size?Include the total number of bytes in the crc. \anumber\a, if specified, is first XOR'd into the size.]:?[number:=0]\
"
#define crc_match	"crc"
#define crc_open	crc_open
#define crc_print	long_print
#define crc_data	long_data
#define crc_scale	0

typedef uint32_t Crcnum_t;

typedef struct Crc_s
{
	_SUM_PUBLIC_
	_SUM_PRIVATE_
	_INTEGRAL_PRIVATE_
	Crcnum_t		init;
	Crcnum_t		done;
	Crcnum_t		xorsize;
	Crcnum_t		tab[256];
	unsigned int		addsize;
	unsigned int		rotate;
} Crc_t;

#define CRC(p,s,c)		(s = (s >> 8) ^ (p)->tab[(s ^ (c)) & 0xff])
#define CRCROTATE(p,s,c)	(s = (s << 8) ^ (p)->tab[((s >> 24) ^ (c)) & 0xff])

static Sum_t*
crc_open(const Method_t* method, const char* name)
{
	register Crc_t*		sum;
	register const char*	s;
	register const char*	t;
	register const char*	v;
	register int		i;
	register int		j;
	Crcnum_t		polynomial;
	Crcnum_t		x;

	if (sum = newof(0, Crc_t, 1, 0))
	{
		sum->method = (Method_t*)method;
		sum->name = name;
	}
	polynomial = 0xedb88320;
	s = name;
	while (*(t = s))
	{
		for (t = s, v = 0; *s && *s != '-'; s++)
			if (*s == '=' && !v)
				v = s;
		i = (v ? v : s) - t;
		if (isdigit(*t) || v && i >= 4 && strneq(t, "poly", 4) && (t = v + 1))
			polynomial = strtoul(t, NiL, 0);
		else if (strneq(t, "done", i))
			sum->done = v ? strtoul(v + 1, NiL, 0) : ~sum->done;
		else if (strneq(t, "init", i))
			sum->init = v ? strtoul(v + 1, NiL, 0) : ~sum->init;
		else if (strneq(t, "rotate", i))
			sum->rotate = 1;
		else if (strneq(t, "size", i))
		{
			sum->addsize = 1;
			if (v)
				sum->xorsize = strtoul(v + 1, NiL, 0);
		}
		if (*s == '-')
			s++;
	}
	if (sum->rotate)
	{
		Crcnum_t	t;
		Crcnum_t	p[8];

		p[0] = polynomial;
		for (i = 1; i < 8; i++)
			p[i] = (p[i-1] << 1) ^ ((p[i-1] & 0x80000000) ? polynomial : 0);
		for (i = 0; i < elementsof(sum->tab); i++)
		{
			t = 0;
			x = i;
			for (j = 0; j < 8; j++)
			{
				if (x & 1)
					t ^= p[j];
				x >>= 1;
			}
			sum->tab[i] = t;
		}
	}
	else
	{
		for (i = 0; i < elementsof(sum->tab); i++)
		{
			x = i;
			for (j = 0; j < 8; j++)
				x = (x>>1) ^ ((x & 1) ? polynomial : 0);
			sum->tab[i] = x;
		}
	}
	return (Sum_t*)sum;
}

static int
crc_init(Sum_t* p)
{
	Crc_t*		sum = (Crc_t*)p;

	sum->sum = sum->init;
	return 0;
}

static int
crc_block(Sum_t* p, const void* s, size_t n)
{
	Crc_t*			sum = (Crc_t*)p;
	register Crcnum_t	c = sum->sum;
	register unsigned char*	b = (unsigned char*)s;
	register unsigned char*	e = b + n;

	if (sum->rotate)
		while (b < e)
			CRCROTATE(sum, c, *b++);
	else
		while (b < e)
			CRC(sum, c, *b++);
	sum->sum = c;
	return 0;
}

static int
crc_done(Sum_t* p)
{
	register Crc_t*		sum = (Crc_t*)p;
	register Crcnum_t	c;
	register uintmax_t	n;
	int			i;
	int			j;

	c = sum->sum;
	if (sum->addsize)
	{
		n = sum->size ^ sum->xorsize;
		if (sum->rotate)
			while (n)
			{
				CRCROTATE(sum, c, n);
				n >>= 8;
			}
		else
			for (i = 0, j = 32; i < 4; i++)
			{
				j -= 8;
				CRC(sum, c, n >> j);
			}
	}
	sum->sum = c ^ sum->done;
	sum->total_sum ^= (sum->sum &= 0xffffffff);
	return 0;
}
