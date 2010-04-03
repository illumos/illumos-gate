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
	const Crcnum_t		*tab; /* use |const| to give the compiler a hint that the data won't change */
	Crcnum_t		tabdata[256];
	unsigned int		addsize;
	unsigned int		rotate;
} Crc_t;

#define CRC(p,s,c)		(s = (s >> 8) ^ (p)->tab[(s ^ (c)) & 0xff])
#define CRCROTATE(p,s,c)	(s = (s << 8) ^ (p)->tab[((s >> 24) ^ (c)) & 0xff])

static const
Crcnum_t posix_cksum_tab[256] = {
	0x00000000U,
	0x04c11db7U, 0x09823b6eU, 0x0d4326d9U, 0x130476dcU, 0x17c56b6bU,
	0x1a864db2U, 0x1e475005U, 0x2608edb8U, 0x22c9f00fU, 0x2f8ad6d6U,
	0x2b4bcb61U, 0x350c9b64U, 0x31cd86d3U, 0x3c8ea00aU, 0x384fbdbdU,
	0x4c11db70U, 0x48d0c6c7U, 0x4593e01eU, 0x4152fda9U, 0x5f15adacU,
	0x5bd4b01bU, 0x569796c2U, 0x52568b75U, 0x6a1936c8U, 0x6ed82b7fU,
	0x639b0da6U, 0x675a1011U, 0x791d4014U, 0x7ddc5da3U, 0x709f7b7aU,
	0x745e66cdU, 0x9823b6e0U, 0x9ce2ab57U, 0x91a18d8eU, 0x95609039U,
	0x8b27c03cU, 0x8fe6dd8bU, 0x82a5fb52U, 0x8664e6e5U, 0xbe2b5b58U,
	0xbaea46efU, 0xb7a96036U, 0xb3687d81U, 0xad2f2d84U, 0xa9ee3033U,
	0xa4ad16eaU, 0xa06c0b5dU, 0xd4326d90U, 0xd0f37027U, 0xddb056feU,
	0xd9714b49U, 0xc7361b4cU, 0xc3f706fbU, 0xceb42022U, 0xca753d95U,
	0xf23a8028U, 0xf6fb9d9fU, 0xfbb8bb46U, 0xff79a6f1U, 0xe13ef6f4U,
	0xe5ffeb43U, 0xe8bccd9aU, 0xec7dd02dU, 0x34867077U, 0x30476dc0U,
	0x3d044b19U, 0x39c556aeU, 0x278206abU, 0x23431b1cU, 0x2e003dc5U,
	0x2ac12072U, 0x128e9dcfU, 0x164f8078U, 0x1b0ca6a1U, 0x1fcdbb16U,
	0x018aeb13U, 0x054bf6a4U, 0x0808d07dU, 0x0cc9cdcaU, 0x7897ab07U,
	0x7c56b6b0U, 0x71159069U, 0x75d48ddeU, 0x6b93dddbU, 0x6f52c06cU,
	0x6211e6b5U, 0x66d0fb02U, 0x5e9f46bfU, 0x5a5e5b08U, 0x571d7dd1U,
	0x53dc6066U, 0x4d9b3063U, 0x495a2dd4U, 0x44190b0dU, 0x40d816baU,
	0xaca5c697U, 0xa864db20U, 0xa527fdf9U, 0xa1e6e04eU, 0xbfa1b04bU,
	0xbb60adfcU, 0xb6238b25U, 0xb2e29692U, 0x8aad2b2fU, 0x8e6c3698U,
	0x832f1041U, 0x87ee0df6U, 0x99a95df3U, 0x9d684044U, 0x902b669dU,
	0x94ea7b2aU, 0xe0b41de7U, 0xe4750050U, 0xe9362689U, 0xedf73b3eU,
	0xf3b06b3bU, 0xf771768cU, 0xfa325055U, 0xfef34de2U, 0xc6bcf05fU,
	0xc27dede8U, 0xcf3ecb31U, 0xcbffd686U, 0xd5b88683U, 0xd1799b34U,
	0xdc3abdedU, 0xd8fba05aU, 0x690ce0eeU, 0x6dcdfd59U, 0x608edb80U,
	0x644fc637U, 0x7a089632U, 0x7ec98b85U, 0x738aad5cU, 0x774bb0ebU,
	0x4f040d56U, 0x4bc510e1U, 0x46863638U, 0x42472b8fU, 0x5c007b8aU,
	0x58c1663dU, 0x558240e4U, 0x51435d53U, 0x251d3b9eU, 0x21dc2629U,
	0x2c9f00f0U, 0x285e1d47U, 0x36194d42U, 0x32d850f5U, 0x3f9b762cU,
	0x3b5a6b9bU, 0x0315d626U, 0x07d4cb91U, 0x0a97ed48U, 0x0e56f0ffU,
	0x1011a0faU, 0x14d0bd4dU, 0x19939b94U, 0x1d528623U, 0xf12f560eU,
	0xf5ee4bb9U, 0xf8ad6d60U, 0xfc6c70d7U, 0xe22b20d2U, 0xe6ea3d65U,
	0xeba91bbcU, 0xef68060bU, 0xd727bbb6U, 0xd3e6a601U, 0xdea580d8U,
	0xda649d6fU, 0xc423cd6aU, 0xc0e2d0ddU, 0xcda1f604U, 0xc960ebb3U,
	0xbd3e8d7eU, 0xb9ff90c9U, 0xb4bcb610U, 0xb07daba7U, 0xae3afba2U,
	0xaafbe615U, 0xa7b8c0ccU, 0xa379dd7bU, 0x9b3660c6U, 0x9ff77d71U,
	0x92b45ba8U, 0x9675461fU, 0x8832161aU, 0x8cf30badU, 0x81b02d74U,
	0x857130c3U, 0x5d8a9099U, 0x594b8d2eU, 0x5408abf7U, 0x50c9b640U,
	0x4e8ee645U, 0x4a4ffbf2U, 0x470cdd2bU, 0x43cdc09cU, 0x7b827d21U,
	0x7f436096U, 0x7200464fU, 0x76c15bf8U, 0x68860bfdU, 0x6c47164aU,
	0x61043093U, 0x65c52d24U, 0x119b4be9U, 0x155a565eU, 0x18197087U,
	0x1cd86d30U, 0x029f3d35U, 0x065e2082U, 0x0b1d065bU, 0x0fdc1becU,
	0x3793a651U, 0x3352bbe6U, 0x3e119d3fU, 0x3ad08088U, 0x2497d08dU,
	0x2056cd3aU, 0x2d15ebe3U, 0x29d4f654U, 0xc5a92679U, 0xc1683bceU,
	0xcc2b1d17U, 0xc8ea00a0U, 0xd6ad50a5U, 0xd26c4d12U, 0xdf2f6bcbU,
	0xdbee767cU, 0xe3a1cbc1U, 0xe760d676U, 0xea23f0afU, 0xeee2ed18U,
	0xf0a5bd1dU, 0xf464a0aaU, 0xf9278673U, 0xfde69bc4U, 0x89b8fd09U,
	0x8d79e0beU, 0x803ac667U, 0x84fbdbd0U, 0x9abc8bd5U, 0x9e7d9662U,
	0x933eb0bbU, 0x97ffad0cU, 0xafb010b1U, 0xab710d06U, 0xa6322bdfU,
	0xa2f33668U, 0xbcb4666dU, 0xb8757bdaU, 0xb5365d03U, 0xb1f740b4U
};
 
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

	if(!strcmp(name, "crc-0x04c11db7-rotate-done-size"))
	{
		sum->init=0;
		sum->done=0xffffffff;
		sum->xorsize=0x0;
		sum->addsize=0x1;
		sum->rotate=1;

		/* Optimized codepath for POSIX cksum to save startup time */
		sum->tab=posix_cksum_tab;
	}
	else
	{
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
			for (i = 0; i < elementsof(sum->tabdata); i++)
			{
				t = 0;
				x = i;
				for (j = 0; j < 8; j++)
				{
					if (x & 1)
						t ^= p[j];
					x >>= 1;
				}
				sum->tabdata[i] = t;
			}
		}
		else
		{
			for (i = 0; i < elementsof(sum->tabdata); i++)
			{
				x = i;
				for (j = 0; j < 8; j++)
					x = (x>>1) ^ ((x & 1) ? polynomial : 0);
				sum->tabdata[i] = x;
			}
		}

		sum->tab=sum->tabdata;
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

#if defined(__SUNPRO_C) || defined(__GNUC__)

#if defined(__SUNPRO_C)
#    include <sun_prefetch.h>
#    define sum_prefetch(addr) sun_prefetch_read_many((void *)(addr))
#elif defined(__GNUC__)
#    define sum_prefetch(addr) __builtin_prefetch((addr), 0, 3)
#else
#    error Unknown compiler
#endif

#define CBLOCK_SIZE (64)
#pragma unroll(16)

static int
crc_block(Sum_t* p, const void* s, size_t n)
{
	Crc_t*			sum = (Crc_t*)p;
	register Crcnum_t	c = sum->sum;
	register const unsigned char*	b = (const unsigned char*)s;
	register const unsigned char*	e = b + n;
	unsigned short i;

	sum_prefetch(b);

	if (sum->rotate)
	{
		while (n > CBLOCK_SIZE)
		{
			sum_prefetch(b+CBLOCK_SIZE);
			for(i=0 ; i < CBLOCK_SIZE ; i++)
			{
				CRCROTATE(sum, c, *b++);
			}

			n-=CBLOCK_SIZE;
		}
		
		while (b < e)
		{
			CRCROTATE(sum, c, *b++);
		}
	}
	else
	{
		while (n > CBLOCK_SIZE)
		{
			sum_prefetch(b+CBLOCK_SIZE);
			for(i=0 ; i < CBLOCK_SIZE ; i++)
			{
				CRC(sum, c, *b++);
			}

			n-=CBLOCK_SIZE;
		}
		
		while (b < e)
		{
			CRC(sum, c, *b++);
		}
	}

	sum->sum = c;
	return 0;
}
#else
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
#endif /* defined(__SUNPRO_C) || defined(__GNUC__) */

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
