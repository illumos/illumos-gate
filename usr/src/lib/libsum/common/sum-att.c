/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1996-2009 AT&T Intellectual Property          *
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
 * att
 */

#define att_description	\
	"The system 5 release 4 checksum. This is the default for \bsum\b \
	when \bgetconf UNIVERSE\b is \batt\b. This is the only true sum; \
	all of the other methods are order dependent."
#define att_options	0
#define att_match	"att|sys5|s5|default"
#define att_open	long_open
#define att_init	long_init
#define att_print	long_print
#define att_data	long_data
#define att_scale	512

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

/* Inmos transputer would love this algorithm */
static int
att_block(register Sum_t* p, const void* s, size_t n)
{
	register uint32_t	c = ((Integral_t*)p)->sum;
	register const unsigned char*	b = (const unsigned char*)s;
	register const unsigned char*	e = b + n;
	register uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
	register unsigned int i;
	
	s0=s1=s2=s3=s4=s5=s6=s7=0U;
	
	sum_prefetch((void *)b);
	
	while (n > CBLOCK_SIZE)
	{
		sum_prefetch((b+CBLOCK_SIZE));
		
		/* Compiler will unroll for() loops per #pragma unroll */
		for (i=0 ; i < (CBLOCK_SIZE/8) ; i++)
		{
			/*
			 * use s0-s7 to decouple calculations (this improves pipelining)
			 * because each operation is completely independent from it's
			 * siblings
			 */
			s0+=b[0];
			s1+=b[1];
			s2+=b[2];
			s3+=b[3];
			s4+=b[4];
			s5+=b[5];
			s6+=b[6];
			s7+=b[7];

			b+=8;
			n-=8;
		}
	}
	
	c+=s0+s1+s2+s3+s4+s5+s6+s7;

	while (b < e)
		c += *b++;
	((Integral_t*)p)->sum = c;
	return 0;
}

#else
static int
att_block(register Sum_t* p, const void* s, size_t n)
{
	register uint32_t	c = ((Integral_t*)p)->sum;
	register unsigned char*	b = (unsigned char*)s;
	register unsigned char*	e = b + n;

	while (b < e)
		c += *b++;
	((Integral_t*)p)->sum = c;
	return 0;
}
#endif /* defined(__SUNPRO_C) || defined(__GNUC__) */

static int
att_done(Sum_t* p)
{
	register uint32_t	c = ((Integral_t*)p)->sum;

	c = (c & 0xffff) + ((c >> 16) & 0xffff);
	c = (c & 0xffff) + (c >> 16);
	((Integral_t*)p)->sum = c & 0xffff;
	return short_done(p);
}
