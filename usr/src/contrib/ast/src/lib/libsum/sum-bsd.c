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
 * bsd
 */

#define bsd_description \
	"The BSD checksum."
#define bsd_options	0
#define bsd_match	"bsd|ucb"
#define bsd_open	long_open
#define bsd_init	long_init
#define bsd_done	short_done
#define bsd_print	long_print
#define bsd_data	long_data
#define bsd_scale	1024

static int
bsd_block(register Sum_t* p, const void* s, size_t n)
{
	register uint32_t	c = ((Integral_t*)p)->sum;
	register unsigned char*	b = (unsigned char*)s;
	register unsigned char*	e = b + n;

	while (b < e)
		c = ((c >> 1) + *b++ + ((c & 01) ? 0x8000 : 0)) & 0xffff;
	((Integral_t*)p)->sum = c;
	return 0;
}
