/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped

#include <ast.h>

/*
 * format 4 byte local byte order ip address
 * and optional prefix bits (if 0 <= bits <= 32)
 */

char*
fmtip4(register uint32_t addr, int bits)
{
	char*	buf;
	int	z;
	int	i;

	buf = fmtbuf(z = 20);
	i = sfsprintf(buf, z, "%d.%d.%d.%d", (addr>>24)&0xff, (addr>>16)&0xff, (addr>>8)&0xff, (addr)&0xff);
	if (bits >= 0 && bits <= 32)
		sfsprintf(buf + i, z - i, "/%d", bits);
	return buf;
}
