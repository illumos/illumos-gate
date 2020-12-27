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
 * Glenn Fowler
 * Landon Kurt Knoll
 * Phong Vo
 *
 * FNV-1 linear congruent checksum/hash/PRNG
 * see http://www.isthe.com/chongo/tech/comp/fnv/
 */

#ifndef _FNV_H
#define _FNV_H

#include <ast_common.h>

#define FNV_INIT	0x811c9dc5L
#define FNV_MULT	0x01000193L

#define FNVINIT(h)	(h = FNV_INIT)
#define FNVPART(h,c)	(h = (h) * FNV_MULT ^ (c))
#define FNVSUM(h,s,n)	do { \
			register size_t _i_ = 0; \
			while (_i_ < n) \
				FNVPART(h, ((unsigned char*)s)[_i_++]); \
			} while (0)

#if _typ_int64_t

#ifdef _ast_LL

#define FNV_INIT64	0xcbf29ce484222325LL
#define FNV_MULT64	0x00000100000001b3LL

#else

#define FNV_INIT64	((int64_t)0xcbf29ce484222325)
#define FNV_MULT64	((int64_t)0x00000100000001b3)

#endif

#define FNVINIT64(h)	(h = FNV_INIT64)
#define FNVPART64(h,c)	(h = (h) * FNV_MULT64 ^ (c))
#define FNVSUM64(h,s,n)	do { \
			register int _i_ = 0; \
			while (_i_ < n) \
				FNVPART64(h, ((unsigned char*)s)[_i_++]); \
			} while (0)

#endif

#endif
