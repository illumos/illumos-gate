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
 * AT&T Research
 *
 * integral representation conversion support definitions
 * supports sizeof(integral_type)<=sizeof(intmax_t)
 */

#ifndef _SWAP_H
#define _SWAP_H

#include <ast_common.h>

#define int_swap	_ast_intswap

#define SWAP_MAX	8

#define SWAPOP(n)	(((n)&int_swap)^(n))

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern void*		swapmem(int, const void*, void*, size_t);
extern intmax_t		swapget(int, const void*, int);
extern void*		swapput(int, void*, int, intmax_t);
extern int		swapop(const void*, const void*, int);

#undef	extern

#endif
