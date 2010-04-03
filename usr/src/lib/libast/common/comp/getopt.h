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
/*
 * gnu getopt interface
 */

#ifndef _GETOPT_H
#ifdef	_AST_STD_I
#define _GETOPT_H		-1
#else
#define _GETOPT_H		1

#include <ast_getopt.h>

#define no_argument		0
#define required_argument	1
#define optional_argument	2

struct option
{
	const char*	name;
	int		has_arg;
	int*		flag;
	int		val;
};

extern int	getopt_long(int, char* const*, const char*, const struct option*, int*);
extern int	getopt_long_only(int, char* const*, const char*, const struct option*, int*);

#endif
#endif
