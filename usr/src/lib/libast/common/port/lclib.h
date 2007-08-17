/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1985-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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
 * locale state private definitions
 */

#ifndef _LCLIB_H
#define _LCLIB_H	1

#define categories	_ast_categories
#define locales		_ast_locales
#define translate	_ast_translate

struct Lc_info_s;

#define _LC_PRIVATE_ \
	struct Lc_info_s	info[AST_LC_COUNT]; \
	struct Lc_s*		next;

#define _LC_TERRITORY_PRIVATE_ \
	unsigned char		indices[LC_territory_language_max];

#include <ast.h>
#include <error.h>
#include <lc.h>

typedef struct Lc_numeric_s
{
	int		decimal;
	int		thousand;
} Lc_numeric_t;

#define LCINFO(c)	(&locales[c]->info[c])

extern	Lc_category_t	categories[];
extern	Lc_t*		locales[];

extern char*		translate(const char*, const char*, const char*, const char*);

#endif
