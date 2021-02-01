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
 * locale state private definitions
 */

#ifndef _LCLIB_H
#define _LCLIB_H	1

#define locales		_ast_locales
#define translate	_ast_translate

#define lc_categories	_ast_lc_categories
#define lc_charsets	_ast_lc_charsets
#define lc_languages	_ast_lc_languages
#define lc_maps		_ast_lc_maps
#define lc_territories	_ast_lc_territories

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

extern const Lc_charset_t	lc_charsets[];
extern const Lc_language_t	lc_languages[];
extern const Lc_map_t		lc_maps[];
extern const Lc_territory_t	lc_territories[];

extern Lc_category_t		lc_categories[];
extern Lc_t*			locales[];

extern char*			translate(const char*, const char*, const char*, const char*);

#endif
