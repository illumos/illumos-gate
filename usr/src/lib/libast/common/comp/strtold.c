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
/*
 * strtold() implementation
 */

#define S2F_function	strtold
#define S2F_type	2

/*
 * ast strtold() => strtod() when double == long double
 */

#define _AST_STD_H	1

#include <ast_common.h>

#if _ast_fltmax_double
#define strtold		______strtold
#endif

#include <ast_lib.h>
#include <ast_sys.h>

#if _ast_fltmax_double
#undef	strtold
#endif

#undef	_AST_STD_H

#include "sfstrtof.h"
