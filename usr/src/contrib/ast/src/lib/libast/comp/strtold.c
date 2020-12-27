/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2012 AT&T Intellectual Property          *
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

#include <ast.h>

#include "sfstrtof.h"
