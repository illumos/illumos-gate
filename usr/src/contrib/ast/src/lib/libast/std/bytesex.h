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
/*
 * linux/gnu compatibility
 */

#ifndef _BYTESEX_H
#define _BYTESEX_H

#include <ast_common.h>

#undef __BYTE_ORDER

#if ( _ast_intswap & 3 ) == 3
#define __BYTE_ORDER	__LITTLE_ENDIAN
#else
#if ( _ast_intswap & 3 ) == 1
#define __BYTE_ORDER	__PDP_ENDIAN
#else
#define __BYTE_ORDER	__BIG_ENDIAN
#endif
#endif

#endif
