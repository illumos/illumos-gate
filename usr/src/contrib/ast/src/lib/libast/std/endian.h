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

#ifndef _ENDIAN_H
#define _ENDIAN_H

#include <bytesex.h>

#define	__LITTLE_ENDIAN	1234
#define	__BIG_ENDIAN	4321
#define	__PDP_ENDIAN	3412

#if defined (__USE_BSD) && !defined(__STRICT_ANSI__)

#ifndef LITTLE_ENDIAN
#define	LITTLE_ENDIAN	__LITTLE_ENDIAN
#endif

#ifndef BIG_ENDIAN
#define	BIG_ENDIAN	__BIG_ENDIAN
#endif

#ifndef PDP_ENDIAN
#define	PDP_ENDIAN	__PDP_ENDIAN
#endif

#undef	BYTE_ORDER
#define	BYTE_ORDER	__BYTE_ORDER

#endif

#endif
