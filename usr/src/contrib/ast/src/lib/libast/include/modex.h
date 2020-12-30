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
 * AT&T Research
 *
 * external mode_t representation support
 */

#ifndef _MODEX_H
#define _MODEX_H

#include <ast_fs.h>
#include <modecanon.h>

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern int		modei(int);
extern int		modex(int);

#undef	extern

#if _S_IDPERM
#define modei(m)	((m)&X_IPERM)
#if _S_IDTYPE
#define modex(m)	(m)
#endif
#endif

#endif
