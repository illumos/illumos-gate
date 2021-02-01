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
 * libgen interface definitions
 */

#ifndef _LIBGEN_H
#define _LIBGEN_H

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif
#if !_BLD_ast && defined(__IMPORT__)
#define extern		extern __IMPORT__
#endif

extern char*	__loc1;

#undef	extern

#if _BLD_ast && defined(__EXPORT__)
#define extern		__EXPORT__
#endif

extern char*	regcmp(const char*, ...);
extern char*	regex(const char*, const char*, ...);
extern char*	basename(char*);
extern char*	dirname(char*);

#undef	extern

#endif
