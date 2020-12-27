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
#ifndef _ASOHDR_H
#define _ASOHDR_H	1

#if _PACKAGE_ast

#include	<ast.h>
#include	<error.h>
#include	<fnv.h>

#else

#include	<errno.h>

#ifndef elementsof
#define elementsof(x)	(sizeof(x)/sizeof(x[0]))
#endif
#ifndef integralof
#define integralof(x)	(((char*)(x))-((char*)0))
#endif
#ifndef FNV_MULT
#define FNV_MULT	0x01000193L
#endif
#ifndef NiL
#define NiL		((void*)0)
#endif
#ifndef NoN 
#if defined(__STDC__) || defined(__STDPP__)
#define NoN(x)		void _STUB_ ## x () {}
#else
#define NoN(x)		void _STUB_/**/x () {}
#endif
#if !defined(_STUB_)
#define _STUB_
#endif
#endif

#endif

#include	"FEATURE/asometh"

#if _UWIN
#undef	_aso_fcntl
#undef	_aso_semaphore
#endif

#include	"aso.h"

#define HASH(p,z)	((integralof(p)*FNV_MULT)%(z))

#endif
